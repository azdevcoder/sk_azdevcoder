"""
Núcleo da calculadora de força de senhas / secret keys.
Só stdlib — roda local e no servidor sem instalar nada.
"""
from __future__ import annotations
import math
import re
import secrets
import string
from dataclasses import dataclass, field

# ---------------------------------------------------------------- benchmarks
# Valores baseados em benchmarks públicos do Hashcat 6.x em RTX 4090 (2024-2026).
# São conservadores (arredondados p/ baixo) para não prometer segurança demais.
SCENARIOS = [
    # (id, label, tentativas/segundo) — ordem decrescente de tempo (taxa crescente)
    ("online_lento",   "Online com rate-limit (10/s)",          10),
    ("online_rapido",  "Online sem rate-limit / vazamento API (1 mil/s)", 1_000),
    ("argon2_forte",   "Argon2id/PBKDF2 forte (50 mil/s)",      50_000),
    ("gpu_bcrypt",     "GPU bcrypt custo 5 (350 mil/s)",        350_000),
    ("wpa2",           "WPA2/WPA3 handshake (1,5 mi/s)",         1_500_000),
    ("cpu_md5",        "CPU offline hash rápido MD5/SHA1 (10 mi/s)", 10_000_000),
    ("rtx4090_ntlm",   "RTX 4090 offline NTLM/MD5 (100 bi/s)",  100_000_000_000),
    ("rig8x",          "Rig 8x RTX 4090 (800 bi/s)",            800_000_000_000),
]

HASH_PRESETS = {
    "online": "online_lento",
    "md5": "rtx4090_ntlm",
    "ntlm": "rtx4090_ntlm",
    "sha1": "rtx4090_ntlm",
    "sha256": "cpu_md5",
    "wpa2": "wpa2",
    "bcrypt": "gpu_bcrypt",
    "argon2": "argon2_forte",
}

COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123",
    "password", "senha", "admin", "letmein", "welcome", "monkey", "dragon",
    "123123", "111111", "123321", "654321", "qwerty123", "1q2w3e4r", "mudar123",
    "brasil", "brasil123", "flamengo", "corinthians", "palmeiras", "vasco",
    "gremio", "santos", "bahia", "benfica", "sporting", "porto", "jesus",
    "deus", "amor", "familia", "maria", "joao", "ana", "carlos", "fernanda",
    "empresa", "suporte", "sistema", "azdevcoder", "hellocode",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET = str.maketrans({"@": "a", "0": "o", "3": "e", "1": "l", "5": "s",
                      "7": "t", "$": "s", "!": "i", "4": "a", "8": "b"})


@dataclass
class Analysis:
    password: str = field(repr=False)
    length: int = 0
    pool: int = 0
    pools_usados: list = field(default_factory=list)
    entropia_nominal: float = 0.0
    desconto_padroes: float = 0.0
    entropia_efetiva: float = 0.0
    combinacoes: float = 0.0
    score: int = 0
    rotulo: str = ""
    avisos: list = field(default_factory=list)
    dicas: list = field(default_factory=list)
    eh_secret_key: bool = False
    secret_tipo: str = ""
    tempos: dict = field(default_factory=dict)  # scenario_id -> segundos (média)


def detect_pools(pw: str):
    pools, size = [], 0
    if re.search(r"[a-z]", pw):
        pools.append("minúsculas (26)"); size += 26
    if re.search(r"[A-Z]", pw):
        pools.append("MAIÚSCULAS (26)"); size += 26
    if re.search(r"\d", pw):
        pools.append("dígitos (10)"); size += 10
    if re.search(r"[ !\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]", pw):
        pools.append("símbolos (~32)"); size += 32
    if re.search(r"[^\x00-\x7F]", pw):
        pools.append("unicode/acentos (~100+)"); size += 100
    if re.search(r"\s", pw):
        pools.append("espaço (1)"); size += 1
    return pools, size


def detect_secret(pw: str):
    s = pw.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", s):
        return True, "HEX 128-bit (32 chars) — ex.: MD5 / API key"
    if re.fullmatch(r"[0-9a-fA-F]{40}", s):
        return True, "HEX 160-bit (40 chars) — ex.: SHA1 / token"
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return True, "HEX 256-bit (64 chars) — ex.: SHA256 / secret key"
    if re.fullmatch(r"[0-9a-fA-F]{16,128}", s) and len(s) % 2 == 0:
        return True, f"HEX {len(s)*4}-bit ({len(s)} chars)"
    if re.fullmatch(r"[A-Za-z0-9_\-]{32,128}={0,2}", s) and len(s) >= 32:
        return True, f"Base64/Base64URL ({len(s)} chars, ~{int(len(s)*6)} bits nominais)"
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s.lower()):
        return True, "UUID (122 bits efetivos)"
    return False, ""


def find_warnings(pw: str) -> tuple[list, float]:
    avisos, desconto = [], 0.0
    low = pw.lower()
    norm = low.translate(LEET)

    for w in COMMON_PASSWORDS:
        if w in norm and len(w) >= 4:
            avisos.append(f"Contém palavra comum: '{w}' — atacante testa isso primeiro (dicionário).")
            desconto += 20
            break

    # sequências de teclado / alfabeto / números
    seq_found = False
    for row in KEYBOARD_ROWS + ["abcdefghijklmnopqrstuvwxyz"]:
        for i in range(len(row) - 2):
            seq = row[i:i + 3]
            if seq in low or seq[::-1] in low:
                seq_found = True
                break
    if re.search(r"(012|123|234|345|456|567|678|789|890|987|876)", pw):
        seq_found = True
    if seq_found:
        avisos.append("Contém sequência previsível (abc, 123, qwe…) — reduz espaço de busca.")
        desconto += 12

    m = re.search(r"(.)\1{2,}", pw)
    if m:
        avisos.append(f"Repetição '{m.group(0)[:6]}…' — brute-force com máscara acha rápido.")
        desconto += 10

    if re.search(r"(19|20)\d{2}", pw):
        avisos.append("Parece conter ano (ex.: 1998, 2024) — máscaras testam isso.")
        desconto += 8

    if pw and (pw[0].isupper() and pw[-1] in "123456789!?" or re.search(r"^[A-Z][a-z]+\d+!?$", pw)):
        avisos.append("Padrão Capitalizado+ dígitos/símbolo no fim (Ex.: Senha123!) — regra nº1 dos crackers.")
        desconto += 10

    if len(set(pw)) <= max(2, len(pw) // 4) and len(pw) >= 6:
        avisos.append("Poucos caracteres únicos — espaço real bem menor que o nominal.")
        desconto += 15

    return avisos, min(desconto, 45)


def score_label(ent: float) -> tuple[int, str]:
    if ent < 28:   return max(0, int(ent * 1.2)), "MUITO FRACA — quebra em segundos"
    if ent < 36:   return 30, "FRACA — não use"
    if ent < 50:   return 50, "RAZOÁVEL — só p/ contas sem valor"
    if ent < 70:   return 70, "FORTE — ok p/ maioria dos usos"
    if ent < 90:   return 85, "MUITO FORTE — boa p/ e-mail/banco"
    if ent < 128:  return 95, "EXCELENTE — nível secret key"
    return 100, "EXCELENTE — nível criptográfico (128+ bits)"


def _pt(v: float) -> str:
    """Arredonda padronizado: <10 -> 1 decimal (7,5); >=10 -> inteiro (456). pt-BR."""
    if v < 10:
        r = round(v, 1)
        if r == int(r):
            return str(int(r))
        return f"{r:.1f}".replace(".", ",")
    return f"{int(round(v)):,}".replace(",", ".")


def _unidade(v: str, sing: str, plur: str) -> str:
    return sing if v == "1" else plur


def _escala_anos(anos: float) -> str:
    if anos < 1_000:
        v = _pt(anos)
        return f"{v} {_unidade(v, 'ano', 'anos')}"
    if anos < 1_000_000:
        v = _pt(anos / 1_000)
        return f"{v} mil anos"
    if anos < 1_000_000_000:
        n = anos / 1_000_000
        v = _pt(n)
        return f"{v} milhão de anos" if n < 2 else f"{v} milhões de anos"
    if anos < 1_000_000_000_000:
        n = anos / 1_000_000_000
        v = _pt(n)
        return f"{v} bilhão de anos" if n < 2 else f"{v} bilhões de anos"
    if anos < 1_000_000_000_000_000:
        n = anos / 1_000_000_000_000
        v = _pt(n)
        return f"{v} trilhão de anos" if n < 2 else f"{v} trilhões de anos"
    if anos < 1_000_000_000_000_000_000:
        n = anos / 1_000_000_000_000_000
        v = _pt(n)
        return f"{v} quatrilhão de anos" if n < 2 else f"{v} quatrilhões de anos"
    n = anos / 1_000_000_000_000_000_000
    v = _pt(n)
    return f"{v} quintilhão de anos" if n < 2 else f"{v} quintilhões de anos"


def format_tempo(seg: float) -> str:
    if seg == float("inf"):
        return "praticamente infinito"
    if seg < 0.001:
        return "instantâneo (< 1 ms)"
    if seg < 1:
        ms = int(round(seg * 1000))
        return f"{ms} {_unidade(str(ms), 'milissegundo', 'milissegundos')}"
    if seg < 60:
        v = _pt(seg)
        return f"{v} {_unidade(v, 'segundo', 'segundos')}"
    if seg < 3600:
        v = _pt(seg / 60)
        return f"{v} {_unidade(v, 'minuto', 'minutos')}"
    if seg < 86400:
        v = _pt(seg / 3600)
        return f"{v} {_unidade(v, 'hora', 'horas')}"
    dias = seg / 86400
    if dias < 60:
        v = _pt(dias)
        return f"{v} {_unidade(v, 'dia', 'dias')}"
    if dias < 730:
        v = _pt(dias / 30.4375)
        return f"{v} {_unidade(v, 'mês', 'meses')}"
    return _escala_anos(seg / (86400 * 365.25))


def analyze(password: str) -> Analysis:
    a = Analysis(password=password)
    a.length = len(password)
    if not password:
        a.rotulo = "VAZIA"
        return a

    eh_secret, tipo = detect_secret(password)
    a.eh_secret_key, a.secret_tipo = eh_secret, tipo

    pools, pool = detect_pools(password)
    a.pools_usados, a.pool = pools, pool or 1

    # Entropia nominal: L * log2(pool)
    a.entropia_nominal = round(a.length * math.log2(a.pool), 1)

    # Caso especial: secret HEX tem entropia exata conhecida
    if eh_secret and re.fullmatch(r"[0-9a-fA-F]+", password.strip()):
        bits = len(password.strip()) * 4
        a.entropia_nominal = float(bits)

    avisos, desconto = find_warnings(password)
    a.avisos = avisos
    a.desconto_padroes = desconto
    a.entropia_efetiva = max(0.0, round(a.entropia_nominal - desconto, 1))

    try:
        a.combinacoes = pow(2.0, a.entropia_efetiva)
    except OverflowError:
        a.combinacoes = float("inf")

    a.score, a.rotulo = score_label(a.entropia_efetiva)

    # Tempos médios = combinações / 2 / taxa
    for sid, _label, taxa in SCENARIOS:
        t = (a.combinacoes / 2) / taxa if a.combinacoes != float("inf") else float("inf")
        a.tempos[sid] = t

    # Dicas
    if a.length < 12:
        a.dicas.append("Use 14+ caracteres (ideal 16–20). Cada caractere extra multiplica o tempo por ~70x.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        a.dicas.append("Misture maiúsculas e minúsculas.")
    if not re.search(r"\d", password):
        a.dicas.append("Adicione dígitos.")
    if not re.search(r"[^A-Za-z0-9]", password):
        a.dicas.append("Adicione símbolos (!@#…).")
    if avisos:
        a.dicas.append("Evite palavras, datas e padrões de teclado — prefira 4–5 palavras aleatórias (ex.: 'vaso roxo relógio maré 47!').")
    if a.entropia_efetiva >= 90:
        a.dicas.append("Excelente. Guarde num gerenciador (Bitwarden/1Password) e ative 2FA.")
    if eh_secret:
        a.dicas.append("É uma secret key: nunca commite no git — use variável de ambiente ou Vault.")
    return a


SIMBOLOS_PADRAO = "!@#$%^&*-_=+?"
AMBIGUOS = set("l1IO0|`'\"")

# Níveis de geração: tamanho dimensionado p/ bits-alvo com pool completo (94).
# bits ≈ L × log2(94) ≈ L × 6,55
NIVEIS = {
    "basica": {"rotulo": "Básica (~80 bits)", "length": 12,
               "maiusculas": True, "minusculas": True, "numeros": True, "especiais": True},
    "forte": {"rotulo": "Forte (~105 bits)", "length": 16,
              "maiusculas": True, "minusculas": True, "numeros": True, "especiais": True},
    "super": {"rotulo": "Super (~130 bits)", "length": 20,
              "maiusculas": True, "minusculas": True, "numeros": True, "especiais": True},
    "cripto": {"rotulo": "Criptográfica (256+ bits)", "length": 40,
               "maiusculas": True, "minusculas": True, "numeros": True, "especiais": True},
}


def generate_password(length: int = 20, *, maiusculas: bool = True,
                      minusculas: bool = True, numeros: bool = True,
                      especiais: bool = True, simbolos: str | None = None,
                      sem_ambiguos: bool = False,
                      garantir_todas: bool = True) -> str:
    """Gera senha com `secrets` (CSRNG). Garante ≥1 char de cada tipo ativo."""
    grupos = []
    if minusculas:
        grupos.append(string.ascii_lowercase)
    if maiusculas:
        grupos.append(string.ascii_uppercase)
    if numeros:
        grupos.append(string.digits)
    if especiais:
        grupos.append(simbolos if simbolos is not None else SIMBOLOS_PADRAO)
    if not grupos:
        raise ValueError("Ative ao menos um tipo de caractere.")
    if sem_ambiguos:
        grupos = ["".join(c for c in g if c not in AMBIGUOS) for g in grupos]
        grupos = [g for g in grupos if g]
        if not grupos:
            raise ValueError("Sem-ambíguos esvaziou os alfabetos.")
    if length < 1:
        raise ValueError("Tamanho deve ser ≥ 1.")
    if garantir_todas and length < len(grupos):
        raise ValueError(f"Tamanho {length} menor que nº de tipos ativos ({len(grupos)}).")
    alfabeto = "".join(grupos)
    while True:
        pw = [secrets.choice(alfabeto) for _ in range(length)]
        if not garantir_todas or all(any(c in g for c in pw) for g in grupos):
            break
    return "".join(pw)


def gerar_por_nivel(nivel: str, length: int | None = None, **opts) -> str:
    """Gera senha pelo preset de nível; `length` explícito sobrescreve o preset."""
    if nivel not in NIVEIS:
        raise ValueError(f"Nível inválido: {nivel} (use: {', '.join(NIVEIS)})")
    cfg = dict(NIVEIS[nivel])
    cfg.pop("rotulo")
    for k in ("maiusculas", "minusculas", "numeros", "especiais"):
        opts.setdefault(k, cfg[k])
    return generate_password(length if length else cfg["length"], **opts)


def generate_secret_hex(bits: int = 256) -> str:
    return secrets.token_hex(bits // 8)
