# Calculadora de força de senhas / secret keys — 100% local, offline

Sem dependências. Roda no Windows local e depois no servidor (só Python 3.10+).

## Usar

```bash
cd calculadora-senhas
python cli.py                      # interativo (senha oculta)
python cli.py -p "Senha123!"       # direto (evita histórico p/ senha real)
python cli.py -p "abc" --json      # saída JSON p/ integrar
python cli.py --gerar 20           # 20 chars, todos os tipos
python cli.py --nivel forte        # presets: basica (~80 bits/12) · forte (~105/16) · super (~130/20) · cripto (256+/40)
python cli.py --gerar 16 --no-especiais --sem-ambiguos --count 5
python cli.py --gerar 12 --no-maiusculas --no-numeros --no-especiais   # só minúsculas
python cli.py --secret 256         # gera secret HEX 256-bit
python web.py                      # abre http://localhost:8000 (interface + API)
```

API JSON local: `GET /api/check?password=...`

## O que calcula

- Pool de caracteres (minúsculas/maiúsculas/dígitos/símbolos/unicode), entropia nominal `L*log2(pool)`
- Desconto de padrões: dicionário PT/BR+EN, sequências (abc/123/qwe), repetição, ano, `Senha123!`, poucos chars únicos
- Detecção de secret key: HEX 128/160/256-bit, Base64, UUID
- Tempo médio de quebra (metade do espaço ÷ taxa) em 8 cenários:
  online 10/s e 1k/s, CPU 10mi/s, RTX 4090 100bi/s, Rig 8x 800bi/s, bcrypt 350mil/s, Argon2id 50mil/s, WPA2 1,5mi/s
- Benchmarks baseados em Hashcat 6.x / RTX 4090, arredondados p/ baixo

## Subir pro servidor

Só copiar a pasta e rodar `python web.py 8000` (systemd/nginx por cima). Sem `pip install`.
