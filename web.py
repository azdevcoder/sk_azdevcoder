"""Web local (stdlib, sem dependências) + pronta p/ subir no servidor.
Uso:  python web.py  ->  http://localhost:8000
No servidor: rode `python web.py 8000` atrás de nginx ou `systemd`.
Rota JSON p/ integrar:  GET /api/check?password=...
                      GET /api/generate?len=20&nivel=forte&minusculas=1&count=3
"""
from __future__ import annotations
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from password_core import analyze, format_tempo, SCENARIOS, generate_password, gerar_por_nivel, NIVEIS

PAGE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Calculadora de força de senhas</title>
<style>
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Roboto,Arial;max-width:760px;margin:32px auto;padding:0 16px;background:#0f1115;color:#e8eaf0;overflow-x:hidden}
.card{background:#181c24;border:1px solid #2a3040;border-radius:12px;padding:20px;margin:16px 0;max-width:100%;overflow:hidden;overflow-wrap:break-word}
input[type=text]{width:100%;max-width:100%;padding:12px;border-radius:8px;border:1px solid #444;background:#0f1115;color:#fff;font-size:16px}
input[type=number]{width:80px;max-width:100%;padding:8px;border-radius:8px;border:1px solid #444;background:#0f1115;color:#fff}
select{padding:8px;border-radius:8px;border:1px solid #444;background:#0f1115;color:#fff;max-width:100%}
label{margin-right:12px;font-size:14px;line-height:2.2}
.gen{font-family:Consolas,monospace;font-size:16px;background:#0f1115;padding:10px;border-radius:8px;word-break:break-all;overflow-wrap:anywhere;margin:6px 0;max-width:100%}
button{padding:12px 20px;border-radius:8px;border:0;background:#4f7cff;color:#fff;font-size:15px;cursor:pointer;margin-top:10px;max-width:100%}
.bar{height:14px;border-radius:8px;background:#222a38;overflow:hidden;margin:8px 0}
.fill{height:100%%;background:linear-gradient(90deg,#ff5252,#ffb74d,#81c784,#4f7cff)}
table{width:100%%;max-width:100%%;border-collapse:collapse;font-size:14px;table-layout:fixed}
td{padding:8px 6px;border-bottom:1px solid #2a3040;overflow-wrap:break-word;word-break:break-word}
td:first-child{width:60%%}
td:last-child{text-align:right;white-space:normal;overflow-wrap:anywhere}
.warn{color:#ffb74d}.tip{color:#81c784}.mono{font-family:Consolas,monospace;font-size:13px;overflow-wrap:anywhere;word-break:break-word}
small{color:#9aa3b5}
h1{font-size:28px;overflow-wrap:break-word}
@media (max-width:560px){body{margin:16px auto}.card{padding:14px}h1{font-size:22px}table{font-size:13px}td{padding:6px 4px}td:first-child{width:55%%}button{width:100%%}}
</style></head><body>
<h1>Calculadora de força de senhas</h1>
 <p><small></small></p>
<div class="card"><form method="GET" action="/">
<input type="text" name="password" placeholder="Digite a senha / secret key…" value="%PWD%" autocomplete="off">
<button type="submit">Calcular</button></form></div>
%BODY%
<div class="card"><h2>Gerador de senhas</h2><form method="GET" action="/">
<input type="hidden" name="gen" value="1">
<label>Tamanho <input type="number" name="len" value="%LEN%" placeholder="auto" min="1" max="128"></label>
<label>Nível <select name="nivel">%NIVEIS%</select></label><br>
<label><input type="checkbox" name="minusculas" %CKMIN%> a-z</label>
<label><input type="checkbox" name="maiusculas" %CKMAI%> A-Z</label>
<label><input type="checkbox" name="numeros" %CKNUM%> 0-9</label>
<label><input type="checkbox" name="especiais" %CKESP%> símbolos</label><br>
<label><input type="checkbox" name="sem_ambiguos" %CKAMB%> sem ambíguos (l, 1, I, O, 0…)</label>
<label>Qtd <input type="number" name="count" value="%COUNT%" min="1" max="20"></label>
<button type="submit">Gerar</button></form></div>
%GEN%
</body></html>"""


def body_for(pw: str) -> str:
    if not pw:
        return ""
    a = analyze(pw)
    w = 100 if a.score >= 100 else a.score
    rows = "".join(
        f"<tr><td>{html.escape(label)}</td><td class='mono'>{format_tempo(a.tempos[sid])}</td></tr>"
        for sid, label, _ in SCENARIOS)
    avisos = "".join(f"<p class='warn'>Aviso: {html.escape(x)}</p>" for x in a.avisos)
    dicas = "".join(f"<p class='tip'>Recomendação: {html.escape(x)}</p>" for x in a.dicas)
    secret = f"<p><b>Secret key detectada:</b> {html.escape(a.secret_tipo)}</p>" if a.eh_secret_key else ""
    return (f"<div class='card'><h2>{a.score}/100 — {html.escape(a.rotulo)}</h2>"
            f"<div class='bar'><div class='fill' style='width:{w}%%'></div></div>"
            f"<p>Tamanho <b>{a.length}</b> · Pool <b>{a.pool}</b> ({html.escape(', '.join(a.pools_usados))})<br>"
            f"Entropia nominal <b>{a.entropia_nominal} bits</b> · Efetiva <b>{a.entropia_efetiva} bits</b></p>"
            f"{secret}{avisos}{dicas}<table>{rows}</table></div>")


def _box(qs: dict, name: str) -> bool:
    """Checkbox do form: ausente = desmarcado; presente = marcado (salvo 0/false/off/no)."""
    if name not in qs:
        return False
    return qs[name][0].lower() not in ("0", "false", "off", "no")


def _int(qs: dict, name: str, default: int | None, lo: int, hi: int) -> int | None:
    raw = qs.get(name, [""])[0].strip()
    if not raw:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        return default


def gen_body(qs: dict) -> str:
    if "gen" not in qs:
        return ""
    nivel = qs.get("nivel", [""])[0] or None
    if nivel is not None and nivel not in NIVEIS:
        return "<div class='card'><p class='warn'>Nível inválido.</p></div>"
    length = _int(qs, "len", None, 1, 128)
    count = _int(qs, "count", 1, 1, 20) or 1
    opts = dict(minusculas=_box(qs, "minusculas"), maiusculas=_box(qs, "maiusculas"),
                numeros=_box(qs, "numeros"), especiais=_box(qs, "especiais"),
                sem_ambiguos=_box(qs, "sem_ambiguos"))
    try:
        if nivel:
            pwds = [gerar_por_nivel(nivel, length, **opts) for _ in range(count)]
        else:
            pwds = [generate_password(length or 20, **opts) for _ in range(count)]
    except ValueError as e:
        return f"<div class='card'><p class='warn'>Erro: {html.escape(str(e))}</p></div>"
    items = "".join(f"<div class='gen'>{html.escape(p)}</div>" for p in pwds)
    return f"<div class='card'><h2>Geradas ({len(pwds)}×)</h2>{items}<small>A primeira foi analisada abaixo.</small></div>" + body_for(pwds[0])


class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        pw = qs.get("password", [""])[0]
        if u.path == "/api/generate":
            def f(name: str, default: bool = True) -> bool:
                v = qs.get(name, [None])[0]
                if v is None:
                    return default
                return v.lower() not in ("0", "false", "off", "no")
            nivel = qs.get("nivel", [""])[0] or None
            try:
                length = _int(qs, "len", None, 1, 128)
                count = _int(qs, "count", 1, 1, 20) or 1
                opts = dict(minusculas=f("minusculas"), maiusculas=f("maiusculas"),
                            numeros=f("numeros"), especiais=f("especiais"),
                            sem_ambiguos=f("sem_ambiguos", False))
                pwds = ([gerar_por_nivel(nivel, length, **opts) for _ in range(count)]
                        if nivel else [generate_password(length or 20, **opts) for _ in range(count)])
                a = analyze(pwds[0])
                out = {"passwords": pwds, "nivel": nivel,
                       "entropia_nominal_bits": a.entropia_nominal, "score": a.score, "rotulo": a.rotulo}
                code = 200
            except ValueError as e:
                out, code = {"erro": str(e)}, 400
            data = json.dumps(out, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/api/check":
            a = analyze(pw)
            out = dict(length=a.length, pool=a.pool, entropia_nominal=a.entropia_nominal,
                       entropia_efetiva=a.entropia_efetiva, score=a.score, rotulo=a.rotulo,
                       avisos=a.avisos, dicas=a.dicas, eh_secret_key=a.eh_secret_key,
                       secret_tipo=a.secret_tipo,
                       tempos={sid: {"label": l, "segundos_media": t, "legivel": format_tempo(t)}
                               for sid, l, _ in SCENARIOS for t in [a.tempos[sid]]})
            data = json.dumps(out, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        nivel_sel = qs.get("nivel", [""])[0]
        opts_html = '<option value="">personalizado</option>' + "".join(
            f'<option value="{k}"{" selected" if k == nivel_sel else ""}>{k} — {v["rotulo"]}</option>'
            for k, v in NIVEIS.items())
        if "gen" in qs:
            ck = {n: ("checked" if _box(qs, n) else "") for n in
                  ("minusculas", "maiusculas", "numeros", "especiais", "sem_ambiguos")}
        else:
            ck = {n: "checked" for n in ("minusculas", "maiusculas", "numeros", "especiais")}
            ck["sem_ambiguos"] = ""
        page = (PAGE.replace("%PWD%", html.escape(pw)).replace("%BODY%", body_for(pw))
                    .replace("%LEN%", html.escape(qs.get("len", [""])[0]))
                    .replace("%COUNT%", html.escape(qs.get("count", ["1"])[0] or "1"))
                    .replace("%NIVEIS%", opts_html)
                    .replace("%CKMIN%", ck["minusculas"]).replace("%CKMAI%", ck["maiusculas"])
                    .replace("%CKNUM%", ck["numeros"]).replace("%CKESP%", ck["especiais"])
                    .replace("%CKAMB%", ck["sem_ambiguos"])
                    .replace("%GEN%", gen_body(qs)))
        data = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"Servindo em http://localhost:{port}  (Ctrl+C p/ parar)")
    HTTPServer(("0.0.0.0", port), H).serve_forever()
