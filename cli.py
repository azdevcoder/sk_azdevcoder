"""CLI da calculadora — `python cli.py` (interativo) ou `python cli.py -p 'Senha123!' --json`."""
from __future__ import annotations
import argparse
import getpass
import json
import sys
from password_core import analyze, format_tempo, SCENARIOS, generate_password, gerar_por_nivel, NIVEIS, generate_secret_hex


def show(a, show_pass: bool = False):
    if show_pass:
        print(f"\nSenha analisada: {a.password!r}")
    print(f"Tamanho: {a.length}  |  Pool: {a.pool} ({', '.join(a.pools_usados) or '—'})")
    print(f"Entropia nominal: {a.entropia_nominal} bits  |  Efetiva: {a.entropia_efetiva} bits (desconto padrões: {a.desconto_padroes})")
    print(f"Força: {a.score}/100 — {a.rotulo}")
    if a.eh_secret_key:
        print(f"Detectado: SECRET KEY — {a.secret_tipo}")
    print("\n--- Tempo médio p/ descobrir (metade do espaço de busca) ---")
    for sid, label, _ in SCENARIOS:
        print(f"  {label:55s} {format_tempo(a.tempos[sid])}")
    if a.avisos:
        print("\nAvisos:")
        for w in a.avisos:
            print(f"  ! {w}")
    if a.dicas:
        print("\nDicas:")
        for d in a.dicas:
            print(f"  * {d}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Calculadora de força de senhas / secret keys (local, offline)")
    ap.add_argument("-p", "--password", default=None, help="senha a analisar (evite no histórico; prefira interativo)")
    ap.add_argument("--show", action="store_true", help="exibir a senha no output")
    ap.add_argument("--json", action="store_true", help="saída JSON (p/ integrar com servidor)")
    ap.add_argument("--gerar", nargs="?", const="DEF", metavar="N",
                      help="gera senha (opcional: N chars). Ex.: --gerar 20")
    ap.add_argument("--len", type=int, default=None, help="tamanho da senha gerada (sobrescreve --gerar N e --nivel)")
    ap.add_argument("--nivel", choices=list(NIVEIS),
                      help=f"preset por nível de força: {', '.join(f'{k} ({v['rotulo']}, {v['length']} chars)' for k, v in NIVEIS.items())}")
    ap.add_argument("--no-maiusculas", action="store_true", help="exclui A-Z")
    ap.add_argument("--no-minusculas", action="store_true", help="exclui a-z")
    ap.add_argument("--no-numeros", action="store_true", help="exclui 0-9")
    ap.add_argument("--no-especiais", action="store_true", help="exclui símbolos")
    ap.add_argument("--simbolos", default=None, metavar="SET",
                      help="conjunto próprio de símbolos, ex.: --simbolos '!@#'. Implica especiais.")
    ap.add_argument("--sem-ambiguos", action="store_true", help="remove chars ambíguos (l, 1, I, O, 0 …)")
    ap.add_argument("--count", type=int, default=1, help="quantas senhas gerar (padrão 1)")
    ap.add_argument("--no-garantir", action="store_true",
                      help="não exige 1 char de cada tipo ativo")
    ap.add_argument("--secret", type=int, metavar="BITS", help="gera secret HEX com BITS (128/256) e sai")
    args = ap.parse_args()

    quer_gerar = (args.gerar is not None or args.nivel is not None or args.len is not None
                  or args.no_maiusculas or args.no_minusculas or args.no_numeros
                  or args.no_especiais or args.simbolos is not None or args.sem_ambiguos
                  or args.count != 1)
    if quer_gerar:
        if args.no_especiais and args.simbolos is not None:
            ap.error("--simbolos conflita com --no-especiais")
        if args.count < 1 or args.count > 100:
            ap.error("--count deve estar entre 1 e 100")
        # Tamanho: --len > --gerar N > preset do --nivel > 20
        length = None
        if args.len is not None:
            length = args.len
        elif args.gerar not in (None, "DEF"):
            try:
                length = int(args.gerar)
            except ValueError:
                ap.error("--gerar espera um número (ex.: --gerar 20)")
        opts = dict(maiusculas=not args.no_maiusculas, minusculas=not args.no_minusculas,
                    numeros=not args.no_numeros,
                    especiais=False if args.no_especiais else True,
                    sem_ambiguos=args.sem_ambiguos, garantir_todas=not args.no_garantir)
        if args.simbolos is not None:
            opts["simbolos"] = args.simbolos
            opts["especiais"] = True
        try:
            if args.nivel is not None:
                out = [gerar_por_nivel(args.nivel, length, **opts) for _ in range(args.count)]
            else:
                out = [generate_password(length or 20, **opts) for _ in range(args.count)]
        except ValueError as e:
            ap.error(str(e))
        print("\n".join(out))
        return
    if args.secret:
        print(generate_secret_hex(args.secret))
        return

    pw = args.password
    if pw is None:
        if not sys.stdin.isatty():
            pw = sys.stdin.read().strip()
        else:
            try:
                pw = getpass.getpass("Digite a senha (oculta, nada sai da máquina): ")
            except (EOFError, KeyboardInterrupt):
                print("\nCancelado.")
                return
    a = analyze(pw)
    if args.json:
        out = dict(length=a.length, pool=a.pool, pools=a.pools_usados,
                   entropia_nominal=a.entropia_nominal, entropia_efetiva=a.entropia_efetiva,
                   score=a.score, rotulo=a.rotulo, avisos=a.avisos, dicas=a.dicas,
                   eh_secret_key=a.eh_secret_key, secret_tipo=a.secret_tipo,
                   tempos={sid: {"label": l, "segundos_media": t, "legivel": format_tempo(t)} for sid, l, _ in SCENARIOS for t in [a.tempos[sid]]})
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        show(a, show_pass=args.show)


if __name__ == "__main__":
    main()
