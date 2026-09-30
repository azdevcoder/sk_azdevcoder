#!/bin/bash
set -e
APP_DIR=/opt/calculadora-senhas
PORT=8000
REPO=https://github.com/azdevcoder/sk_azdevcoder.git
apt update && apt install -y python3 git
python3 --version
if [ ! -d $APP_DIR/.git ]; then git clone $REPO $APP_DIR; else git -C $APP_DIR pull --ff-only; fi
python3 -m py_compile $APP_DIR/web.py $APP_DIR/password_core.py $APP_DIR/cli.py && echo py-ok
cp $APP_DIR/deploy/forcekeys.service /etc/systemd/system/forcekeys.service
systemctl daemon-reload
systemctl enable --now forcekeys
sleep 2
systemctl status forcekeys --no-pager --lines=20
ss -tlnp | grep $PORT || true
echo --- cloudflared ingress abaixo ---
cat $APP_DIR/deploy/cloudflared-ingress.snippet.yml
