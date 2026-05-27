#!/bin/bash
# Чистая установка PROXOMATRON на новый сервер. Создаёт /opt/proxomatron + systemd-юнит
# + утилиту /usr/local/bin/proxomatronctl. Служба ставится disabled — старт вручную:
#   proxomatronctl start           # бессрочно
#   proxomatronctl start 3h        # на 3 часа (затем авто-стоп)
#
# Источник proxomatron.py определяется так (первый найденный):
#   1) аргумент:  bash install-proxomatron.sh /путь/к/proxomatron.py
#   2) /tmp/proxomatron-new.py  (заливка через pscp)
#   3) рядом со скриптом: ../proxomatron.py, ../app/proxomatron.py, ./proxomatron.py
set -u
DST=/opt/proxomatron/proxomatron.py
HERE="$(cd "$(dirname "$0")" && pwd)"

SRC="${1:-}"
if [ -z "$SRC" ]; then
  for c in /tmp/proxomatron-new.py "$HERE/../proxomatron.py" \
           "$HERE/../app/proxomatron.py" "$HERE/proxomatron.py"; do
    if [ -f "$c" ]; then SRC="$c"; break; fi
  done
fi
if [ -z "$SRC" ] || [ ! -f "$SRC" ]; then
  echo "ОШИБКА: не найден proxomatron.py."
  echo "Укажите путь явно:  bash install-proxomatron.sh /путь/к/proxomatron.py"
  exit 1
fi
echo "### источник: $SRC"

echo "### syntax-check"
if ! python3 -m py_compile "$SRC"; then
  echo "PY-SYNTAX-FAIL — установка прервана"; exit 1
fi
echo "PY-SYNTAX-OK"

echo "### установка в /opt/proxomatron"
mkdir -p /opt/proxomatron
cp "$SRC" "$DST"
sed -i 's/\r$//' "$DST"
chmod 644 "$DST"

echo "### systemd-юнит /etc/systemd/system/proxomatron.service"
cat > /etc/systemd/system/proxomatron.service <<'EOF'
[Unit]
Description=PROXOMATRON prototype dashboard
After=network-online.target vitastor-mon.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/proxomatron/proxomatron.py
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "### утилита /usr/local/bin/proxomatronctl"
VBC_SRC=""
for c in "$HERE/proxomatronctl" "$HERE/../proxomatronctl" \
         "$HERE/../app/proxomatronctl" /tmp/proxomatronctl; do
  if [ -f "$c" ]; then VBC_SRC="$c"; break; fi
done
if [ -n "$VBC_SRC" ]; then
  cp "$VBC_SRC" /usr/local/bin/proxomatronctl
  sed -i 's/\r$//' /usr/local/bin/proxomatronctl
  chmod 755 /usr/local/bin/proxomatronctl
  echo "  установлено из $VBC_SRC"
else
  echo "  ВНИМАНИЕ: proxomatronctl рядом не найден — пропущено"
fi

echo "### daemon-reload + остановка прежнего экземпляра + disable"
systemctl daemon-reload
# Если ранее служба была enabled — снимаем автозапуск (security default).
if systemctl is-enabled proxomatron >/dev/null 2>&1; then
  systemctl disable proxomatron 2>&1 | tail -1
fi
# Снимаем плановый автостоп от предыдущих запусков, если был.
systemctl stop proxomatron-autostop.timer 2>/dev/null || true
systemctl stop proxomatron-autostop.service 2>/dev/null || true
systemctl reset-failed proxomatron-autostop.timer 2>/dev/null || true
systemctl reset-failed proxomatron-autostop.service 2>/dev/null || true
# Перезапускаем работающий процесс с новым кодом, либо оставляем остановленным.
WAS_ACTIVE="$(systemctl is-active proxomatron 2>/dev/null || true)"
if [ "$WAS_ACTIVE" = "active" ]; then
  systemctl restart proxomatron
  sleep 2
  echo "  служба перезапущена — is-active=$(systemctl is-active proxomatron)"
else
  echo "  служба установлена в disabled-состоянии (не запущена)"
fi

cat <<'EOF'

### КАК ЗАПУСТИТЬ

  proxomatronctl start           # запустить бессрочно
  proxomatronctl start 3h        # запустить на 3 часа (затем авто-стоп) — рекомендуется
  proxomatronctl stop            # остановить
  proxomatronctl status          # состояние службы + плановая остановка

EOF

if [ "$WAS_ACTIVE" = "active" ]; then
  echo "### verify HTTP (служба работала и была перезапущена)"
  echo "  GET /        -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/)"
  echo "  GET /healthz -> $(curl -s -m 5 http://127.0.0.1:8080/healthz)"
fi
echo "### журнал proxomatron (5 строк)"
journalctl -u proxomatron --no-pager -n 5 2>&1
echo DONE-INSTALL
