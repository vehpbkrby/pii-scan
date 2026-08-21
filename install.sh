#!/usr/bin/env bash
#
# Установка pii-scan на Linux-сервер.
#
#   ./install.sh                     полная установка (образ с NER)
#   ./install.sh --slim              образ без NER: 164 МБ вместо 276 МБ
#   ./install.sh --systemd weekly    плюс регулярный прогон по расписанию
#   ./install.sh --uninstall         удалить обёртку и юниты systemd
#
# Скрипт создаёт каталоги config/ и out/, собирает образ и ставит обёртку
# pii-scan, чтобы не набирать длинную команду docker run руками.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="pii-scan"
WITH_NLP=1
TAG="full"
SYSTEMD_SCHEDULE=""
DO_UNINSTALL=0

# --- вывод ------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
die()  { printf '%s✗%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step() { printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }

# --- разбор аргументов ------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --slim)      WITH_NLP=0; TAG="slim" ;;
        --full)      WITH_NLP=1; TAG="full" ;;
        --systemd)   SYSTEMD_SCHEDULE="${2:-weekly}"; shift ;;
        --uninstall) DO_UNINSTALL=1 ;;
        -h|--help)   sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           die "неизвестный аргумент: $1 (см. --help)" ;;
    esac
    shift
done

# --- куда ставить обёртку ---------------------------------------------------

if [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
    SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    BIN_DIR="/usr/local/bin"
    SUDO="sudo"
else
    BIN_DIR="$HOME/.local/bin"
    SUDO=""
fi
WRAPPER="$BIN_DIR/pii-scan"

# --- удаление ---------------------------------------------------------------

if [ "$DO_UNINSTALL" -eq 1 ]; then
    step "Удаление"
    if [ -f "$WRAPPER" ]; then
        $SUDO rm -f "$WRAPPER" && ok "удалена обёртка $WRAPPER"
    fi
    if [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; then
        if systemctl list-unit-files 2>/dev/null | grep -q '^pii-scan.timer'; then
            $SUDO systemctl disable --now pii-scan.timer >/dev/null 2>&1 || true
            $SUDO rm -f /etc/systemd/system/pii-scan.timer \
                        /etc/systemd/system/pii-scan.service
            $SUDO systemctl daemon-reload
            ok "удалены юниты systemd"
        fi
    fi
    say ""
    say "Образ ${IMAGE_NAME} и каталоги config/, out/ оставлены."
    say "Удалить образ:  docker rmi ${IMAGE_NAME}:full ${IMAGE_NAME}:slim"
    exit 0
fi

# --- проверки ---------------------------------------------------------------

step "Проверка окружения"

command -v docker >/dev/null 2>&1 || die "docker не установлен"
docker info >/dev/null 2>&1 || die "нет доступа к docker: запустите демон \
или добавьте пользователя в группу docker (sudo usermod -aG docker \$USER)"
ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

if docker compose version >/dev/null 2>&1; then
    ok "docker compose доступен"
else
    warn "docker compose не найден — обёртка pii-scan будет работать, \
compose-файл нет"
fi

AVAILABLE_KB=$(df -Pk "$REPO_DIR" | awk 'NR==2 {print $4}')
NEEDED_KB=$([ "$WITH_NLP" -eq 1 ] && echo 1500000 || echo 700000)
if [ "$AVAILABLE_KB" -lt "$NEEDED_KB" ]; then
    warn "на диске $((AVAILABLE_KB / 1024)) МБ — для сборки может не хватить"
else
    ok "места на диске достаточно ($((AVAILABLE_KB / 1024 / 1024)) ГБ)"
fi

# --- каталоги и конфиг ------------------------------------------------------

step "Подготовка каталогов"

mkdir -p "$REPO_DIR/config" "$REPO_DIR/out"
ok "config/ и out/ созданы"

if [ ! -f "$REPO_DIR/config/config.yml" ]; then
    cp "$REPO_DIR/config.example.yml" "$REPO_DIR/config/config.yml"
    ok "создан config/config.yml из примера — отредактируйте адреса и учётки"
else
    ok "config/config.yml уже есть, не трогаю"
fi

if [ ! -f "$REPO_DIR/.env" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    chmod 600 "$REPO_DIR/.env"
    ok "создан .env (права 600) — впишите пароли к БД"
else
    chmod 600 "$REPO_DIR/.env"
    ok ".env уже есть, права выставлены в 600"
fi

# --- сборка образа ----------------------------------------------------------

step "Сборка образа ${IMAGE_NAME}:${TAG}"
say "Это займёт пару минут; интернет нужен только сейчас."

docker build --build-arg "WITH_NLP=${WITH_NLP}" \
    -t "${IMAGE_NAME}:${TAG}" "$REPO_DIR" >/tmp/pii-scan-build.log 2>&1 || {
        tail -20 /tmp/pii-scan-build.log >&2
        die "сборка не удалась, полный лог: /tmp/pii-scan-build.log"
    }
SIZE=$(docker images "${IMAGE_NAME}:${TAG}" --format '{{.Size}}')
ok "образ ${IMAGE_NAME}:${TAG} собран ($SIZE)"

# --- обёртка ----------------------------------------------------------------

step "Установка команды pii-scan"

mkdir -p "$BIN_DIR" 2>/dev/null || $SUDO mkdir -p "$BIN_DIR"

TMP_WRAPPER="$(mktemp)"
cat > "$TMP_WRAPPER" <<WRAPPER_EOF
#!/usr/bin/env bash
# Обёртка над docker run для pii-scan. Создана install.sh.
set -euo pipefail

REPO_DIR="${REPO_DIR}"
IMAGE="${IMAGE_NAME}:${TAG}"

# -t нужен, чтобы работал индикатор выполнения
TTY_FLAG=""
[ -t 1 ] && TTY_FLAG="-t"

ENV_ARGS=()
if [ -f "\$REPO_DIR/.env" ]; then
    ENV_ARGS+=(--env-file "\$REPO_DIR/.env")
fi

NET_ARGS=()
if [ -n "\${PII_NETWORK:-}" ]; then
    NET_ARGS+=(--network "\$PII_NETWORK")
fi

exec docker run --rm \$TTY_FLAG \\
    --user "\$(id -u):\$(id -g)" \\
    "\${ENV_ARGS[@]}" "\${NET_ARGS[@]}" \\
    -v "\$REPO_DIR/config:/config:ro" \\
    -v "\$REPO_DIR/out:/out" \\
    "\$IMAGE" --config /config/config.yml "\$@"
WRAPPER_EOF

if [ -n "$SUDO" ]; then
    $SUDO install -m 755 "$TMP_WRAPPER" "$WRAPPER"
else
    install -m 755 "$TMP_WRAPPER" "$WRAPPER"
fi
rm -f "$TMP_WRAPPER"
ok "установлена команда $WRAPPER"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR не в PATH — добавьте: export PATH=\"\$PATH:$BIN_DIR\"" ;;
esac

# --- systemd ----------------------------------------------------------------

if [ -n "$SYSTEMD_SCHEDULE" ]; then
    step "Регулярный прогон (systemd)"
    if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
        warn "нет прав root — юниты systemd не установлены"
    else
        $SUDO tee /etc/systemd/system/pii-scan.service >/dev/null <<SERVICE_EOF
[Unit]
Description=Поиск персональных данных в БД (152-ФЗ)
Documentation=https://github.com/vehpbkrby/pii-scan
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=$(id -un)
WorkingDirectory=${REPO_DIR}
# Нагрузка ограничена: регулярный прогон не должен мешать проду
ExecStart=${WRAPPER} --progress off --pause-ms 200 --max-minutes 120
SERVICE_EOF

        $SUDO tee /etc/systemd/system/pii-scan.timer >/dev/null <<TIMER_EOF
[Unit]
Description=Регулярный поиск персональных данных в БД

[Timer]
OnCalendar=${SYSTEMD_SCHEDULE}
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
TIMER_EOF

        $SUDO systemctl daemon-reload
        $SUDO systemctl enable --now pii-scan.timer >/dev/null
        ok "таймер включён: расписание «${SYSTEMD_SCHEDULE}»"
        say "  журнал прогонов:  journalctl -u pii-scan.service"
        say "  ближайший запуск: systemctl list-timers pii-scan.timer"
    fi
fi

# --- что дальше -------------------------------------------------------------

step "Готово"
say ""
say "1. Впишите пароли:            \$EDITOR ${REPO_DIR}/.env"
say "2. Укажите адреса и учётки:   \$EDITOR ${REPO_DIR}/config/config.yml"
say "3. Сухой прогон без чтения данных:"
say "     pii-scan --dry-run"
say "4. Полный прогон:"
say "     pii-scan"
say ""
say "Отчёты появятся в ${REPO_DIR}/out"
say ""
say "Если БД доступна только из docker-сети или с самого хоста:"
say "     PII_NETWORK=имя_сети pii-scan"
