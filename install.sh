#!/usr/bin/env bash
#
# Установка pii-scan на Linux-сервер.
#
#   ./install.sh                     полная установка (образ с NER)
#   ./install.sh --slim              образ без NER: 164 МБ вместо 276 МБ
#   ./install.sh --systemd weekly    плюс регулярный прогон по расписанию
#   ./install.sh --skip-build        не собирать образ (уже загружен docker load)
#   ./install.sh --uninstall         удалить обёртку и юниты systemd
#
# Для корпоративного контура с TLS-инспектором или внутренним зеркалом PyPI:
#   ./install.sh --ca-cert /etc/ssl/certs/ca-certificates.crt
#   ./install.sh --pip-index https://nexus.corp/repository/pypi/simple \
#                --trusted-host nexus.corp
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
SKIP_BUILD=0
CA_CERT=""
PIP_INDEX=""
TRUSTED_HOST=""

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
        --skip-build) SKIP_BUILD=1 ;;
        --ca-cert)    CA_CERT="${2:-}"; shift ;;
        --pip-index)  PIP_INDEX="${2:-}"; shift ;;
        --trusted-host) TRUSTED_HOST="${2:-}"; shift ;;
        --uninstall) DO_UNINSTALL=1 ;;
        -h|--help)   sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# Причин «нет доступа к docker» несколько, и лечатся они по-разному.
# Самая частая и неочевидная: usermod -aG выполнен, но текущая сессия
# свой список групп не перечитывает — он выдаётся при входе в систему.
docker_access_problem() {
    local me
    me="$(id -un)"

    if command -v systemctl >/dev/null 2>&1; then
        local state
        state="$(systemctl is-active docker 2>/dev/null || true)"
        if [ "$state" != "active" ]; then
            printf 'демон docker не запущен (systemctl is-active docker → %s).\n' \
                   "${state:-неизвестно}"
            printf '\n    sudo systemctl start docker\n'
            printf '    sudo systemctl enable docker    # чтобы поднимался при загрузке\n'
            printf '\nenable без start только прописывает автозапуск, но сервис не поднимает.\n'
            return
        fi
    fi

    if getent group docker 2>/dev/null | grep -qE "(:|,)${me}(,|$)"; then
        if ! id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
            printf 'пользователь %s состоит в группе docker, но текущая сессия её\n' "$me"
            printf 'не видит: членство в группах выдаётся при входе в систему и в уже\n'
            printf 'запущенной оболочке не обновляется.\n'
            printf '\n    newgrp docker            # применить в этой сессии\n'
            printf '    sg docker -c ./install.sh   # либо сразу запустить установку\n'
            printf '\nЛибо выйдите из системы и зайдите заново.\n'
            return
        fi
        printf 'группа docker выдана и применена, но доступ к сокету не получен.\n'
        printf 'Проверьте права на сокет:\n'
        printf '\n    ls -l /var/run/docker.sock\n'
        return
    fi

    printf 'пользователь %s не состоит в группе docker.\n' "$me"
    printf '\n    sudo usermod -aG docker %s\n' "$me"
    printf '    newgrp docker            # применить, не перелогиниваясь\n'
}

if ! docker info >/dev/null 2>&1; then
    die "нет доступа к docker.

$(docker_access_problem)"
fi
ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

if docker compose version >/dev/null 2>&1; then
    ok "docker compose доступен"
else
    warn "docker compose не найден — обёртка pii-scan будет работать, \
compose-файл нет"
fi

AVAILABLE_KB=$(df -Pk "$REPO_DIR" | awk 'NR==2 {print $4}')
NEEDED_KB=$([ "$WITH_NLP" -eq 1 ] && echo 1500000 || echo 700000)
# Готовому образу место под сборку не нужно
[ "$SKIP_BUILD" -eq 1 ] && NEEDED_KB=0
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
    ok "config/config.yml уже есть, не трогаю — в нём ваши адреса и пароли"
    # Пример обновляется вместе с кодом, а рабочий конфиг остаётся прежним.
    # Молчать об этом нельзя: новые параметры иначе не найти.
    TMP_NEW="$(mktemp)"; TMP_OLD="$(mktemp)"
    grep -oE '^ +#? *[a-z_]+:' "$REPO_DIR/config.example.yml" 2>/dev/null \
        | tr -d ' #:' | sort -u > "$TMP_NEW"
    grep -oE '^ +#? *[a-z_]+:' "$REPO_DIR/config/config.yml" 2>/dev/null \
        | tr -d ' #:' | sort -u > "$TMP_OLD"
    new_count=$(comm -23 "$TMP_NEW" "$TMP_OLD" | wc -l | tr -d ' ')
    if [ "${new_count:-0}" -gt 0 ]; then
        new_keys=$(comm -23 "$TMP_NEW" "$TMP_OLD" | head -6 | tr '\n' ' ')
        [ "$new_count" -gt 6 ] && new_keys="$new_keys… и ещё $((new_count - 6))"
        warn "в примере есть параметры, которых нет у вас ($new_count): $new_keys"
        say  "  посмотреть:  diff -u ${REPO_DIR}/config/config.yml ${REPO_DIR}/config.example.yml"
        say  "  описание:    README, раздел «Параметры конфига»"
        say  "  все параметры необязательны — без них работают значения по умолчанию"
    fi
    rm -f "$TMP_NEW" "$TMP_OLD"
fi

if [ ! -f "$REPO_DIR/.env" ]; then
    cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
    chmod 600 "$REPO_DIR/.env"
    ok "создан .env (права 600) — впишите пароли к БД"
else
    chmod 600 "$REPO_DIR/.env"
    ok ".env уже есть, права выставлены в 600"
fi

# Установку нередко запускают от root (sudo su), а сканировать потом — от
# себя. Тогда out/ остаётся во владении root, контейнер под обычным
# пользователем не может записать отчёты, и прогон падает на проверке прав.
# Возвращаем всё созданное владельцу каталога проекта.
REPO_OWNER="$(stat -c '%U' "$REPO_DIR" 2>/dev/null || echo '')"
if [ "$(id -u)" -eq 0 ] && [ -n "$REPO_OWNER" ] && [ "$REPO_OWNER" != "root" ]; then
    chown -R "$REPO_OWNER" "$REPO_DIR/config" "$REPO_DIR/out" "$REPO_DIR/.env"
    ok "владелец config/, out/ и .env — $REPO_OWNER (установка идёт от root)"
fi

# --- сборка образа ----------------------------------------------------------

if [ "$SKIP_BUILD" -eq 1 ]; then
    step "Сборка образа пропущена (--skip-build)"
    if ! docker image inspect "${IMAGE_NAME}:${TAG}" >/dev/null 2>&1; then
        die "образа ${IMAGE_NAME}:${TAG} нет в системе. Загрузите его файлом:
    gunzip -c pii-scan-${TAG}.tar.gz | docker load
или уберите --skip-build, чтобы собрать на месте (нужен интернет)."
    fi
    ok "образ ${IMAGE_NAME}:${TAG} найден ($(docker images         "${IMAGE_NAME}:${TAG}" --format '{{.Size}}'))"
else

step "Сборка образа ${IMAGE_NAME}:${TAG}"
say "Это займёт пару минут; интернет нужен только сейчас."

BUILD_LOG="$(mktemp -t pii-scan-build.XXXXXX.log 2>/dev/null     || echo "${TMPDIR:-/tmp}/pii-scan-build.$$.log")"

BUILD_ARGS=(--build-arg "WITH_NLP=${WITH_NLP}")

if [ -n "$CA_CERT" ]; then
    [ -f "$CA_CERT" ] || die "файл сертификата не найден: $CA_CERT"
    cp "$CA_CERT" "$REPO_DIR/ca-cert.crt"
    ok "корневой сертификат взят из $CA_CERT"
elif [ -f "$REPO_DIR/ca-cert.crt" ]; then
    ok "используется ca-cert.crt из каталога проекта"
fi
[ -n "$PIP_INDEX" ] && BUILD_ARGS+=(--build-arg "PIP_INDEX_URL=${PIP_INDEX}")
[ -n "$TRUSTED_HOST" ] && BUILD_ARGS+=(--build-arg "PIP_TRUSTED_HOST=${TRUSTED_HOST}")

docker build "${BUILD_ARGS[@]}" \
    -t "${IMAGE_NAME}:${TAG}" "$REPO_DIR" >"$BUILD_LOG" 2>&1 || {
        tail -20 "$BUILD_LOG" >&2
        if grep -qE "CERTIFICATE_VERIFY_FAILED|self-signed certificate" \
                "$BUILD_LOG"; then
            if [ -f "$REPO_DIR/ca-cert.crt" ]; then
                CERT_HINT="Сертификат в сборку передавался, но не подошёл —
похоже, это не тот корень, которым подписывает инспектор. Возьмите связку
хоста целиком, в ней есть всё, чему доверяет сам сервер:

    ./install.sh --ca-cert /etc/ssl/certs/ca-certificates.crt"
            else
                CERT_HINT="Так выглядит корпоративный TLS-инспектор: трафик подменяется его
сертификатом, а внутри образа его корневого CA нет. Хост инспектору
доверяет, контейнер — ещё нет. Передайте связку сертификатов хоста:

    ./install.sh --ca-cert /etc/ssl/certs/ca-certificates.crt"
            fi
            die "сборка не удалась: pip не доверяет сертификату pypi.org.

${CERT_HINT}

Если PyPI закрыт полностью, укажите внутреннее зеркало:

    ./install.sh --pip-index https://nexus.corp/repository/pypi/simple \\
                 --trusted-host nexus.corp

Либо соберите образ там, где интернет есть, и перенесите файлом:

    docker save pii-scan:${TAG} | gzip > pii-scan-${TAG}.tar.gz
    gunzip -c pii-scan-${TAG}.tar.gz | docker load
    ./install.sh --skip-build

Полный лог: $BUILD_LOG"
        fi
        die "сборка не удалась, полный лог: $BUILD_LOG"
    }
SIZE=$(docker images "${IMAGE_NAME}:${TAG}" --format '{{.Size}}')
ok "образ ${IMAGE_NAME}:${TAG} собран ($SIZE)"

fi

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
