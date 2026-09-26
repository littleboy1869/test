#!/usr/bin/env bash
# Run self-hosted Firecrawl in a Claude Code cloud container without Docker networking.
#
# Containers there can't reach the internet, so this copies the prebuilt apps out of the
# official images and runs everything as plain processes that use the session's
# HTTPS proxy. Docker is used only to unpack the images.
#
#   ./firecrawl-local.sh setup   # once per container: packages, images, database
#   ./firecrawl-local.sh start   # start all services (foreground; Ctrl-C stops them)
#
# Then: firecrawl --api-url http://localhost:3002 --api-key local scrape <url>
set -euo pipefail

D=/opt/firecrawl
LOGS=$D/logs
: "${HTTPS_PROXY:?HTTPS_PROXY must be set (the cloud session proxy)}"
CA=/root/.ccr/ca-bundle.crt

setup() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    redis-server rabbitmq-server postgresql-16 postgresql-16-cron libnss3-tools git >/dev/null

  # Let Chromium trust the session proxy's CA.
  mkdir -p /root/.pki/nssdb
  certutil -d sql:/root/.pki/nssdb -L -n ccr-agent-proxy >/dev/null 2>&1 ||
    certutil -d sql:/root/.pki/nssdb -A -t "C,," -n ccr-agent-proxy -i /root/.ccr/agent-proxy-ca.crt

  # Unpack the prebuilt apps from the official images.
  pgrep -x dockerd >/dev/null || { dockerd >/tmp/dockerd.log 2>&1 & sleep 5; }
  mkdir -p "$D"
  for img in firecrawl playwright-service; do
    [ -d "$D/$img" ] && continue
    docker pull -q "ghcr.io/firecrawl/$img:latest"
    c=$(docker create "ghcr.io/firecrawl/$img:latest")
    docker cp "$c:$(docker inspect "ghcr.io/firecrawl/$img:latest" -f '{{.Config.WorkingDir}}')" "$D/$img"
    docker rm "$c" >/dev/null
  done
  # The image's Chromium isn't copied; use the machine's preinstalled one instead.
  grep -q 'executablePath: process.env.CHROME_PATH' "$D/playwright-service/dist/api.js" ||
    sed -i 's/chromium\.launch({/chromium.launch({ executablePath: process.env.CHROME_PATH || undefined,/' \
      "$D/playwright-service/dist/api.js"

  # Postgres with pg_cron and the NuQ job-queue schema.
  conf=/etc/postgresql/16/main/postgresql.conf
  grep -q "^shared_preload_libraries = 'pg_cron'" $conf ||
    printf "\nshared_preload_libraries = 'pg_cron'\ncron.database_name = 'postgres'\n" >>$conf
  [ -f "$D/nuq.sql" ] || {
    tmp=$(mktemp -d)
    git clone -q --depth 1 https://github.com/firecrawl/firecrawl.git "$tmp/fc"
    cp "$tmp/fc/apps/nuq-postgres/nuq.sql" "$D/nuq.sql" && chmod 644 "$D/nuq.sql"
    rm -rf "$tmp"
  }
  start_postgres
  su postgres -c "psql -q -c \"alter user postgres password 'postgres'\""
  PGPASSWORD=postgres psql -h 127.0.0.1 -U postgres -tAc "select 1 from pg_namespace where nspname='nuq'" | grep -q 1 ||
    PGPASSWORD=postgres psql -h 127.0.0.1 -U postgres -q -v ON_ERROR_STOP=1 -f "$D/nuq.sql" >/dev/null
  echo "setup done; run: $0 start"
}

start_postgres() {
  mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql
  pgrep -u postgres -x postgres >/dev/null && return
  su postgres -c "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main \
    -c config_file=/etc/postgresql/16/main/postgresql.conf -c listen_addresses=127.0.0.1" \
    >"$LOGS/postgres.log" 2>&1 &
  for _ in $(seq 30); do pg_isready -q -h 127.0.0.1 && return; sleep 1; done
  echo "postgres did not start; see $LOGS/postgres.log" >&2; exit 1
}

start() {
  mkdir -p "$LOGS"
  trap 'kill $(jobs -p) 2>/dev/null' EXIT
  pgrep -x redis-server >/dev/null ||
    redis-server --bind 127.0.0.1 --port 6379 --save "" --appendonly no >"$LOGS/redis.log" 2>&1 &
  pgrep -f 'beam.*rabbit' >/dev/null ||
    RABBITMQ_NODE_IP_ADDRESS=127.0.0.1 RABBITMQ_NODENAME=rabbit@localhost \
      rabbitmq-server >"$LOGS/rabbitmq.log" 2>&1 &
  start_postgres

  (cd "$D/playwright-service" &&
    PORT=3000 CHROME_PATH=/opt/pw-browsers/chromium PROXY_SERVER="$HTTPS_PROXY" \
      MAX_CONCURRENT_PAGES=4 exec node dist/api.js) >"$LOGS/playwright.log" 2>&1 &

  for _ in $(seq 60); do rabbitmq-diagnostics -q check_running >/dev/null 2>&1 && break; sleep 2; done

  cd "$D/firecrawl"
  echo "Firecrawl API starting on http://localhost:3002 (logs: $LOGS)"
  env HOST=127.0.0.1 PORT=3002 ENV=local USE_DB_AUTHENTICATION=false \
    REDIS_URL=redis://127.0.0.1:6379 REDIS_RATE_LIMIT_URL=redis://127.0.0.1:6379 \
    PLAYWRIGHT_MICROSERVICE_URL=http://127.0.0.1:3000/scrape \
    POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres POSTGRES_DB=postgres \
    POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=5432 NUQ_RABBITMQ_URL=amqp://127.0.0.1:5672 \
    NUM_WORKERS_PER_QUEUE=4 MAX_CONCURRENT_JOBS=3 BROWSER_POOL_SIZE=3 \
    PROXY_SERVER="$HTTPS_PROXY" NODE_EXTRA_CA_CERTS="$CA" \
    node dist/src/harness.js --start-docker
}

case "${1:-}" in
  setup) mkdir -p "$LOGS"; setup ;;
  start) start ;;
  *) echo "usage: $0 setup|start" >&2; exit 2 ;;
esac
