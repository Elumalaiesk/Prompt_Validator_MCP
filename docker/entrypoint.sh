#!/usr/bin/env bash
set -euo pipefail

# Wait for Postgres, run migrations, optionally seed, then start the server.

echo "[entrypoint] applying database migrations..."
for attempt in $(seq 1 30); do
  if alembic upgrade head; then
    echo "[entrypoint] migrations applied."
    break
  fi
  echo "[entrypoint] db not ready (attempt ${attempt}/30); retrying in 2s..."
  sleep 2
done

if [ "${MPV_SEED:-false}" = "true" ]; then
  echo "[entrypoint] seeding baseline roles/admin..."
  mpv-seed || echo "[entrypoint] seed step reported a non-zero status (may already be seeded)."
fi

echo "[entrypoint] starting: $*"
exec "$@"
