#!/usr/bin/env bash
# Solo el enlace de baja. Es la única superficie pública, a propósito.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ./.env; set +a
exec /home/diego/vigia/backend/.venv/bin/python -m prospector.public
