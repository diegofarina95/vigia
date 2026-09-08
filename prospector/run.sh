#!/usr/bin/env bash
# La consola de revisión. Solo tailnet.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ./.env; set +a
# `vigia` vive en el backend y no está instalado en el venv: sin esto el escaneo
# real muere con ModuleNotFoundError dentro del hilo de fondo, donde no se ve.
export PYTHONPATH="/home/diego/vigia/backend${PYTHONPATH:+:$PYTHONPATH}"
exec /home/diego/vigia/backend/.venv/bin/python -m prospector.app
