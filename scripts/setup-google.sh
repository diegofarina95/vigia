#!/usr/bin/env bash
#
# Vigía — conecta el cliente OAuth de Google (lado servidor automatizado).
#
# Lo ÚNICO que no puede automatizarse es crear el cliente OAuth en la
# consola de Google (Google no lo permite por API). Este script te guía en
# esos pasos y luego hace todo lo demás: valida los valores, escribe el
# .env, desactiva el modo demo, reinicia el servicio y comprueba que el
# flujo real arranca contra Google.
#
set -euo pipefail

ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env"
REDIRECT_URI="https://diegofarina.com/vigia/api/auth/google/callback"
SCOPES=(
  "https://www.googleapis.com/auth/admin.directory.user.readonly"
  "https://www.googleapis.com/auth/admin.directory.domain.readonly"
  "https://www.googleapis.com/auth/admin.reports.audit.readonly"
  "https://www.googleapis.com/auth/admin.reports.usage.readonly"
)

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }

cat <<EOF

$(bold "Vigía · configuración del cliente Google OAuth")

Haz esto una vez en la consola de Google (con tu cuenta admin de Workspace).
Cada paso lleva enlace directo a la pantalla exacta — solo clicas y pegas.

  1. Crea un proyecto NUEVO (no reutilices el de Butaca/VetPassport):
       $(bold "https://console.cloud.google.com/projectcreate")

  2. Habilita la "Admin SDK API" (con el proyecto nuevo seleccionado):
       $(bold "https://console.cloud.google.com/apis/library/admin.googleapis.com")

  3. Pantalla de consentimiento de OAuth:
       $(bold "https://console.cloud.google.com/apis/credentials/consent")
       - Tipo de usuario: External (o Internal si solo tu propia org).
       - En "Datos de acceso" añade EXACTAMENTE estos 4 scopes:
$(for s in "${SCOPES[@]}"; do echo "           $s"; done)
       - En "Usuarios de prueba" añádete a ti mismo (así puedes usarla ya,
         sin esperar a la verificación de Google).

  4. Crea el cliente OAuth:
       $(bold "https://console.cloud.google.com/apis/credentials")
       - Crear credenciales > ID de cliente de OAuth
       - Tipo de aplicación: Aplicación web
       - URI de redireccionamiento autorizado (cópialo TAL CUAL):
           $(bold "$REDIRECT_URI")

  5. Copia el "ID de cliente" y el "Secreto de cliente" que te da Google
     y pégalos aquí abajo. Yo hago el resto.

EOF

read -rp "ID de cliente (…apps.googleusercontent.com): " CLIENT_ID
read -rsp "Secreto de cliente (GOCSPX-…): " CLIENT_SECRET
echo

CLIENT_ID="$(echo "$CLIENT_ID" | xargs)"
CLIENT_SECRET="$(echo "$CLIENT_SECRET" | xargs)"

if [[ ! "$CLIENT_ID" =~ \.apps\.googleusercontent\.com$ ]]; then
  red "✗ El client_id no acaba en .apps.googleusercontent.com — revísalo."
  exit 1
fi
if [[ -z "$CLIENT_SECRET" ]]; then
  red "✗ El secreto está vacío."
  exit 1
fi
if [[ ! "$CLIENT_SECRET" =~ ^GOCSPX- ]]; then
  echo "⚠ El secreto no empieza por 'GOCSPX-' (formato habitual). Continúo igualmente."
fi

# Reescribe las claves en el .env sin tocar el resto.
python3 - "$ENV_FILE" "$CLIENT_ID" "$CLIENT_SECRET" <<'PY'
import re, sys
path, cid, secret = sys.argv[1], sys.argv[2], sys.argv[3]
env = open(path).read()
def setkey(env, key, value):
    line = f"{key}={value}"
    if re.search(rf"^{key}=", env, re.M):
        return re.sub(rf"^{key}=.*$", line, env, flags=re.M)
    return env.rstrip() + "\n" + line + "\n"
env = setkey(env, "GOOGLE_CLIENT_ID", cid)
env = setkey(env, "GOOGLE_CLIENT_SECRET", secret)
env = setkey(env, "MOCK_MODE", "0")
open(path, "w").write(env)
print("  .env actualizado (MOCK_MODE=0, credenciales escritas)")
PY

green "✓ Credenciales guardadas."

echo "Reiniciando el servicio…"
systemctl --user restart vigia.service
sleep 2
if ! systemctl --user is-active --quiet vigia.service; then
  red "✗ El servicio no arrancó. Mira: journalctl --user -u vigia.service -n 30"
  exit 1
fi

echo "Comprobando que /api/auth/google/start ya redirige a Google…"
LOCATION="$(curl -s -o /dev/null -D - "http://127.0.0.1:8110/api/auth/google/start" | grep -i '^location:' | tr -d '\r' | cut -d' ' -f2-)"
if [[ "$LOCATION" == *"accounts.google.com"* ]]; then
  green "✓ Listo. Vigía ya usa Google de verdad."
  echo "   Entra en https://diegofarina.com/vigia y pulsa «Connect Workspace»."
  echo "   (La primera vez Google pedirá verificar la app; para pruebas puedes"
  echo "    añadirte como usuario de test en la pantalla de consentimiento.)"
else
  red "✗ Aún no redirige a Google (Location: ${LOCATION:-vacío})."
  echo "   Revisa que MOCK_MODE=0 y las credenciales en $ENV_FILE."
  exit 1
fi
