#!/usr/bin/env bash
set -euo pipefail

# A fresh Compose project exercises production startup without the scenario DB.
PRODUCTION_PROJECT="${COMPOSE_PROJECT_NAME}-prod"
KEY_DIRECTORY=$(mktemp -d)
# shellcheck disable=SC2317 -- invoked via EXIT trap
cleanup() {
  docker compose -p "$PRODUCTION_PROJECT" -f docker-compose.prod.yaml down --volumes --remove-orphans
  rm -rf "$KEY_DIRECTORY"
}
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_DIRECTORY/private.pem" 2>/dev/null
# The Buildpacks image runs as a non-root user. This is a disposable test key.
chmod 755 "$KEY_DIRECTORY"
chmod 644 "$KEY_DIRECTORY/private.pem"
export TOLO_IDP_IMAGE="$CI_APP_IMAGE"
export TOLO_IDP_POSTGRES_PASSWORD=tolo-idp-ci
export TOLO_IDP_ISSUER=http://localhost:8080
export TOLO_IDP_JWK_PRIVATE_KEY_HOST_PATH="$KEY_DIRECTORY/private.pem"
export TOLO_IDP_JWK_PRIVATE_KEY_LOCATION=/run/tolo-idp/private.pem

docker compose -p "$PRODUCTION_PROJECT" -f docker-compose.prod.yaml up -d --pull never
for _ in $(seq 1 60); do
  if curl --fail --silent --connect-timeout 2 --max-time 3 http://localhost:8080/actuator/health | grep -q '"status":"UP"'; then
    curl --fail --silent --connect-timeout 2 --max-time 3 http://localhost:8080/.well-known/openid-configuration \
      | python3 -c 'import json, sys; assert json.load(sys.stdin)["issuer"] == "http://localhost:8080"'
    exit 0
  fi
  sleep 2
done
docker compose -p "$PRODUCTION_PROJECT" -f docker-compose.prod.yaml ps -a
echo 'Production image did not become healthy' >&2
exit 1
