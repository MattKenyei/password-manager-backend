#!/usr/bin/env bash
set -euo pipefail

EMAIL="$1"
DEVICE_ID="${2:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"

# Шаг 1: получить соли
curl -sS -X POST http://localhost:8080/auth/login/start \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}"
echo

AUTH_KEY="${AUTH_KEY:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"

curl -sS -X POST http://localhost:8080/auth/login/finish \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"auth_key\": \"$AUTH_KEY\",
    \"device_id\": \"$DEVICE_ID\",
    \"device_name\": \"Test Device\",
    \"device_platform\": \"linux\"
  }"
echo