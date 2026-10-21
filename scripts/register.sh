#!/usr/bin/env bash
set -euo pipefail

EMAIL="${1:-test-$(date +%s)@example.com}"
AUTH_KEY=$(head -c 32 /dev/urandom | base64 -w 0)
AUTH_SALT=$(head -c 16 /dev/urandom | base64 -w 0)
ENC_SALT=$(head -c 16 /dev/urandom | base64 -w 0)
WRAPPED=$(head -c 80 /dev/urandom | base64 -w 0)

curl -sS -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"auth_key\": \"$AUTH_KEY\",
    \"auth_salt\": \"$AUTH_SALT\",
    \"enc_salt\": \"$ENC_SALT\",
    \"kdf_params\": \"eyJhbGdvIjoiYXJnb24yaWQifQ==\",
    \"wrapped_account_key\": \"$WRAPPED\"
  }"
echo