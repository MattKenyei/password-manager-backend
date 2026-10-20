# ============ 1. Регистрация + логин ============
EMAIL="sync-test-$(date +%s)@example.com"
AUTH_KEY=$(head -c 32 /dev/urandom | base64 -w 0)
AUTH_SALT=$(head -c 16 /dev/urandom | base64 -w 0)
ENC_SALT=$(head -c 16 /dev/urandom | base64 -w 0)
WRAPPED=$(head -c 80 /dev/urandom | base64 -w 0)
DEVICE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

echo "=== Register $EMAIL ==="
curl -sS -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"auth_key\":\"$AUTH_KEY\",\"auth_salt\":\"$AUTH_SALT\",\"enc_salt\":\"$ENC_SALT\",\"kdf_params\":\"eyJhbGdvIjoiYXJnb24yaWQifQ==\",\"wrapped_account_key\":\"$WRAPPED\"}"
echo

echo "=== Login ==="
LOGIN_RESP=$(curl -sS -X POST http://localhost:8080/auth/login/finish \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"auth_key\":\"$AUTH_KEY\",\"device_id\":\"$DEVICE_ID\",\"device_name\":\"Test\",\"device_platform\":\"linux\"}")

# Get tokens
ACCESS=$(echo "$LOGIN_RESP" | grep -oE '"access_token":"[^"]*"' | cut -d'"' -f4)
REFRESH=$(echo "$LOGIN_RESP" | grep -oE '"refresh_token":"[^"]*"' | cut -d'"' -f4)

echo "ACCESS length: ${#ACCESS}"
echo "REFRESH length: ${#REFRESH}"
echo

if [ -z "$ACCESS" ]; then
  echo "!!! LOGIN FAILED !!!"
  echo "$LOGIN_RESP"
  exit 1
fi

# ============ 2. Check /devices ============
echo "=== GET /devices ==="
curl -sS -H "Authorization: Bearer $ACCESS" http://localhost:8080/devices
echo

# ============ 3. Create item ============
ITEM_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
BLOB=$(head -c 50 /dev/urandom | base64 -w 0)

echo "=== POST /sync (create) ==="
curl -sS -X POST http://localhost:8080/sync \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"changes\":[{\"id\":\"$ITEM_ID\",\"encrypted_blob\":\"$BLOB\",\"base_version\":0,\"deleted\":false}]}"
echo

# ============ 4. Pull all ============
echo "=== GET /sync?since=0 ==="
curl -sS -H "Authorization: Bearer $ACCESS" "http://localhost:8080/sync?since=0"
echo

# ============ 5. Update ============
BLOB2=$(head -c 50 /dev/urandom | base64 -w 0)
echo "=== POST /sync (update, base=1) ==="
curl -sS -X POST http://localhost:8080/sync \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"changes\":[{\"id\":\"$ITEM_ID\",\"encrypted_blob\":\"$BLOB2\",\"base_version\":1,\"deleted\":false}]}"
echo

# ============ 6. Conflict (base_version) ============
BLOB3=$(head -c 50 /dev/urandom | base64 -w 0)
echo "=== POST /sync (conflict, base=1) ==="
curl -sS -X POST http://localhost:8080/sync \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"changes\":[{\"id\":\"$ITEM_ID\",\"encrypted_blob\":\"$BLOB3\",\"base_version\":1,\"deleted\":false}]}"
echo

# ============ 7. Pull since 2 (must be empty) ============
echo "=== GET /sync?since=2 ==="
curl -sS -H "Authorization: Bearer $ACCESS" "http://localhost:8080/sync?since=2"
echo

# ============ 8. DB for check ============
echo "=== DB state ==="
docker compose exec postgres psql -U pm_user -d password_manager \
  -c "SELECT id, version, global_revision, deleted FROM items WHERE user_id = (SELECT id FROM users WHERE email = '$EMAIL');"
docker compose exec postgres psql -U pm_user -d password_manager \
  -c "SELECT current_revision FROM user_revisions WHERE user_id = (SELECT id FROM users WHERE email = '$EMAIL');"