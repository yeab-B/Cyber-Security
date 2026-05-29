#!/bin/bash
# ── VulnAssess Pro — Restart & Full Endpoint Test ──────────────────────────────
set -e

BACKEND_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BACKEND_DIR"

echo "════════════════════════════════════════════════════════"
echo "  VulnAssess Pro — Backend Restart & Test Suite"
echo "════════════════════════════════════════════════════════"

# Activate venv
if [ -d ".venv" ]; then
  source .venv/bin/activate
elif [ -d "venv" ]; then
  source venv/bin/activate
else
  echo "❌ No virtual environment found (.venv or venv)"
  exit 1
fi

echo "✅ Virtual environment activated"
echo "   Python: $(python --version)"

# Kill existing server
pkill -f "uvicorn app.main:app" 2>/dev/null && echo "✅ Stopped existing server" || echo "   No existing server to stop"
sleep 2

# Start server in background
echo ""
echo "🚀 Starting server..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 2>&1 &
SERVER_PID=$!
sleep 4

# Check if running
if ! kill -0 $SERVER_PID 2>/dev/null; then
  echo "❌ Server failed to start"
  exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"
echo ""

# ── TESTS ──────────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

test_endpoint() {
  local NAME="$1"
  local RESULT="$2"
  local EXPECTED="$3"
  if echo "$RESULT" | grep -q "$EXPECTED"; then
    echo "  ✅ $NAME"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $NAME — got: $(echo "$RESULT" | head -c 200)"
    FAIL=$((FAIL + 1))
  fi
}

echo "── Test 1: Health Check ──────────────────────────────"
HEALTH=$(curl -sf http://localhost:8000/api/health 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/health" "$HEALTH" "healthy"

echo ""
echo "── Test 2: Register ──────────────────────────────────"
RAND=$(date +%s)
REG=$(curl -sf -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"test${RAND}@test.com\",\"username\":\"testuser${RAND}\",\"password\":\"TestPass@2025!\",\"full_name\":\"Test User\"}" 2>&1 || echo "CURL_ERROR")
test_endpoint "POST /api/auth/register" "$REG" "access_token"
TOKEN=$(echo "$REG" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)

echo ""
echo "── Test 3: Login ─────────────────────────────────────"
LOGIN=$(curl -sf -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"testuser${RAND}\",\"password\":\"TestPass@2025!\"}" 2>&1 || echo "CURL_ERROR")
test_endpoint "POST /api/auth/login" "$LOGIN" "access_token"
if echo "$LOGIN" | grep -q "access_token"; then
  TOKEN=$(echo "$LOGIN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)
fi

echo ""
echo "── Test 4: Admin Login ───────────────────────────────"
ADMIN_LOGIN=$(curl -sf -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"VulnAdmin@2025!"}' 2>&1 || echo "CURL_ERROR")
test_endpoint "POST /api/auth/login (admin)" "$ADMIN_LOGIN" "access_token"
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)

echo ""
echo "── Test 5: Get Profile (/auth/me) ────────────────────"
ME=$(curl -sf http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/auth/me" "$ME" "username"

echo ""
echo "── Test 6: Dashboard Stats ───────────────────────────"
DASH=$(curl -sf http://localhost:8000/api/dashboard/stats \
  -H "Authorization: Bearer $TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/dashboard/stats" "$DASH" "total_scans"

echo ""
echo "── Test 7: Reports List ──────────────────────────────"
REPORTS=$(curl -sf http://localhost:8000/api/reports/ \
  -H "Authorization: Bearer $TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/reports/" "$REPORTS" "\[\]"

echo ""
echo "── Test 8: Web Scan ──────────────────────────────────"
SCAN=$(curl -sf -X POST http://localhost:8000/api/scans/web \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://httpbin.org","scan_depth":"quick"}' \
  --max-time 60 2>&1 || echo "CURL_ERROR")
test_endpoint "POST /api/scans/web" "$SCAN" "security_score"

echo ""
echo "── Test 9: Admin Users (admin token) ─────────────────"
USERS=$(curl -sf http://localhost:8000/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/admin/users" "$USERS" "username"

echo ""
echo "── Test 10: Admin Stats ──────────────────────────────"
ASTATS=$(curl -sf http://localhost:8000/api/admin/stats \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/admin/stats" "$ASTATS" "total_users"

echo ""
echo "── Test 11: Admin Audit Logs ─────────────────────────"
ALOGS=$(curl -sf http://localhost:8000/api/admin/audit-logs \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/admin/audit-logs" "$ALOGS" "\["

echo ""
echo "── Test 12: Unauthorized (no token) ──────────────────"
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/dashboard/stats 2>&1 || echo "CURL_ERROR")
test_endpoint "GET /api/dashboard/stats (no token) → 401" "$UNAUTH" "401"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Results: ✅ $PASS passed  ❌ $FAIL failed"
echo "════════════════════════════════════════════════════════"
echo ""
echo "📌 Default Admin Credentials:"
echo "   Username: admin"
echo "   Password: VulnAdmin@2025!"
echo ""
echo "🌐 Server running at: http://localhost:8000"
echo "📖 API Docs at:       http://localhost:8000/api/docs"
echo "🖥️  Open frontend:    file://${BACKEND_DIR}/../frontend/app.html"
echo ""
