#!/bin/bash

echo "=================================="
echo "Testing Authentication Flow"
echo "=================================="
echo ""

# Step 1: Login
echo "Step 1: Login as admin"
echo "------------------------"
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')

echo "Login Response:"
echo "$LOGIN_RESPONSE" | python3 -m json.tool
echo ""

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "❌ Failed to get token"
    exit 1
fi

echo "✓ Token received: ${TOKEN:0:50}..."
echo ""

# Step 2: Test /me endpoint
echo "Step 2: Get current user info (/auth/me)"
echo "------------------------------------------"
ME_RESPONSE=$(curl -s http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN")

echo "Me Response:"
echo "$ME_RESPONSE" | python3 -m json.tool
echo ""

# Step 3: Test other protected endpoints
echo "Step 3: Test protected endpoint (/devices)"
echo "--------------------------------------------"
DEVICES_RESPONSE=$(curl -s http://localhost:8000/api/devices \
  -H "Authorization: Bearer $TOKEN")

echo "Devices Response:"
echo "$DEVICES_RESPONSE" | python3 -m json.tool | head -20
echo ""

# Step 4: Test with CORS headers (simulate frontend)
echo "Step 4: Test with CORS headers (simulating frontend)"
echo "-----------------------------------------------------"
CORS_RESPONSE=$(curl -s http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: http://localhost:3000" \
  -v 2>&1 | grep -E "(< HTTP|< access-control|username)")

echo "CORS Headers:"
echo "$CORS_RESPONSE"
echo ""

# Step 5: Test without token
echo "Step 5: Test without token (should fail)"
echo "------------------------------------------"
NO_AUTH_RESPONSE=$(curl -s http://localhost:8000/api/auth/me)

echo "No Auth Response:"
echo "$NO_AUTH_RESPONSE" | python3 -m json.tool
echo ""

echo "=================================="
echo "Authentication Test Complete"
echo "=================================="
