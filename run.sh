#!/usr/bin/env bash
# 构建并启动 靶场(:8081) + 检测平台(:8082)
set -euo pipefail
cd "$(dirname "$0")"

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}"
MVN="$HOME/tools/apache-maven-3.9.11/bin/mvn"
[ -x "$MVN" ] || MVN=mvn

echo "== 构建 =="
( cd idor-target   && "$MVN" -q -B package -DskipTests )
( cd idor-detector && "$MVN" -q -B package -DskipTests )

echo "== 启动 =="
kill $(lsof -ti:8081) $(lsof -ti:8082) 2>/dev/null || true
sleep 1
java -jar idor-target/target/quarkus-app/quarkus-run.jar   > /tmp/idor-target.log   2>&1 &
java -jar idor-detector/target/quarkus-app/quarkus-run.jar > /tmp/idor-detector.log 2>&1 &
sleep 5

echo "== 灌入演示数据并扫描 =="
curl -s -X POST http://localhost:8082/api/demo/seed > /dev/null
curl -s -X POST http://localhost:8082/api/scan -H 'Content-Type: application/json' \
  -d '{"baselineAccount":"admin-a","lowPrivAccount":"user-a","crossTenantAccount":"user-b","similarityThreshold":0.8}' \
  | python3 -c "
import json,sys
from collections import Counter
r = json.load(sys.stdin)
print('findings:', len(r['findings']), dict(Counter(f['verdict'] for f in r['findings'])))
"
echo
echo "靶场:     http://localhost:8081  (token-admin-a / token-user-a / token-user-b)"
echo "检测平台: http://localhost:8082  (UI)"
