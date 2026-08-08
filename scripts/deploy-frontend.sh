#!/usr/bin/env bash
# deploy-frontend.sh — 部署 PortHub 前端到已配置的 Core 主机
# 用法: ./deploy-frontend.sh <release名称> [--skip-build]
# 凭据: 优先 SSH Key; 否则传入权限为 600 的临时 SSH_PASSWORD_FILE
#   SSH_PASSWORD_FILE=/tmp/porthub-ssh-password ./deploy-frontend.sh my-release
# 关键: 自动修正 porthub 用户读取权限，并验证线上实际返回 Vue SPA
set -euo pipefail

HOST="${PORTHUB_HOST:-127.0.0.1}"
USER=root
REMOTE_FRONTEND=/opt/porthub/frontend
LOCAL_DIST=/root/web/porthub/apps/frontend/dist
LOCAL_REPO=/root/web/porthub

RELEASE_NAME="${1:?用法: $0 <release名称, 如 mapping-edit> [--skip-build]}"
SKIP_BUILD=0
[ "${2:-}" = "--skip-build" ] && SKIP_BUILD=1
if [[ ! "$RELEASE_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "!! release 名称只能包含字母、数字、点、下划线和连字符" >&2
  exit 1
fi

# --- 凭据: 优先 SSH Key, 否则使用受保护的临时密码文件 ---
SSH_OPTS=(-o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o BatchMode=yes)
if ssh "${SSH_OPTS[@]}" "${USER}@${HOST}" true 2>/dev/null; then
  SSH=(ssh "${SSH_OPTS[@]}")
  SCP=(scp "${SSH_OPTS[@]}")
  echo "==> 使用 SSH Key 认证"
elif [ -n "${SSH_PASSWORD_FILE:-}" ] && [ -f "$SSH_PASSWORD_FILE" ]; then
  mode=$(stat -c '%a' "$SSH_PASSWORD_FILE")
  if [ "$mode" != "600" ]; then
    echo "!! SSH_PASSWORD_FILE 权限必须为 600" >&2
    exit 1
  fi
  SSH=(sshpass -f "$SSH_PASSWORD_FILE" ssh -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
  SCP=(sshpass -f "$SSH_PASSWORD_FILE" scp -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
  echo "==> 使用临时密码文件认证"
else
  echo "!! 未配置凭据: 请设置 SSH_PASSWORD_FILE 或配置 SSH Key ${HOST}" >&2
  exit 1
fi

# 1. 本地构建
if [ "$SKIP_BUILD" != "1" ]; then
  echo "==> 构建前端 (vue-tsc + vite)"
  (cd "${LOCAL_REPO}/apps/frontend" && npm run build)
fi

# 2. 打包
TS=$(date +%Y%m%d-%H%M%S)
RELEASE_DIR="releases/${TS}-${RELEASE_NAME}"
echo "==> 打包 dist -> /tmp/${TS}-${RELEASE_NAME}.tar.gz"
tar -C "$LOCAL_DIST" -czf "/tmp/${TS}-${RELEASE_NAME}.tar.gz" .

# 3. 上传
echo "==> 上传到 ${HOST}"
"${SCP[@]}" "/tmp/${TS}-${RELEASE_NAME}.tar.gz" "${USER}@${HOST}:/tmp/"

# 4. 服务器端: 建 release + 权限修正 + 切软链 + 重启 core
"${SSH[@]}" "${USER}@${HOST}" bash -s <<EOF
set -euo pipefail
REL="${REMOTE_FRONTEND}/releases/${TS}-${RELEASE_NAME}"
mkdir -p "\$REL"
chmod 755 "\$REL"
tar -xzf "/tmp/${TS}-${RELEASE_NAME}.tar.gz" -C "\$REL"
chmod -R a+rX "\$REL"                       # 权限修正: porthub 用户必须可读
ln -sfn "\$REL" "${REMOTE_FRONTEND}/current"
chmod 755 "${REMOTE_FRONTEND}/releases" "${REMOTE_FRONTEND}"
# 验证 porthub 用户确实可读 index.html (core 启动锁定的关键文件)
if ! su -s /bin/sh porthub -c "test -r ${REMOTE_FRONTEND}/current/index.html"; then
  echo "!! index.html 对 porthub 不可读, 中止 (core 会锁定内置模板)" >&2
  exit 1
fi
echo "==> current -> \$REL"
echo "==> 重启 porthub-core (重新评估 frontend-dir, 避免锁定内置模板)"
systemctl restart porthub-core
sleep 2
systemctl is-active porthub-core
EOF

# 5. 验证线上响应是 Vue SPA 而非内置模板
echo "==> 验证 https://${HOST}:9443/"
"${SSH[@]}" "${USER}@${HOST}" bash -s <<EOF
CODE=\$(curl -sk -o /tmp/idx.html -w '%{http_code}' https://localhost:9443/)
echo "HTTP \${CODE}"
if grep -q 'html lang="zh-CN"' /tmp/idx.html && grep -q 'id="app"' /tmp/idx.html; then
  echo "OK: 线上是 Vue SPA"
else
  echo "!! 线上返回内置模板 (core 仍锁定旧版), 检查权限后重启 core" >&2
  exit 1
fi
EOF

echo "==> 完成: ${RELEASE_DIR}"
