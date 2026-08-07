#!/usr/bin/env bash
# Sub-Panel 一键安装 / 升级脚本
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/CodeManXposed/Subpanel/main/install.sh | bash
#   或:wget -qO- ... | bash
#   升级:再跑一次同样命令,会保留 /opt/Sub-Panel/{config.yml,data/}
#
# 卸载:/opt/Sub-Panel/uninstall.sh
set -euo pipefail

REPO="${SUB_PANEL_REPO:-CodeManXposed/Subpanel}"
INSTALL_DIR="/opt/Sub-Panel"
TMPFS_DIR="/tmp/sub-panel"
SERVICE_NAME="sub-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
XDB_URL="https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb"
ASN_URL="https://iptoasn.com/data/ip2asn-v4.tsv.gz"

C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'
C_BLUE='\033[0;34m'
C_RESET='\033[0m'

log()  { echo -e "${C_BLUE}[Sub-Panel]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[Sub-Panel]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[Sub-Panel]${C_RESET} $*"; }
die()  { echo -e "${C_RED}[Sub-Panel]${C_RESET} $*" >&2; exit 1; }

# 1) 必须 root
[[ $EUID -eq 0 ]] || die "请用 root 运行(或 sudo)"

# 2) 检测架构
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) die "不支持的架构: $ARCH(目前只发 amd64 / arm64)" ;;
esac
log "架构: $ARCH → $GOARCH"

# 3) 检测依赖
need_cmds=(curl tar systemctl sha256sum od gzip)
for c in "${need_cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || die "缺少命令: $c,请先 apt/yum install"
done

# 4) 取版本号
log "查询最新版本…"
if [[ -n "${SUB_PANEL_VERSION:-}" ]]; then
  TAG="$SUB_PANEL_VERSION"
  log "环境变量指定版本: $TAG"
else
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
  [[ -n "$TAG" ]] || die "未能获取 Release tag,请检查 GitHub API 或手动指定 SUB_PANEL_VERSION=v0.1.0"
  log "最新版本: $TAG"
fi

ASSET="sub-panel-linux-${GOARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

# 5) 是升级还是首装?
IS_UPGRADE=0
if [[ -x "${INSTALL_DIR}/sub-panel" ]]; then
  IS_UPGRADE=1
  OLD_VER="$(${INSTALL_DIR}/sub-panel version 2>/dev/null || echo "unknown")"
  log "检测到已安装 (v${OLD_VER}),将升级到 ${TAG}"
else
  log "首次安装到 ${INSTALL_DIR}"
fi

# 6) 下载二进制
TMP_DIR="$(mktemp -d)"
trap "rm -rf ${TMP_DIR}" EXIT
log "下载: ${DOWNLOAD_URL}"
curl -fL --progress-bar -o "${TMP_DIR}/${ASSET}" "${DOWNLOAD_URL}" \
  || die "下载失败,请检查网络或 Release 是否上传"
curl -fsSL -o "${TMP_DIR}/${ASSET}.sha256" "${CHECKSUM_URL}" \
  || die "校验文件下载失败"
(cd "${TMP_DIR}" && sha256sum -c "${ASSET}.sha256") \
  || die "SHA256 校验失败,拒绝安装"
ok "Release SHA256 校验通过"

log "解包…"
tar -xzf "${TMP_DIR}/${ASSET}" -C "${TMP_DIR}"
[[ -f "${TMP_DIR}/sub-panel" ]] || die "解包后未找到 sub-panel 二进制"

# 7) 准备目录
mkdir -p "${INSTALL_DIR}/data" "${TMPFS_DIR}"

# 8) 停服务(若已运行)
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  log "停止旧服务…"
  systemctl stop "$SERVICE_NAME"
fi

# 9) 替换二进制
install -m 0755 "${TMP_DIR}/sub-panel" "${INSTALL_DIR}/sub-panel"
ok "二进制已安装: ${INSTALL_DIR}/sub-panel"

# 10) 首装才写默认 config 和 xdb
if [[ "$IS_UPGRADE" -eq 0 ]]; then
  if [[ ! -f "${INSTALL_DIR}/config.yml" ]]; then
    log "下载默认 config.yml…"
    curl -fsSL -o "${INSTALL_DIR}/config.yml" \
      "https://raw.githubusercontent.com/${REPO}/main/configs/config.example.yml" \
      || die "下载默认配置失败"
    ADMIN_PASSWORD="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
    ADMIN_HASH="$("${INSTALL_DIR}/sub-panel" hashpwd "${ADMIN_PASSWORD}")"
    sed -i "s|^[[:space:]]*password_hash:.*|  password_hash: \"${ADMIN_HASH}\"|" "${INSTALL_DIR}/config.yml"
    ok "默认配置已写入: ${INSTALL_DIR}/config.yml"
  fi
fi

# 11) 下载 ip2region IPv4 xdb(放 tmpfs + 备份一份到 /opt/Sub-Panel)
if [[ ! -f "${INSTALL_DIR}/ip2region.xdb" ]] || [[ "${SUB_PANEL_REFRESH_XDB:-0}" == "1" ]]; then
  log "下载 ip2region IPv4 xdb(约 11MB)…"
  curl -fL --progress-bar -o "${INSTALL_DIR}/ip2region.xdb" "$XDB_URL" \
    || warn "xdb 下载失败,可手动放到 ${INSTALL_DIR}/ip2region.xdb"
fi
# 拷一份到 tmpfs(内存盘,加速)
if [[ -f "${INSTALL_DIR}/ip2region.xdb" ]]; then
  cp -f "${INSTALL_DIR}/ip2region.xdb" "${TMPFS_DIR}/ip2region.xdb"
  ok "xdb 已就位: ${TMPFS_DIR}/ip2region.xdb(tmpfs)"
fi

# 12) 下载 IPtoASN 离线库(约 6.6MB 压缩,每小时更新)
if [[ ! -f "${INSTALL_DIR}/ip2asn-v4.tsv.gz" ]] || [[ "${SUB_PANEL_REFRESH_ASN:-0}" == "1" ]]; then
  log "下载 IPtoASN IPv4 数据库…"
  curl -fL --progress-bar -o "${TMP_DIR}/ip2asn-v4.tsv.gz" "$ASN_URL" \
    || die "ASN 数据库下载失败"
  gzip -t "${TMP_DIR}/ip2asn-v4.tsv.gz" || die "ASN 数据库 gzip 校验失败"
  install -m 0644 "${TMP_DIR}/ip2asn-v4.tsv.gz" "${INSTALL_DIR}/ip2asn-v4.tsv.gz"
fi
cp -f "${INSTALL_DIR}/ip2asn-v4.tsv.gz" "${TMPFS_DIR}/ip2asn-v4.tsv.gz"
ok "ASN 数据库已就位: ${TMPFS_DIR}/ip2asn-v4.tsv.gz"

# 13) 安装 systemd unit
log "写入 systemd unit…"
curl -fsSL -o "$SERVICE_FILE" \
  "https://raw.githubusercontent.com/${REPO}/main/scripts/sub-panel.service" \
  || die "下载 systemd unit 失败"
systemctl daemon-reload

# 14) 写卸载脚本
log "安装快捷升级脚本…"
curl -fsSL -o "${INSTALL_DIR}/upgrade.sh" \
  "https://raw.githubusercontent.com/${REPO}/main/upgrade.sh" \
  || die "快捷升级脚本下载失败"
chmod 0755 "${INSTALL_DIR}/upgrade.sh"

cat > "${INSTALL_DIR}/uninstall.sh" <<'UNINST'
#!/usr/bin/env bash
# Sub-Panel 卸载脚本。默认保留 config + data,加 --purge 才全删。
set -euo pipefail
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1
[[ $EUID -eq 0 ]] || { echo "请用 root"; exit 1; }

systemctl stop sub-panel 2>/dev/null || true
systemctl disable sub-panel 2>/dev/null || true
rm -f /etc/systemd/system/sub-panel.service
systemctl daemon-reload

if [[ $PURGE -eq 1 ]]; then
  rm -rf /opt/Sub-Panel /tmp/sub-panel
  echo "✓ 已完全卸载(含 config + data)"
else
  rm -f /opt/Sub-Panel/sub-panel /opt/Sub-Panel/ip2region.xdb /opt/Sub-Panel/ip2asn-v4.tsv.gz
  rm -rf /tmp/sub-panel
  echo "✓ 已卸载(保留 /opt/Sub-Panel/config.yml + data/)"
  echo "  完全清除请加 --purge:bash /opt/Sub-Panel/uninstall.sh --purge"
fi
UNINST
chmod +x "${INSTALL_DIR}/uninstall.sh"

# 15) 启动
log "启动服务…"
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl restart "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
  ADMIN_PORT="$(grep -E "^admin_listen:" "${INSTALL_DIR}/config.yml" | awk -F'"' '{print $2}' | awk -F: '{print $2}')"
  ADMIN_LISTEN="$(grep -E "^admin_listen:" "${INSTALL_DIR}/config.yml" | awk -F'"' '{print $2}')"
  ADMIN_HOST="${ADMIN_LISTEN%:*}"
  echo ""
  ok "════════════════════════════════════════════"
  ok " Sub-Panel ${TAG} 安装成功 ✓"
  ok "════════════════════════════════════════════"
  echo ""
  if [[ "$ADMIN_HOST" == "127.0.0.1" || "$ADMIN_HOST" == "localhost" || "$ADMIN_HOST" == "::1" ]]; then
    echo "  管理面:   http://127.0.0.1:${ADMIN_PORT:-19090}/ (仅本机)"
    echo "  SSH 隧道: ssh -L ${ADMIN_PORT:-19090}:127.0.0.1:${ADMIN_PORT:-19090} root@<服务器 IP>"
  else
    PUBLIC_IP="$(curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || echo "<服务器 IP>")"
    echo "  管理面:   http://${PUBLIC_IP}:${ADMIN_PORT:-19090}/"
  fi
  if [[ "$IS_UPGRADE" -eq 0 ]]; then
    echo "  默认账号: admin"
    echo "  初始密码: ${ADMIN_PASSWORD:-请检查现有配置}"
    echo ""
    warn "  请保存初始密码,首次登录后建议立即修改。"
  fi
  echo ""
  echo "  常用命令:"
  echo "    systemctl status  sub-panel    # 状态"
  echo "    systemctl restart sub-panel    # 重启"
  echo "    journalctl -u sub-panel -f     # 看日志"
  echo "    bash /opt/Sub-Panel/upgrade.sh           # 快捷升级"
  echo "    bash /opt/Sub-Panel/uninstall.sh         # 卸载(留数据)"
  echo "    bash /opt/Sub-Panel/uninstall.sh --purge # 完全卸载"
  echo ""
  echo "  升级:bash /opt/Sub-Panel/upgrade.sh（保留 config + data，失败自动回滚）"
  echo ""
else
  warn "服务未能正常启动,查看日志:journalctl -u ${SERVICE_NAME} -e --no-pager"
  systemctl status "$SERVICE_NAME" --no-pager || true
  exit 1
fi
