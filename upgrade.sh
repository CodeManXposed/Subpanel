#!/usr/bin/env bash
# Sub-Panel 快捷升级脚本：只更新二进制，保留 config.yml 与 data/。
#
# 在线执行：
#   curl -fsSL https://raw.githubusercontent.com/CodeManXposed/Subpanel/main/upgrade.sh | bash
# 本机执行：
#   bash /opt/Sub-Panel/upgrade.sh
# 指定版本：
#   SUB_PANEL_VERSION=v0.1.66 bash /opt/Sub-Panel/upgrade.sh
set -euo pipefail

REPO="${SUB_PANEL_REPO:-CodeManXposed/Subpanel}"
INSTALL_DIR="${SUB_PANEL_INSTALL_DIR:-/opt/Sub-Panel}"
SERVICE_NAME="${SUB_PANEL_SERVICE:-sub-panel}"
BINARY="${INSTALL_DIR}/sub-panel"

C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'
C_BLUE='\033[0;34m'
C_RESET='\033[0m'

log()  { echo -e "${C_BLUE}[Sub-Panel]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[Sub-Panel]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[Sub-Panel]${C_RESET} $*"; }
die()  { echo -e "${C_RED}[Sub-Panel]${C_RESET} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行（或 sudo）"
[[ -x "$BINARY" ]] || die "未找到 ${BINARY}，请先运行 install.sh 完成安装"
[[ -f "${INSTALL_DIR}/config.yml" ]] || die "未找到 ${INSTALL_DIR}/config.yml，拒绝升级"

case "$(uname -m)" in
  x86_64|amd64)  GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) die "不支持的架构: $(uname -m)" ;;
esac

for cmd in curl tar systemctl sha256sum install; do
  command -v "$cmd" >/dev/null 2>&1 || die "缺少命令: $cmd"
done

CURRENT_VERSION="$($BINARY version 2>/dev/null || echo unknown)"
if [[ -n "${SUB_PANEL_VERSION:-}" ]]; then
  TAG="$SUB_PANEL_VERSION"
else
  log "查询 GitHub 最新 Release…"
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
fi
[[ -n "$TAG" ]] || die "无法获取最新版本，可通过 SUB_PANEL_VERSION=v0.1.66 指定"
[[ "$TAG" == v* ]] || TAG="v${TAG}"
TARGET_VERSION="${TAG#v}"

log "当前版本: v${CURRENT_VERSION}"
log "目标版本: ${TAG}"
if [[ "$CURRENT_VERSION" == "$TARGET_VERSION" && "${SUB_PANEL_FORCE:-0}" != "1" ]]; then
  ok "当前已是最新版本，无需升级"
  exit 0
fi

ASSET="sub-panel-linux-${GOARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log "下载 ${ASSET}…"
curl -fL --progress-bar -o "${TMP_DIR}/${ASSET}" "${BASE_URL}/${ASSET}" \
  || die "下载失败，请确认 Release ${TAG} 已发布"
curl -fsSL -o "${TMP_DIR}/${ASSET}.sha256" "${BASE_URL}/${ASSET}.sha256" \
  || die "SHA256 文件下载失败"
(cd "$TMP_DIR" && sha256sum -c "${ASSET}.sha256") \
  || die "SHA256 校验失败，已停止升级"

tar -xzf "${TMP_DIR}/${ASSET}" -C "$TMP_DIR"
[[ -x "${TMP_DIR}/sub-panel" ]] || chmod 0755 "${TMP_DIR}/sub-panel"
DOWNLOADED_VERSION="$("${TMP_DIR}/sub-panel" version 2>/dev/null || true)"
[[ "$DOWNLOADED_VERSION" == "$TARGET_VERSION" ]] \
  || die "版本校验失败：下载文件为 v${DOWNLOADED_VERSION:-unknown}，目标为 ${TAG}"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${INSTALL_DIR}/sub-panel.backup.v${CURRENT_VERSION}.${STAMP}"
install -m 0755 "$BINARY" "$BACKUP"
install -m 0755 "${TMP_DIR}/sub-panel" "${BINARY}.new"
ok "旧版本已备份到 ${BACKUP}"

log "替换二进制并重启服务…"
systemctl stop "$SERVICE_NAME"
mv -f "${BINARY}.new" "$BINARY"
systemctl start "$SERVICE_NAME"

ACTIVE=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    ACTIVE=1
    break
  fi
  sleep 1
done

if [[ "$ACTIVE" -ne 1 ]]; then
  warn "新版本启动失败，正在自动回滚…"
  install -m 0755 "$BACKUP" "$BINARY"
  systemctl restart "$SERVICE_NAME" || true
  systemctl status "$SERVICE_NAME" --no-pager || true
  die "升级失败，已恢复 v${CURRENT_VERSION}"
fi

INSTALLED_VERSION="$($BINARY version 2>/dev/null || echo unknown)"
if [[ "$INSTALLED_VERSION" != "$TARGET_VERSION" ]]; then
  warn "服务已启动，但版本输出异常: v${INSTALLED_VERSION}"
fi

ok "升级完成: v${CURRENT_VERSION} → v${INSTALLED_VERSION}"
echo "  状态: systemctl status ${SERVICE_NAME}"
echo "  日志: journalctl -u ${SERVICE_NAME} -f"
echo "  回滚: install -m 0755 ${BACKUP} ${BINARY} && systemctl restart ${SERVICE_NAME}"
