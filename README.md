# Sub-Panel

V2Board 订阅前置反代清洗网关 —— 黑名单 / 风控规则 / GeoIP / 投毒 / Web 管理面板。

## 特性

- 🛡️ **反代清洗**:挡掉浏览器直访、云厂商 IP、海外节点扫描
- 🌍 **GeoIP**:ip2region xdb 满载版,本地 mmap 内存查询
- 🎯 **触发规则**:token 频次 / 多 IP / 滑窗模型,命中自动封禁或投毒
- 📊 **管理面板**:租户管理 / 请求日志 / 异常事件 / 检测规则 / Top IP 地区 ISP
- ☠️ **投毒**:命中可疑请求时返回伪造订阅,真节点照常工作
- 🔐 **一键透传**:紧急回滚开关,跳过所有规则
- 📦 **单二进制**:零依赖,systemd 托管,在线升级保留数据

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/huabanmao168/SubPanel/main/install.sh | bash
```

支持 Linux amd64 / arm64。

## 升级

再跑一次同样的命令即可。会自动:

- 停服务 → 替换二进制 → 重启
- 保留 `/opt/Sub-Panel/config.yml` 和 `/opt/Sub-Panel/data/`

## 目录结构

```
/opt/Sub-Panel/
├── sub-panel              # 主二进制
├── config.yml             # 配置文件(自行修改)
├── ip2region.xdb          # GeoIP 数据(原始拷贝)
├── uninstall.sh           # 卸载脚本
└── data/
    ├── sub-panel.db       # SQLite 业务库
    └── salt               # HMAC 盐(首启自动生成)

/tmp/sub-panel/
└── ip2region.xdb          # GeoIP tmpfs 副本(内存盘,mmap 加速)
```

## 默认凭据

- 管理面:`http://<服务器 IP>:19090/`
- 账号:`admin`
- 密码:`admin123456`

**⚠️ 首次登录后请立刻在「设置」页改密。**

## 常用命令

```bash
systemctl status  sub-panel       # 状态
systemctl restart sub-panel       # 重启
journalctl -u sub-panel -f        # 实时日志

bash /opt/Sub-Panel/uninstall.sh           # 卸载(保留 config + data)
bash /opt/Sub-Panel/uninstall.sh --purge   # 完全卸载
```

## 监听端口

| 端口    | 用途                       |
|---------|----------------------------|
| `18443` | 反代入口(对外订阅地址)   |
| `19090` | 管理面板 + API             |

在配置文件 `listen` / `admin_listen` 处可改。

## 配置租户

管理面 → 租户管理 → 新增,填:

- `name`:租户标识(英文)
- `host`:订阅域名(如 `s.example.com`)
- `subscribe_path`:订阅路径前缀(如 `/sub/cat`)
- `upstream`:上游 V2Board 地址(如 `https://panel.example.com`)
- `upstream_path`:上游订阅路径(一般 `/api/v1/client/subscribe`)

## 本地构建

```bash
git clone https://github.com/huabanmao168/SubPanel.git
cd SubPanel
go build -o sub-panel ./cmd/sub-panel
```

## License

MIT
