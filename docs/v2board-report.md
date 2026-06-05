# v2board 上报接入指南

## 1. Sub-Panel 配置

在面板「设置」页配置「上报密钥」即可，留空则不校验。

## 2. 获取上报地址

进入面板「机场管理」→ 点击目标机场的「接入代码」按钮。弹窗会显示：

- **上报 URL**：`http://你的域名/r/{report_id}`（挂在订阅网关 80 端口）
- **上报密钥**：面板设置页中配的 secret

每个机场有独立的随机 `report_id`，URL 不暴露机场名。

## 3. v2board 代码修改

文件位置：`app/Http/Controllers/V1/Client/ClientController.php`

在 `subscribe()` 方法内，`$userService->isAvailable($user)` 判定通过后、`$serverService = new ServerService();` **之前**插入（约第 22 行）：

```php
// ─── Sub-Panel 上报 ───
$subPanelUrl = 'http://你的域名/r/你的report_id';  // 从面板「接入代码」弹窗复制
$subPanelKey = '你的上报密钥';                       // 面板设置页配置

// 连接 IP：从设备数限制的在线 IP 缓存读（ALIVE_IP_USER_{用户id}）
// 结构：['节点type+id' => ['aliveips' => ['1.2.3.4_5', ...], 'lastupdateAt' => ts], 'alive_ip' => count]
$connectIps = [];
$aliveData = \Illuminate\Support\Facades\Cache::get('ALIVE_IP_USER_' . $user->id);
if (is_array($aliveData)) {
    foreach ($aliveData as $nodeKey => $nodeData) {
        if ($nodeKey === 'alive_ip' || !is_array($nodeData) || !isset($nodeData['aliveips'])) {
            continue; // 跳过统计字段 alive_ip 和无效节点
        }
        foreach ($nodeData['aliveips'] as $ipNodeId) {
            $ip = explode('_', $ipNodeId)[0]; // 元素是 "IP_节点ID"，取 IP 段
            if ($ip !== '') {
                $connectIps[$ip] = true; // 用 key 去重
            }
        }
    }
}
$connectIps = array_values(array_keys($connectIps));

$reportData = [
    'token'              => $user->token,
    'uuid'               => $user->uuid,
    'email'              => $user->email,
    'traffic_used'       => $user->u + $user->d,
    'traffic_total'      => $user->transfer_enable,
    'wallet_balance'     => $user->balance ?? 0,
    'commission_balance' => $user->commission_balance ?? 0,
    'user_created_at'    => (string)$user->created_at,
    'ip'                 => $request->header('cf-connecting-ip')
                            ?? explode(',', $request->header('x-forwarded-for', ''))[0]
                            ?? $request->ip(),
    'user_agent'         => $request->userAgent() ?? '',
    'site_domain'        => $request->getHost(),
    'connect_ips'        => $connectIps, // 节点侧实际连接 IP 列表（去重）
];

try {
    \Illuminate\Support\Facades\Http::timeout(3)
        ->withHeaders(['X-Report-Key' => $subPanelKey])
        ->post($subPanelUrl, $reportData);
} catch (\Exception $e) {
    // 静默失败,不影响订阅下发
}
// ─── Sub-Panel 上报结束 ───
```

## 4. 多机场部署

每个机场在面板里有独立的 `report_id`，各自从「接入代码」弹窗复制对应 URL 即可：

```
机场A: POST http://panel.example.com/r/a1b2c3d4...
机场B: POST http://panel.example.com/r/e5f6g7h8...
```

`上报密钥` 全局共用一个。

## 5. 字段说明

- token (string): 用户订阅 token 原文（必填）
- uuid (string): v2board 用户 UUID
- email (string): 用户邮箱
- traffic_used (int): 已用流量 bytes（u + d）
- traffic_total (int): 总流量 bytes
- wallet_balance (int): 钱包余额（分）
- commission_balance (int): 佣金余额（分）
- user_created_at (string): 用户注册时间
- ip (string): 拉取时客户端 IP
- user_agent (string): 拉取时 UA
- site_domain (string): 请求来源域名
- connect_ips (string[]): 节点侧实际连接 IP 列表（去重，来自 `ALIVE_IP_USER_{用户id}` 缓存）

> ⚠️ **connect_ips 时效**：该数据来自节点上报的在线 IP 缓存（TTL 120s）。订阅拉取的那一刻，若用户当前没有活跃连接（缓存为空或过期），`connect_ips` 会是空数组——这是正常的，连接IP表只在用户有活跃节点连接时才有数据。设备数限制功能需在节点侧开启上报，否则 `ALIVE_IP_USER_*` 缓存不存在。

## 6. 嫌疑分析

Sub-Panel 面板「嫌疑用户」页会自动交叉分析：

- 事件日志中该 token 的拉取次数、独立 IP 数、独立 UA 数
- 上报的流量使用情况

红旗规则：
- 🚩 流量使用率 < 5% 且拉取 ≥ 10 次
- 🚩 流量为 0 且拉取 ≥ 5 次
- 🚩 独立 IP ≥ 5
- 🚩 独立 UA ≥ 3
