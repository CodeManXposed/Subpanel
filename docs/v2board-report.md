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

## 6. 嫌疑分析

Sub-Panel 面板「嫌疑用户」页会聚合每个 token 的行为指标，供运营自行研判：

- 事件日志中该 token 的拉取次数、独立 IP 数、独立 UA 数
- 上报的流量使用情况（已用 / 总量 / 使用率）

面板不做自动判定，提供多维排序由运营横向比对：
- 按独立 IP（默认，共享/倒卖最直观信号）
- 按独立 UA
- 按拉取次数
- 按使用率（低 → 高）

独立 IP 数与使用率仍带冷热色阶作视觉锚点（仅可视化，不下结论）。
