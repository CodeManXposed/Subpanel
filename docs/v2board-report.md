# v2board 上报接入指南

## 1. Sub-Panel 配置

在 `config.yml` 的 `admin` 节下加一行：

```yaml
admin:
  report_secret: "你的密钥"   # 上报鉴权,留空则不校验
```

## 2. v2board 代码修改

在 `app/Http/Controllers/V1/Client/ClientController.php`（或 `app/Http/Controllers/Client/ClientController.php`）的订阅拉取方法中，`$serverService = new ServerService();` 之前加入：

```php
// ─── Sub-Panel 上报 ───
$subPanelUrl = 'https://你的面板地址/api/report/机场名';  // 机场名 = Sub-Panel 里的 tenant name
$subPanelKey = '你的report_secret';

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

## 3. 多机场部署

每个机场的 v2board 实例配不同的 URL 路径：

```
机场A: POST https://panel.example.com/api/report/airport-a
机场B: POST https://panel.example.com/api/report/airport-b
```

路径末尾的名称必须与 Sub-Panel「机场管理」里配置的机场名一致。

`report_secret` 全局共用一个即可。

## 4. 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| token | string | 用户订阅 token 原文（必填） |
| uuid | string | v2board 用户 UUID |
| email | string | 用户邮箱 |
| traffic_used | int | 已用流量 bytes（u + d） |
| traffic_total | int | 总流量 bytes |
| wallet_balance | int | 钱包余额（分） |
| commission_balance | int | 佣金余额（分） |
| user_created_at | string | 用户注册时间 |
| ip | string | 拉取时客户端 IP |
| user_agent | string | 拉取时 UA |
| site_domain | string | 请求来源域名 |

## 5. 嫌疑分析

Sub-Panel 面板「嫌疑用户」页会自动交叉分析：

- 事件日志中该 token 的拉取次数、独立 IP 数、独立 UA 数
- 上报的流量使用情况

红旗规则：
- 🚩 流量使用率 < 5% 且拉取 ≥ 10 次
- 🚩 流量为 0 且拉取 ≥ 5 次
- 🚩 独立 IP ≥ 5
- 🚩 独立 UA ≥ 3
