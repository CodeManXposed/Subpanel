// sub-panel: Sub-Panel —— V2Board 订阅前置网关
//
// 用法:
//
//	sub-panel -c /opt/Sub-Panel/config.yml
//	sub-panel hashpwd <password>   # 生成 admin.password_hash 用
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/cloudip"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/dnswatch"
	"github.com/huabanmao168/SubPanel/internal/faker"
	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/proxy"
	"github.com/huabanmao168/SubPanel/internal/rules"
	"github.com/huabanmao168/SubPanel/internal/slidingwin"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
	"github.com/huabanmao168/SubPanel/internal/webui"
)

var Version = "0.1.89"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "hashpwd":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "usage: sub-panel hashpwd <password>")
				os.Exit(2)
			}
			h, err := bcrypt.GenerateFromPassword([]byte(os.Args[2]), bcrypt.DefaultCost)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			fmt.Println(string(h))
			return
		case "version":
			fmt.Println(Version)
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	var cfgPath string
	fs := flag.NewFlagSet("sub-panel", flag.ExitOnError)
	fs.StringVar(&cfgPath, "c", "/opt/Sub-Panel/config.yml", "配置文件路径")
	_ = fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("加载配置失败", "err", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepathDir(cfg.Storage.SQLitePath), 0750); err != nil {
		logger.Error("创建数据库目录失败", "err", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepathDir(cfg.HMACSaltFile), 0750); err != nil {
		logger.Error("创建 salt 目录失败", "err", err)
		os.Exit(1)
	}

	salt, err := token.LoadOrCreateSalt(cfg.HMACSaltFile)
	if err != nil {
		logger.Error("加载 HMAC salt 失败", "err", err)
		os.Exit(1)
	}
	hasher := token.NewHasher(salt)

	st, err := store.Open(cfg.Storage.SQLitePath, cfg.Storage.BatchFlushInterval.Std(), cfg.Storage.BatchFlushSize)
	if err != nil {
		logger.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	bans := banlist.New(st)
	if err := bans.LoadFromStore(context.Background()); err != nil {
		logger.Error("加载封禁列表失败", "err", err)
		os.Exit(1)
	}

	// tenants: 首次启动把 yaml 里的种子写入 DB,之后以 DB 为准
	if err := syncTenantsFromYAML(st, cfg, logger); err != nil {
		logger.Error("初始化机场配置失败", "err", err)
		os.Exit(1)
	}
	// 给老数据补 report_id
	if err := st.BackfillReportIDs(); err != nil {
		logger.Error("补 report_id 失败", "err", err)
		os.Exit(1)
	}
	if err := loadTenantsFromDB(st, cfg); err != nil {
		logger.Error("加载机场配置失败", "err", err)
		os.Exit(1)
	}

	det, err := detector.New(&cfg.Detector)
	if err != nil {
		logger.Error("检测器初始化失败", "err", err)
		os.Exit(1)
	}

	// 触发规则:首次启动用 yaml 种子写入 DB,之后 DB 为权威源,yaml 不再读
	if err := seedDetectRulesFromYAML(st, cfg, logger); err != nil {
		logger.Error("初始化触发规则失败", "err", err)
		os.Exit(1)
	}
	if err := ensureUncommonUARule(st); err != nil {
		logger.Error("初始化非常见 UA 规则失败", "err", err)
		os.Exit(1)
	}
	if err := ensureAbuseRateLimitRules(st); err != nil {
		logger.Error("初始化上游前限流规则失败", "err", err)
		os.Exit(1)
	}
	if rs, err := loadDetectRulesFromDB(st); err != nil {
		logger.Error("加载触发规则失败", "err", err)
		os.Exit(1)
	} else {
		det.SetRules(rs)
	}

	stopCh := make(chan struct{})
	slidingwin.RunGC(stopCh, time.Minute, det.GCTargets()...)

	// GeoIP xdb - 新版官方库提供地理/运营商,旧满载库还可提供用途类型等扩展字段
	geo := geoip.Global()
	if p := cfg.GeoIP.XDBPath; p != "" {
		if err := geo.Load(p); err != nil {
			logger.Warn("加载 GeoIP xdb 失败,from_cloud_ip / country / usage_type 规则将失效", "path", p, "err", err)
		} else {
			snap := geo.Snapshot()
			logger.Info("GeoIP xdb 已加载", "path", p, "version", snap.Version)
		}
	} else {
		logger.Info("未配置 geoip.xdb_path,GeoIP 功能禁用")
	}
	if p := cfg.GeoIP.ASNPath; p != "" {
		if err := geo.LoadASN(p); err != nil {
			logger.Warn("加载 ASN 数据库失败,ASN 与推断类型将为空", "path", p, "err", err)
		} else {
			snap := geo.Snapshot()
			logger.Info("ASN 数据库已加载", "path", p, "records", snap.ASNRecords)
		}
	}
	if n, err := st.BackfillEventNetworkInfo(context.Background(), func(ip string) (string, string, string) {
		info := geo.Lookup(ip)
		if info == nil {
			return "", "", ""
		}
		return info.ASN, info.ASNOrg, info.CloudProvider
	}); err != nil {
		logger.Warn("历史事件 ASN/云厂商信息回填失败", "err", err)
	} else if n > 0 {
		logger.Info("历史事件 ASN/云厂商信息回填完成", "events", n)
	}

	// 云 IP 匹配器 (底层走 GeoIP xdb,按 ISP 字段反推云厂商)
	cloudMatcher := cloudip.NewMatcher()
	cloudFetcher := cloudip.NewFetcher(cloudMatcher, st, logger)
	det.SetCloudLookup(cloudMatcher.Match)
	// 注入 GeoIP 查询(给 country/usage_type/isp 规则用)
	det.SetGeoLookup(func(ip string) *detector.GeoInfo {
		info := geo.Lookup(ip)
		if info == nil {
			return nil
		}
		return &detector.GeoInfo{
			Country:   info.Country,
			ISOCode:   info.ISOCode,
			ISP:       info.ISP,
			UsageType: info.UsageType,
		}
	})
	ctxFetch, cancelFetch := context.WithCancel(context.Background())
	cloudFetcher.RunPeriodic(ctxFetch, 7*24*time.Hour)
	dnswatch.New(st, logger, 30*time.Second).Run(ctxFetch)

	// 动态规则(IP 白名单)
	rulesMgr := rules.NewManager(st)
	if err := rulesMgr.Reload(); err != nil {
		logger.Error("加载动态规则失败", "err", err)
		os.Exit(1)
	}
	rulesMgr.RunDomainWhitelistResolver(ctxFetch, 30*time.Second)
	det.SetDynamicIPWhitelist(rulesMgr.IPWhitelisted)
	det.SetDynamicUAWhitelist(rulesMgr.UAWhitelisted)

	fk := faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount)

	gw, err := proxy.NewGateway(cfg, hasher, st, bans, det, fk, proxy.AutoBanCfg{}, logger)
	if err != nil {
		logger.Error("网关初始化失败", "err", err)
		os.Exit(1)
	}
	// 注入 GeoIP 查询(给请求日志写入地区、ASN 与云厂商画像)
	gw.SetGeoLookup(func(ip string) proxy.NetworkInfo {
		info := geo.Lookup(ip)
		if info == nil {
			return proxy.NetworkInfo{}
		}
		country := info.ISOCode
		if country == "" {
			country = info.Country
		}
		// ip2region 把港澳台 ISO 标为 CN,需要按中文名修正,
		// 否则「禁海外」规则无法拦截港澳台。
		if country == "CN" {
			switch {
			case strings.Contains(info.Country, "香港"):
				country = "HK"
			case strings.Contains(info.Country, "澳门"):
				country = "MO"
			case strings.Contains(info.Country, "台湾"):
				country = "TW"
			}
		}
		return proxy.NetworkInfo{
			Country:       country,
			UsageType:     info.UsageType,
			ISP:           info.ISP,
			ASN:           info.ASN,
			ASNOrg:        info.ASNOrg,
			CloudProvider: info.CloudProvider,
		}
	})
	gw.SetCloudLookup(cloudMatcher.Match)

	// 全局黑名单(海外/云/ISP/浏览器)
	bl := blacklist.New(st)
	gw.SetBlacklist(bl)
	// IP 白名单仅豁免“单 IP 多 Token”条件；其他检测与硬限流继续生效。
	gw.SetIPWhitelist(rulesMgr.IPWhitelisted)

	// 启动时恢复「一键透传」开关(store.meta 持久化)
	if v, _ := st.GetMeta("passthrough_all"); v == "true" {
		gw.SetPassthroughAll(true)
		logger.Warn("一键透传已开启 — 所有规则/黑白名单短路")
	}

	// admin server (先创建 ui,subMux 也要用它的 ReportHandler)
	ui := webui.NewServer(cfg, st, bans, hasher, cloudMatcher, cloudFetcher, rulesMgr, gw, det, bl, Version, logger)

	// 反代 server
	subMux := http.NewServeMux()
	subMux.HandleFunc("/healthz", proxy.Healthz)
	subMux.Handle("/r/", ui.ReportHandler()) // v2board 上报复用订阅网关入口
	subMux.Handle("/", gw)
	subSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           subMux,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	adminSrv := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           ui.Handler(),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("订阅网关监听中", "addr", cfg.Listen)
		if err := subSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("订阅网关启动失败", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Info("管理面监听中", "addr", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("管理面启动失败", "err", err)
			os.Exit(1)
		}
	}()

	// 定时 vacuum
	go runVacuum(stopCh, st, cfg, logger)

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("收到退出信号", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = subSrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
	cancelFetch()
	close(stopCh)
	time.Sleep(200 * time.Millisecond) // 让异步 writer flush
	logger.Info("已退出")
}

func runVacuum(stop <-chan struct{}, st *store.Store, cfg *config.Config, logger *slog.Logger) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := st.Vacuum(ctx, cfg.Storage.Retention.Events.Std(), cfg.Storage.Retention.Incidents.Std(),
				cfg.Storage.Retention.AWSIPChanges.Std())
			cancel()
			if err != nil {
				logger.Warn("数据清理失败", "err", err)
			}
		}
	}
}

func filepathDir(p string) string {
	// 极简版 filepath.Dir,避免引入额外包(其实 stdlib 已经有,这里用 stdlib)
	if p == "" {
		return "."
	}
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func printHelp() {
	fmt.Println(`Sub-Panel - V2Board 订阅前置网关

用法:
  sub-panel -c <config.yml>        启动服务(反代 + Web UI)
  sub-panel hashpwd <password>     生成 bcrypt 密码哈希(填到 admin.password_hash)
  sub-panel version                打印版本
  sub-panel help                   本帮助`)
}

// syncTenantsFromYAML: 首次启动(DB tenants 表为空)时把 cfg.Tenants 写入 DB 作为种子。
// 之后再启动,DB 已有数据就不动 yaml 里的内容。
func syncTenantsFromYAML(st *store.Store, cfg *config.Config, logger *slog.Logger) error {
	n, err := st.CountTenants()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	logger.Info("机场配置: 首次启动,把 yaml 种子写入数据库", "count", len(cfg.Tenants))
	for _, t := range cfg.Tenants {
		if err := st.UpsertTenant(store.TenantRow{
			Name:          t.Name,
			SubscribePath: t.SubscribePath,
			Upstream:      t.Upstream,
			UpstreamPath:  t.UpstreamPath,
			Enabled:       true,
		}); err != nil {
			return fmt.Errorf("写入机场 %s: %w", t.Name, err)
		}
	}
	return nil
}

// loadTenantsFromDB: 用 DB 里的(启用的)tenants 覆盖 cfg.Tenants,作为启动时的真实数据源。
func loadTenantsFromDB(st *store.Store, cfg *config.Config) error {
	rows, err := st.ListTenants()
	if err != nil {
		return err
	}
	out := make([]config.Tenant, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		out = append(out, config.Tenant{
			Name:          r.Name,
			SubscribePath: r.SubscribePath,
			Upstream:      r.Upstream,
			UpstreamPath:  r.UpstreamPath,
		})
	}
	cfg.Tenants = out
	return nil
}

// seedDetectRulesFromYAML 首次启动时把 yaml 里的 detector.rules 写入 DB,DB 不空就跳过。
func seedDetectRulesFromYAML(st *store.Store, cfg *config.Config, logger *slog.Logger) error {
	n, err := st.CountDetectRules()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if len(cfg.Detector.Rules) == 0 {
		logger.Info("触发规则: DB 为空且 yaml 无规则,跳过种子")
		return nil
	}
	logger.Info("触发规则: 首次启动,把 yaml 种子写入数据库", "count", len(cfg.Detector.Rules))
	for i, r := range cfg.Detector.Rules {
		buf, err := json.Marshal(r.When)
		if err != nil {
			return fmt.Errorf("规则 %s 序列化失败: %w", r.Name, err)
		}
		if err := st.UpsertDetectRule(store.DetectRuleRow{
			Name:      r.Name,
			Desc:      r.Desc,
			Action:    r.Action,
			WhenJSON:  string(buf),
			Enabled:   true,
			SortOrder: i,
		}); err != nil {
			return fmt.Errorf("写入规则 %s: %w", r.Name, err)
		}
	}
	return nil
}

// ensureUncommonUARule 为已有安装执行一次升级迁移。管理员之后即使删除该规则，
// 也不会在每次重启时被重新创建。
func ensureUncommonUARule(st *store.Store) error {
	const migrationKey = "migration_uncommon_ua_rule_v1"
	if done, _ := st.GetMeta(migrationKey); done == "1" {
		return nil
	}
	rows, err := st.ListDetectRules()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Name == "uncommon_ua" {
			return st.SetMeta(migrationKey, "1")
		}
	}
	whenJSON, err := json.Marshal(config.When{UncommonUA: true})
	if err != nil {
		return err
	}
	if err := st.UpsertDetectRule(store.DetectRuleRow{
		Name:      "uncommon_ua",
		Desc:      "请求 UA 未命中常规订阅客户端库且不在 UA 白名单时自动投毒",
		Action:    "fake",
		WhenJSON:  string(whenJSON),
		Enabled:   true,
		SortOrder: 45,
	}); err != nil {
		return err
	}
	return st.SetMeta(migrationKey, "1")
}

// ensureAbuseRateLimitRules 为已有安装补齐真正的“上游前”防刷规则。
// 迁移只执行一次；之后管理员可以在 UI 中自由修改动作、阈值或删除规则。
func ensureAbuseRateLimitRules(st *store.Store) error {
	const migrationKey = "migration_abuse_rate_limit_rules_v1"
	if done, _ := st.GetMeta(migrationKey); done == "1" {
		return nil
	}
	rows, err := st.ListDetectRules()
	if err != nil {
		return err
	}
	byName := make(map[string]store.DetectRuleRow, len(rows))
	for _, row := range rows {
		byName[row.Name] = row
	}
	defaults := []store.DetectRuleRow{
		{
			Name: "ip_freq_burst", Desc: "单 IP 60 秒内 >=20 次请求，直接 429 且不访问源站",
			Action: "rate_limit", WhenJSON: `{"IPFreq":{"Window":60000000000,"GTE":20}}`, Enabled: true, SortOrder: 20,
		},
		{
			Name: "ip_multi_token", Desc: "单 IP 10 分钟内 >=8 个不同 Token，直接 429 且不访问源站",
			Action: "rate_limit", WhenJSON: `{"IPDistinctTokens":{"Window":600000000000,"GTE":8}}`, Enabled: true, SortOrder: 30,
		},
	}
	for _, def := range defaults {
		if existing, ok := byName[def.Name]; ok {
			existing.Action = "rate_limit"
			// 保留管理员原有条件和启停状态，只升级处置语义。
			if err := st.UpsertDetectRule(existing); err != nil {
				return err
			}
			continue
		}
		if err := st.UpsertDetectRule(def); err != nil {
			return err
		}
	}
	return st.SetMeta(migrationKey, "1")
}

// loadDetectRulesFromDB 读 DB 里启用的规则,反序列化成 config.Rule slice。
func loadDetectRulesFromDB(st *store.Store) ([]config.Rule, error) {
	rows, err := st.ListDetectRules()
	if err != nil {
		return nil, err
	}
	out := make([]config.Rule, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		var when config.When
		if err := json.Unmarshal([]byte(r.WhenJSON), &when); err != nil {
			return nil, fmt.Errorf("规则 %s 反序列化失败: %w", r.Name, err)
		}
		out = append(out, config.Rule{
			Name:   r.Name,
			Desc:   r.Desc,
			Action: r.Action,
			When:   when,
		})
	}
	return out, nil
}
