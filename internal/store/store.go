// Package store 提供 SQLite 持久化:events / incidents / bans。
// 写入是异步的:外部调用 Submit*() 入 channel,后台 goroutine 批量落盘。
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    tenant      TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    ua          TEXT,
    token_hash  TEXT,
    flag        TEXT,
    path        TEXT,
    status      INTEGER,
    action      TEXT,
    rule_tags   TEXT,
    upstream_ms INTEGER,
    resp_size   INTEGER,
    country     TEXT,
    usage_type  TEXT,
    isp         TEXT,
    asn         TEXT,
    asn_org     TEXT,
    cloud_provider TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts          ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_token       ON events(token_hash, ts);
CREATE INDEX IF NOT EXISTS idx_events_ip          ON events(client_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_action_ts   ON events(action, ts);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts   ON events(tenant, ts);
-- GeoIP 索引在 ALTER 迁移之后再建(见 NewStore),否则老库会报 no such column

CREATE TABLE IF NOT EXISTS bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    target     TEXT NOT NULL,
    reason     TEXT,
    rule_tags  TEXT,
    created_ts INTEGER NOT NULL,
    expires_ts INTEGER,
    created_by TEXT,
    UNIQUE(kind, target)
);
CREATE INDEX IF NOT EXISTS idx_bans_target ON bans(kind, target);
CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_ts);

CREATE TABLE IF NOT EXISTS incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    tenant     TEXT,
    severity   TEXT,
    client_ip  TEXT,
    token_hash TEXT,
    rule_tags  TEXT,
    action     TEXT,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_ts ON incidents(severity, ts);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);

-- cloud_cidrs 表已废弃(v2 起改用 ip2region xdb),老库的 DROP 见 NewStore 迁移

CREATE TABLE IF NOT EXISTS ua_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,         -- 'blacklist' | 'whitelist'
    pattern    TEXT NOT NULL,         -- 正则(black) 或 前缀(white)
    note       TEXT,
    created_ts INTEGER NOT NULL,
    UNIQUE(kind, pattern)
);
CREATE INDEX IF NOT EXISTS idx_ua_kind ON ua_rules(kind);

CREATE TABLE IF NOT EXISTS ip_whitelist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL UNIQUE,  -- IP 或 CIDR
    note       TEXT,
    created_ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    name           TEXT PRIMARY KEY,
    host           TEXT NOT NULL,
    subscribe_path TEXT NOT NULL,
    upstream       TEXT NOT NULL,
    upstream_path  TEXT,
    report_id      TEXT NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_ts     INTEGER NOT NULL,
    updated_ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenants_host_path ON tenants(host, subscribe_path);

CREATE TABLE IF NOT EXISTS detect_rules (
    name       TEXT PRIMARY KEY,
    desc       TEXT,
    severity   TEXT NOT NULL,         -- yellow|orange|red
    when_json  TEXT NOT NULL,         -- 序列化的 config.When
    enabled    INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_ts INTEGER NOT NULL,
    updated_ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resolved_tokens (
    token       TEXT PRIMARY KEY,
    tenant      TEXT,
    note        TEXT,
    resolved_ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resolved_tenant_ts ON resolved_tokens(tenant, resolved_ts);
`

// Event 一行请求记录。
type Event struct {
	TS            time.Time
	Tenant        string
	ClientIP      string
	UA            string
	TokenHash     string
	Flag          string
	Path          string
	Status        int
	Action        string
	RuleTags      []string
	UpstreamMS    int64
	RespSize      int64
	Country       string // ISO2 (CN/US/...)
	UsageType     string // IDC/CDN/DYN/MOB/COM
	ISP           string // 电信/阿里/Cloudflare/...
	ASN           string // AS4134
	ASNOrg        string // ASN 注册组织
	CloudProvider string // aws/aliyun/cloudflare/...;空表示非已知云厂商
	ReTriggered   bool   // 曾标记已处理后又出现的新请求
}

// Incident 命中规则的事件。Severity/Action 字段已废弃,DB 列保留向后兼容,
// 写入时给空值,读取时不再展示。
type Incident struct {
	TS        time.Time
	Tenant    string
	Severity  string // 已废弃,固定为空
	ClientIP  string
	TokenHash string
	RuleTags  []string
	Action    string // 已废弃,固定为空
	Note      string
}

// Ban 封禁记录。
type Ban struct {
	ID        int64
	Kind      string // "ip" | "token"
	Target    string
	Reason    string
	RuleTags  []string
	CreatedTS time.Time
	ExpiresTS *time.Time
	CreatedBy string
}

type Store struct {
	db *sql.DB

	eventCh    chan Event
	incidentCh chan Incident
	flushSize  int
	flushEvery time.Duration

	wg     sync.WaitGroup
	stopCh chan struct{}
}

func Open(path string, flushEvery time.Duration, flushSize int) (*Store, error) {
	// 启用 WAL,journal_mode 必须在 connect 后设置一次
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	// modernc 不支持并行写,单 writer 串行化
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// 兼容老数据库:补 events 表 GeoIP 三列(已存在会报错,忽略)
	for _, alter := range []string{
		"ALTER TABLE events ADD COLUMN country TEXT",
		"ALTER TABLE events ADD COLUMN usage_type TEXT",
		"ALTER TABLE events ADD COLUMN isp TEXT",
		"ALTER TABLE events ADD COLUMN asn TEXT",
		"ALTER TABLE events ADD COLUMN asn_org TEXT",
		"ALTER TABLE events ADD COLUMN cloud_provider TEXT",
	} {
		_, _ = db.Exec(alter) // duplicate column 错误忽略
	}
	// 列就位后再建 GeoIP 索引
	for _, idx := range []string{
		"CREATE INDEX IF NOT EXISTS idx_events_country_ts ON events(country, ts)",
		"CREATE INDEX IF NOT EXISTS idx_events_usage_ts   ON events(usage_type, ts)",
		"CREATE INDEX IF NOT EXISTS idx_events_cloud_ts   ON events(cloud_provider, ts)",
		"CREATE INDEX IF NOT EXISTS idx_events_asn_ts     ON events(asn, ts)",
	} {
		if _, err := db.Exec(idx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("geoip index: %w", err)
		}
	}
	// 清理 v1 残留:cloud_cidrs 表(已被 xdb 替代)
	_, _ = db.Exec("DROP TABLE IF EXISTS cloud_cidrs")
	// 补 tenants.report_id 列(老库升级)
	_, _ = db.Exec("ALTER TABLE tenants ADD COLUMN report_id TEXT NOT NULL DEFAULT ''")
	// user_reports 表(v2board 上报)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS user_reports (
		token             TEXT NOT NULL,
		tenant            TEXT NOT NULL,
		uuid              TEXT,
		email             TEXT,
		traffic_used      INTEGER NOT NULL DEFAULT 0,
		traffic_total     INTEGER NOT NULL DEFAULT 0,
		wallet_balance    INTEGER NOT NULL DEFAULT 0,
		commission_balance INTEGER NOT NULL DEFAULT 0,
		user_created_at   TEXT,
		last_ip           TEXT,
		last_ua           TEXT,
		site_domain       TEXT,
		report_count      INTEGER NOT NULL DEFAULT 0,
		first_seen        INTEGER NOT NULL,
		last_seen         INTEGER NOT NULL,
		PRIMARY KEY(token, tenant)
	)`)
	// 新增列(兼容旧库)
	_, _ = db.Exec(`ALTER TABLE user_reports ADD COLUMN connect_ips TEXT DEFAULT ''`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_user_reports_tenant ON user_reports(tenant, last_seen)`)
	s := &Store{
		db:         db,
		eventCh:    make(chan Event, 1024),
		incidentCh: make(chan Incident, 256),
		flushSize:  flushSize,
		flushEvery: flushEvery,
		stopCh:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

func (s *Store) Close() error {
	close(s.stopCh)
	s.wg.Wait()
	return s.db.Close()
}

// ----- 异步入队 -----

func (s *Store) SubmitEvent(e Event) {
	select {
	case s.eventCh <- e:
	default:
		// channel 满了直接丢,避免阻塞主路径。
	}
}

func (s *Store) SubmitIncident(in Incident) {
	select {
	case s.incidentCh <- in:
	default:
	}
}

// ----- 后台写 -----

func (s *Store) writer() {
	defer s.wg.Done()
	t := time.NewTicker(s.flushEvery)
	defer t.Stop()
	var (
		events    []Event
		incidents []Incident
	)
	flush := func() {
		if len(events) > 0 {
			if err := s.insertEvents(events); err != nil {
				// 不让一次失败导致丢全量,这里只能丢日志
				fmt.Printf("store: insert events failed: %v\n", err)
			}
			events = events[:0]
		}
		if len(incidents) > 0 {
			if err := s.insertIncidents(incidents); err != nil {
				fmt.Printf("store: insert incidents failed: %v\n", err)
			}
			incidents = incidents[:0]
		}
	}
	for {
		select {
		case e := <-s.eventCh:
			events = append(events, e)
			if len(events) >= s.flushSize {
				flush()
			}
		case in := <-s.incidentCh:
			incidents = append(incidents, in)
			if len(incidents) >= s.flushSize {
				flush()
			}
		case <-t.C:
			flush()
		case <-s.stopCh:
			// 排空再退出
			for {
				select {
				case e := <-s.eventCh:
					events = append(events, e)
				case in := <-s.incidentCh:
					incidents = append(incidents, in)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Store) insertEvents(es []Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO events
		(ts,tenant,client_ip,ua,token_hash,flag,path,status,action,rule_tags,upstream_ms,resp_size,country,usage_type,isp,asn,asn_org,cloud_provider)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range es {
		tags, _ := json.Marshal(e.RuleTags)
		if _, err := stmt.Exec(
			e.TS.UnixMilli(), e.Tenant, e.ClientIP, e.UA, e.TokenHash, e.Flag,
			e.Path, e.Status, e.Action, string(tags), e.UpstreamMS, e.RespSize,
			e.Country, e.UsageType, e.ISP, e.ASN, e.ASNOrg, e.CloudProvider,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) insertIncidents(ins []Incident) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO incidents
        (ts,tenant,severity,client_ip,token_hash,rule_tags,action,note)
        VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, in := range ins {
		tags, _ := json.Marshal(in.RuleTags)
		if _, err := stmt.Exec(
			in.TS.UnixMilli(), in.Tenant, in.Severity, in.ClientIP, in.TokenHash,
			string(tags), in.Action, in.Note,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ----- bans 同步 API -----

func (s *Store) AddBan(b Ban) error {
	if b.Kind != "ip" && b.Kind != "token" {
		return errors.New("封禁类型必须是 ip 或 token")
	}
	tags, _ := json.Marshal(b.RuleTags)
	var exp interface{}
	if b.ExpiresTS != nil {
		exp = b.ExpiresTS.UnixMilli()
	}
	_, err := s.db.Exec(`INSERT INTO bans (kind,target,reason,rule_tags,created_ts,expires_ts,created_by)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(kind,target) DO UPDATE SET
		  reason=excluded.reason,
		  rule_tags=excluded.rule_tags,
		  created_ts=excluded.created_ts,
		  expires_ts=excluded.expires_ts,
		  created_by=excluded.created_by`,
		b.Kind, b.Target, b.Reason, string(tags), b.CreatedTS.UnixMilli(), exp, b.CreatedBy)
	return err
}

func (s *Store) RemoveBan(kind, target string) error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE kind=? AND target=?`, kind, target)
	return err
}

func (s *Store) ListActiveBans(ctx context.Context) ([]Ban, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,kind,target,reason,rule_tags,created_ts,expires_ts,created_by
		 FROM bans
		 WHERE expires_ts IS NULL OR expires_ts > ?
		 ORDER BY created_ts DESC`, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var tags sql.NullString
		var exp sql.NullInt64
		var reason, createdBy sql.NullString
		var createdMs int64
		if err := rows.Scan(&b.ID, &b.Kind, &b.Target, &reason, &tags, &createdMs, &exp, &createdBy); err != nil {
			return nil, err
		}
		b.CreatedTS = time.UnixMilli(createdMs)
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &b.RuleTags)
		}
		if exp.Valid {
			t := time.UnixMilli(exp.Int64)
			b.ExpiresTS = &t
		}
		b.Reason = reason.String
		b.CreatedBy = createdBy.String
		out = append(out, b)
	}
	return out, rows.Err()
}

// ----- 查询 API(给 Web UI) -----

type EventFilter struct {
	Tenant    string
	ClientIP  string
	TokenHash string
	Action    string
	Usage     string // usage_type 精确匹配(IDC/CDN/DYN/MOB/...)
	Cloud     string // "yes"=云厂商,"no"=非云厂商
	Provider  string // cloud_provider 精确匹配
	ASN       string // ASN 精确匹配,如 AS16509
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
	// IncludeResolved 为 true 时不过滤已处理 token;默认 false。
	// 单 token 精确过滤(TokenHash != "")时会自动忽略此开关——
	// 用户显式查某个 token 就该看到完整记录。
	IncludeResolved bool
}

func (s *Store) QueryEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	q := `SELECT ts,tenant,client_ip,ua,token_hash,flag,path,status,action,rule_tags,upstream_ms,resp_size,
			COALESCE(country,''),COALESCE(usage_type,''),COALESCE(isp,''),COALESCE(asn,''),COALESCE(asn_org,''),COALESCE(cloud_provider,''),
			CASE WHEN EXISTS (SELECT 1 FROM resolved_tokens rt
				WHERE rt.token=events.token_hash AND (rt.tenant='' OR rt.tenant=events.tenant)
				AND events.ts>rt.resolved_ts) THEN 1 ELSE 0 END
			FROM events WHERE 1=1`
	args := []any{}
	if f.Tenant != "" {
		q += " AND tenant=?"
		args = append(args, f.Tenant)
	}
	if f.ClientIP != "" {
		q += " AND client_ip=?"
		args = append(args, f.ClientIP)
	}
	if f.TokenHash != "" {
		q += " AND token_hash=?"
		args = append(args, f.TokenHash)
	}
	if f.Action != "" {
		q += " AND action=?"
		args = append(args, f.Action)
	}
	if f.Usage != "" {
		q += " AND usage_type=?"
		args = append(args, f.Usage)
	}
	if f.Cloud == "yes" {
		q += " AND COALESCE(cloud_provider,'')<>''"
	} else if f.Cloud == "no" {
		q += " AND COALESCE(cloud_provider,'')=''"
	}
	if f.Provider != "" {
		q += " AND LOWER(cloud_provider)=LOWER(?)"
		args = append(args, f.Provider)
	}
	if f.ASN != "" {
		q += " AND UPPER(asn)=UPPER(?)"
		args = append(args, f.ASN)
	}
	if !f.Since.IsZero() {
		q += " AND ts>=?"
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		q += " AND ts<=?"
		args = append(args, f.Until.UnixMilli())
	}
	// 默认隐藏“已处理时间点之前”的记录；同 token 后续再次出现会重新展示并标记。
	// 单 token 精确查询时不过滤，方便查看完整时间线。
	if !f.IncludeResolved && f.TokenHash == "" {
		q += ` AND NOT EXISTS (SELECT 1 FROM resolved_tokens rt
			WHERE rt.token=events.token_hash AND (rt.tenant='' OR rt.tenant=events.tenant)
			AND events.ts<=rt.resolved_ts)`
	}
	q += " ORDER BY ts DESC"
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var tags sql.NullString
		var ua, tokenHash, flag, path, action sql.NullString
		var reTriggered int
		if err := rows.Scan(&ts, &e.Tenant, &e.ClientIP, &ua, &tokenHash, &flag,
			&path, &e.Status, &action, &tags, &e.UpstreamMS, &e.RespSize,
			&e.Country, &e.UsageType, &e.ISP, &e.ASN, &e.ASNOrg, &e.CloudProvider, &reTriggered); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ts)
		e.UA = ua.String
		e.TokenHash = tokenHash.String
		e.Flag = flag.String
		e.Path = path.String
		e.Action = action.String
		e.ReTriggered = reTriggered != 0
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &e.RuleTags)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// BackfillEventNetworkInfo 为升级前的事件补齐 ASN 与云厂商信息。
// lookup 只按 distinct IP 调用一次，避免对每条历史事件重复查询数据库。
func (s *Store) BackfillEventNetworkInfo(ctx context.Context, lookup func(ip string) (asn, asnOrg, provider string)) (int, error) {
	if lookup == nil {
		return 0, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT client_ip FROM events
		WHERE client_ip<>'' AND (COALESCE(asn,'')='' OR COALESCE(cloud_provider,'')='')`)
	if err != nil {
		return 0, err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ips = append(ips, ip)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	stmt, err := tx.PrepareContext(ctx, `UPDATE events
		SET asn=?, asn_org=?, cloud_provider=? WHERE client_ip=?`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	updated := 0
	for _, ip := range ips {
		asn, asnOrg, provider := lookup(ip)
		res, err := stmt.ExecContext(ctx, asn, asnOrg, provider, ip)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			updated += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

type IncidentFilter struct {
	Tenant    string
	Severity  string
	IP        string
	TokenHash string
	Action    string
	Tag       string // 命中规则标签子串
	Keyword   string // 在 note 里模糊搜
	Since     time.Time
	Limit     int
	Offset    int
}

func (s *Store) QueryIncidents(ctx context.Context, f IncidentFilter) ([]Incident, error) {
	q := `SELECT ts,tenant,severity,client_ip,token_hash,rule_tags,action,note FROM incidents WHERE 1=1`
	args := []any{}
	if f.Tenant != "" {
		q += " AND tenant=?"
		args = append(args, f.Tenant)
	}
	if f.Severity != "" {
		q += " AND severity=?"
		args = append(args, f.Severity)
	}
	if f.IP != "" {
		q += " AND client_ip=?"
		args = append(args, f.IP)
	}
	if f.TokenHash != "" {
		q += " AND token_hash=?"
		args = append(args, f.TokenHash)
	}
	if f.Action != "" {
		q += " AND action=?"
		args = append(args, f.Action)
	}
	if f.Tag != "" {
		q += " AND rule_tags LIKE ?"
		args = append(args, "%"+f.Tag+"%")
	}
	if f.Keyword != "" {
		q += " AND note LIKE ?"
		args = append(args, "%"+f.Keyword+"%")
	}
	if !f.Since.IsZero() {
		q += " AND ts>=?"
		args = append(args, f.Since.UnixMilli())
	}
	q += " ORDER BY ts DESC"
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var ts int64
		var tags, tenant, severity, clientIP, tokenHash, action, note sql.NullString
		if err := rows.Scan(&ts, &tenant, &severity, &clientIP, &tokenHash, &tags, &action, &note); err != nil {
			return nil, err
		}
		in.TS = time.UnixMilli(ts)
		in.Tenant = tenant.String
		in.Severity = severity.String
		in.ClientIP = clientIP.String
		in.TokenHash = tokenHash.String
		in.Action = action.String
		in.Note = note.String
		if tags.Valid {
			_ = json.Unmarshal([]byte(tags.String), &in.RuleTags)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// IncidentIPAgg 异常事件按 IP 聚合的一行。
type IncidentIPAgg struct {
	ClientIP string   `json:"client_ip"`
	Count    int64    `json:"count"`
	LastTS   int64    `json:"last_ts"` // ms
	Actions  []string `json:"actions"`
	Tags     []string `json:"tags"`
}

// AggIncidentsByIP 按 IP 聚合,返回触发次数最高的 N 个 IP。
// 复用 IncidentFilter 的 Since/Tenant/Severity/Action/Tag/Keyword 字段。
func (s *Store) AggIncidentsByIP(ctx context.Context, f IncidentFilter) ([]IncidentIPAgg, error) {
	q := `SELECT client_ip, COUNT(*) c, MAX(ts) last_ts,
	             GROUP_CONCAT(DISTINCT action) acts,
	             GROUP_CONCAT(rule_tags, '|') tags
	      FROM incidents WHERE 1=1`
	args := []any{}
	if f.Tenant != "" {
		q += " AND tenant=?"
		args = append(args, f.Tenant)
	}
	if f.Severity != "" {
		q += " AND severity=?"
		args = append(args, f.Severity)
	}
	if f.Action != "" {
		q += " AND action=?"
		args = append(args, f.Action)
	}
	if f.Tag != "" {
		q += " AND rule_tags LIKE ?"
		args = append(args, "%"+f.Tag+"%")
	}
	if f.Keyword != "" {
		q += " AND note LIKE ?"
		args = append(args, "%"+f.Keyword+"%")
	}
	if !f.Since.IsZero() {
		q += " AND ts>=?"
		args = append(args, f.Since.UnixMilli())
	}
	q += " AND client_ip != '' GROUP BY client_ip ORDER BY c DESC"
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 20
	}
	q += " LIMIT ?"
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentIPAgg
	for rows.Next() {
		var a IncidentIPAgg
		var actsStr, tagsStr sql.NullString
		if err := rows.Scan(&a.ClientIP, &a.Count, &a.LastTS, &actsStr, &tagsStr); err != nil {
			return nil, err
		}
		if actsStr.Valid {
			for _, x := range strings.Split(actsStr.String, ",") {
				if x != "" {
					a.Actions = append(a.Actions, x)
				}
			}
		}
		if tagsStr.Valid {
			tagSet := map[string]bool{}
			for _, chunk := range strings.Split(tagsStr.String, "|") {
				var arr []string
				if json.Unmarshal([]byte(chunk), &arr) == nil {
					for _, t := range arr {
						tagSet[t] = true
					}
				}
			}
			for t := range tagSet {
				a.Tags = append(a.Tags, t)
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Stats 概要统计(过去 window 内)
type Stats struct {
	TotalEvents     int64            `json:"total_events"`
	PassCount       int64            `json:"pass"`
	SlowCount       int64            `json:"slow"`
	FakeCount       int64            `json:"fake"`
	DenyCount       int64            `json:"deny"`
	UniqueIPs       int64            `json:"unique_ips"`
	UniqueTokens    int64            `json:"unique_tokens"`
	TopIPs          []KeyCount       `json:"top_ips"`
	TopTokens       []KeyCount       `json:"top_tokens"`
	IncidentByLevel map[string]int64 `json:"incident_by_level"`
}

type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
	// Tenant 仅用于 TopTokens，避免不同站点相同 token 被合并。
	Tenant string `json:"tenant,omitempty"`
	// 仅用于 Top IPs 富化:在 Summary() 中由 webui 层填,store 本身留空。
	Region string `json:"region,omitempty"`
	ISP    string `json:"isp,omitempty"`
}

func (s *Store) Summary(ctx context.Context, tenant string, since time.Time) (*Stats, error) {
	out := &Stats{IncidentByLevel: map[string]int64{}}
	args := []any{since.UnixMilli()}
	tenantClause := ""
	if tenant != "" {
		tenantClause = " AND tenant=?"
		args = append(args, tenant)
	}
	// 总数
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM events WHERE ts>=?"+tenantClause, args...).Scan(&out.TotalEvents); err != nil {
		return nil, err
	}
	// 按 action 拆
	rows, err := s.db.QueryContext(ctx,
		"SELECT action,COUNT(*) FROM events WHERE ts>=?"+tenantClause+" GROUP BY action", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a string
		var n int64
		if err := rows.Scan(&a, &n); err != nil {
			rows.Close()
			return nil, err
		}
		switch a {
		case "pass":
			out.PassCount = n
		case "slow":
			out.SlowCount = n
		case "fake":
			out.FakeCount = n
		case "deny":
			out.DenyCount = n
		}
	}
	rows.Close()
	// unique
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT client_ip) FROM events WHERE ts>=?"+tenantClause, args...).Scan(&out.UniqueIPs); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT token_hash) FROM events WHERE ts>=? AND token_hash<>''"+tenantClause, args...).Scan(&out.UniqueTokens); err != nil {
		return nil, err
	}
	// top ips
	rows, err = s.db.QueryContext(ctx,
		"SELECT client_ip,COUNT(*) c FROM events WHERE ts>=?"+tenantClause+
			" GROUP BY client_ip ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k KeyCount
		if err := rows.Scan(&k.Key, &k.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopIPs = append(out.TopIPs, k)
	}
	rows.Close()
	// top tokens
	rows, err = s.db.QueryContext(ctx,
		"SELECT tenant,token_hash,COUNT(*) c FROM events WHERE ts>=? AND token_hash<>''"+tenantClause+
			" GROUP BY tenant,token_hash ORDER BY c DESC LIMIT 10", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k KeyCount
		if err := rows.Scan(&k.Tenant, &k.Key, &k.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopTokens = append(out.TopTokens, k)
	}
	rows.Close()
	// incident by level
	rows, err = s.db.QueryContext(ctx,
		"SELECT severity,COUNT(*) FROM incidents WHERE ts>=?"+tenantClause+" GROUP BY severity", args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.IncidentByLevel[sev] = n
	}
	rows.Close()
	return out, nil
}

// Retention 清理
func (s *Store) Vacuum(ctx context.Context, eventsRetention, incidentsRetention time.Duration) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM events WHERE ts<?", now.Add(-eventsRetention).UnixMilli()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM incidents WHERE ts<?", now.Add(-incidentsRetention).UnixMilli()); err != nil {
		return err
	}
	// 只删过期超过 7 天的 bans,保留近期作为审计
	cutoff := now.Add(-7 * 24 * time.Hour).UnixMilli()
	if _, err := s.db.ExecContext(ctx,
		"DELETE FROM bans WHERE expires_ts IS NOT NULL AND expires_ts<?", cutoff); err != nil {
		return err
	}
	return nil
}

// ----- resolved_tokens(已处理 token) -----

type ResolvedToken struct {
	Token      string `json:"token"`
	Tenant     string `json:"tenant"`
	Note       string `json:"note"`
	ResolvedTS int64  `json:"resolved_ts"` // 毫秒
}

// AddResolvedToken 标记 token 为已处理。tenant 可空(跨租户)。
func (s *Store) AddResolvedToken(ctx context.Context, token, tenant, note string) error {
	if token == "" {
		return fmt.Errorf("token is empty")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO resolved_tokens (token, tenant, note, resolved_ts) VALUES (?,?,?,?)
		 ON CONFLICT(token) DO UPDATE SET tenant=excluded.tenant, note=excluded.note, resolved_ts=excluded.resolved_ts`,
		token, tenant, note, time.Now().UnixMilli())
	return err
}

// RemoveResolvedToken 取消已处理标记。
func (s *Store) RemoveResolvedToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM resolved_tokens WHERE token=?", token)
	return err
}

// ListResolvedTokens 列出已处理 token。tenant 空=全部。
func (s *Store) ListResolvedTokens(ctx context.Context, tenant string) ([]ResolvedToken, error) {
	q := "SELECT token, COALESCE(tenant,''), COALESCE(note,''), resolved_ts FROM resolved_tokens"
	var args []any
	if tenant != "" {
		q += " WHERE tenant=? OR tenant=''"
		args = append(args, tenant)
	}
	q += " ORDER BY resolved_ts DESC LIMIT 500"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResolvedToken
	for rows.Next() {
		var r ResolvedToken
		if err := rows.Scan(&r.Token, &r.Tenant, &r.Note, &r.ResolvedTS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeEvents 清空请求事件 + 异常事件。tenant 为空=全部租户;否则只清该租户。
// 返回 (events_deleted, incidents_deleted, err)。
func (s *Store) PurgeEvents(ctx context.Context, tenant string) (int64, int64, error) {
	var evArgs, inArgs, urArgs []any
	evQ := "DELETE FROM events"
	inQ := "DELETE FROM incidents"
	urQ := "DELETE FROM user_reports"
	if tenant != "" {
		evQ += " WHERE tenant=?"
		inQ += " WHERE tenant=?"
		urQ += " WHERE tenant=?"
		evArgs = append(evArgs, tenant)
		inArgs = append(inArgs, tenant)
		urArgs = append(urArgs, tenant)
	}
	evRes, err := s.db.ExecContext(ctx, evQ, evArgs...)
	if err != nil {
		return 0, 0, err
	}
	inRes, err := s.db.ExecContext(ctx, inQ, inArgs...)
	if err != nil {
		return 0, 0, err
	}
	// 同步清除上报数据
	_, _ = s.db.ExecContext(ctx, urQ, urArgs...)
	evN, _ := evRes.RowsAffected()
	inN, _ := inRes.RowsAffected()

	// 强制 WAL 合并回主库,再释放磁盘空间
	_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	_, _ = s.db.ExecContext(ctx, "VACUUM")

	return evN, inN, nil
}

// ----- meta key/value -----

// SetMeta upsert.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		key, value)
	return err
}

// GetMeta 不存在返回 ("", nil)
func (s *Store) GetMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) DeleteMeta(key string) error {
	_, err := s.db.Exec(`DELETE FROM meta WHERE k=?`, key)
	return err
}

// AllMeta 一次返回所有 k/v
func (s *Store) AllMeta() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT k,v FROM meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ----- cloud_cidrs (已废弃) -----
//
// v2 起改用 ip2region xdb 做云 IP 判定,cloud_cidrs 表与相关 store 方法已删除。
// 老库的表 + 数据会在 NewStore 启动时自动 DROP(见 schema 后的迁移)。

// ----- ua_rules -----

type UARule struct {
	ID        int64
	Kind      string // blacklist|whitelist
	Pattern   string
	Note      string
	CreatedTS time.Time
}

func (s *Store) AddUARule(r UARule) error {
	if r.Kind != "blacklist" && r.Kind != "whitelist" {
		return errors.New("规则类型必须是 blacklist 或 whitelist")
	}
	_, err := s.db.Exec(
		`INSERT INTO ua_rules (kind,pattern,note,created_ts) VALUES (?,?,?,?)
		 ON CONFLICT(kind,pattern) DO UPDATE SET note=excluded.note`,
		r.Kind, r.Pattern, r.Note, time.Now().UnixMilli())
	return err
}

func (s *Store) DeleteUARule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ua_rules WHERE id=?`, id)
	return err
}

func (s *Store) ListUARules(kind string) ([]UARule, error) {
	q := `SELECT id,kind,pattern,COALESCE(note,''),created_ts FROM ua_rules`
	args := []any{}
	if kind != "" {
		q += ` WHERE kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UARule
	for rows.Next() {
		var r UARule
		var ts int64
		if err := rows.Scan(&r.ID, &r.Kind, &r.Pattern, &r.Note, &ts); err != nil {
			return nil, err
		}
		r.CreatedTS = time.UnixMilli(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----- ip_whitelist -----

type IPWhitelistEntry struct {
	ID        int64
	Target    string // IP 或 CIDR
	Note      string
	CreatedTS time.Time
}

func (s *Store) AddIPWhitelist(target, note string) error {
	_, err := s.db.Exec(
		`INSERT INTO ip_whitelist (target,note,created_ts) VALUES (?,?,?)
		 ON CONFLICT(target) DO UPDATE SET note=excluded.note`,
		target, note, time.Now().UnixMilli())
	return err
}

func (s *Store) DeleteIPWhitelist(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ip_whitelist WHERE id=?`, id)
	return err
}

// UpdateIPWhitelist 改 target 或 note。target 冲突会返回 UNIQUE 错。
func (s *Store) UpdateIPWhitelist(id int64, target, note string) error {
	_, err := s.db.Exec(
		`UPDATE ip_whitelist SET target=?, note=? WHERE id=?`,
		target, note, id)
	return err
}

func (s *Store) ListIPWhitelist() ([]IPWhitelistEntry, error) {
	rows, err := s.db.Query(
		`SELECT id,target,COALESCE(note,''),created_ts FROM ip_whitelist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPWhitelistEntry
	for rows.Next() {
		var e IPWhitelistEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Target, &e.Note, &ts); err != nil {
			return nil, err
		}
		e.CreatedTS = time.UnixMilli(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ----- tenants -----

// TenantRow DB 里的一行,UpstreamPath 可空,Enabled 软删/禁用用。
type TenantRow struct {
	Name          string
	Host          string
	SubscribePath string
	Upstream      string
	UpstreamPath  string
	ReportID      string
	Enabled       bool
	CreatedTS     time.Time
	UpdatedTS     time.Time
}

// UpsertTenant 插入或按 name 更新。
func (s *Store) UpsertTenant(t TenantRow) error {
	now := time.Now().UnixMilli()
	created := t.CreatedTS.UnixMilli()
	if created == 0 {
		created = now
	}
	enabled := 0
	if t.Enabled {
		enabled = 1
	}
	// 自动生成 report_id(16 字节 hex = 32 字符）
	if t.ReportID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		t.ReportID = hex.EncodeToString(b)
	}
	_, err := s.db.Exec(
		`INSERT INTO tenants (name,host,subscribe_path,upstream,upstream_path,report_id,enabled,created_ts,updated_ts)
		 VALUES (?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET
		   host=excluded.host,
		   subscribe_path=excluded.subscribe_path,
		   upstream=excluded.upstream,
		   upstream_path=excluded.upstream_path,
		   report_id=CASE WHEN tenants.report_id='' THEN excluded.report_id ELSE tenants.report_id END,
		   enabled=excluded.enabled,
		   updated_ts=excluded.updated_ts`,
		t.Name, t.Host, t.SubscribePath, t.Upstream, t.UpstreamPath, t.ReportID, enabled, created, now)
	return err
}

// DeleteTenant 按 name 删除。
func (s *Store) DeleteTenant(name string) error {
	_, err := s.db.Exec(`DELETE FROM tenants WHERE name=?`, name)
	return err
}

// ListTenants 全量返回(含禁用)。
func (s *Store) ListTenants() ([]TenantRow, error) {
	rows, err := s.db.Query(
		`SELECT name,host,subscribe_path,upstream,COALESCE(upstream_path,''),COALESCE(report_id,''),enabled,created_ts,updated_ts
		 FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantRow
	for rows.Next() {
		var t TenantRow
		var cts, uts int64
		var en int
		if err := rows.Scan(&t.Name, &t.Host, &t.SubscribePath, &t.Upstream, &t.UpstreamPath, &t.ReportID, &en, &cts, &uts); err != nil {
			return nil, err
		}
		t.Enabled = en != 0
		t.CreatedTS = time.UnixMilli(cts)
		t.UpdatedTS = time.UnixMilli(uts)
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTenantByReportID 通过 report_id 查找机场(上报接口用)。
func (s *Store) GetTenantByReportID(reportID string) (TenantRow, error) {
	var t TenantRow
	var cts, uts int64
	var en int
	err := s.db.QueryRow(
		`SELECT name,host,subscribe_path,upstream,COALESCE(upstream_path,''),report_id,enabled,created_ts,updated_ts
		 FROM tenants WHERE report_id=?`, reportID).
		Scan(&t.Name, &t.Host, &t.SubscribePath, &t.Upstream, &t.UpstreamPath, &t.ReportID, &en, &cts, &uts)
	if err != nil {
		return t, err
	}
	t.Enabled = en != 0
	t.CreatedTS = time.UnixMilli(cts)
	t.UpdatedTS = time.UnixMilli(uts)
	return t, nil
}

// CountTenants 用于判断是否已迁移过 yaml 种子。
func (s *Store) CountTenants() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&n)
	return n, err
}

// BackfillReportIDs 给所有 report_id 为空的 tenant 补随机 ID。
func (s *Store) BackfillReportIDs() error {
	rows, err := s.db.Query(`SELECT name FROM tenants WHERE report_id='' OR report_id IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		names = append(names, n)
	}
	for _, name := range names {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		if _, err := s.db.Exec(`UPDATE tenants SET report_id=? WHERE name=?`, id, name); err != nil {
			return err
		}
	}
	return nil
}

// ----- detect_rules -----

// DetectRuleRow:DB 里的一条规则。WhenJSON 存的是 config.When 的 JSON 序列化。
type DetectRuleRow struct {
	Name      string
	Desc      string
	Severity  string
	WhenJSON  string
	Enabled   bool
	SortOrder int
	UpdatedTS time.Time
}

func (s *Store) UpsertDetectRule(r DetectRuleRow) error {
	now := time.Now().Unix()
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO detect_rules (name,desc,severity,when_json,enabled,sort_order,created_ts,updated_ts)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET desc=excluded.desc, severity=excluded.severity,
		   when_json=excluded.when_json, enabled=excluded.enabled, sort_order=excluded.sort_order,
		   updated_ts=excluded.updated_ts`,
		r.Name, r.Desc, r.Severity, r.WhenJSON, enabled, r.SortOrder, now, now)
	return err
}

func (s *Store) DeleteDetectRule(name string) error {
	_, err := s.db.Exec(`DELETE FROM detect_rules WHERE name=?`, name)
	return err
}

func (s *Store) ListDetectRules() ([]DetectRuleRow, error) {
	rows, err := s.db.Query(
		`SELECT name, COALESCE(desc,''), severity, when_json, enabled, sort_order, updated_ts
		 FROM detect_rules ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetectRuleRow
	for rows.Next() {
		var r DetectRuleRow
		var en int
		var uts int64
		if err := rows.Scan(&r.Name, &r.Desc, &r.Severity, &r.WhenJSON, &en, &r.SortOrder, &uts); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.UpdatedTS = time.Unix(uts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountDetectRules() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM detect_rules`).Scan(&n)
	return n, err
}

// ════════════════════════════════════════════════════════
// user_reports: v2board 上报的用户流量/身份信息
// ════════════════════════════════════════════════════════

type UserReport struct {
	Token             string `json:"token"`
	Tenant            string `json:"tenant"`
	UUID              string `json:"uuid"`
	Email             string `json:"email"`
	TrafficUsed       int64  `json:"traffic_used"`
	TrafficTotal      int64  `json:"traffic_total"`
	WalletBalance     int64  `json:"wallet_balance"`
	CommissionBalance int64  `json:"commission_balance"`
	UserCreatedAt     string `json:"user_created_at"`
	LastIP            string `json:"last_ip"`
	LastUA            string `json:"last_ua"`
	SiteDomain        string `json:"site_domain"`
	ReportCount       int64  `json:"report_count"`
	FirstSeen         int64  `json:"first_seen"`
	LastSeen          int64  `json:"last_seen"`
}

func (s *Store) UpsertUserReport(r UserReport) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO user_reports (token, tenant, uuid, email, traffic_used, traffic_total,
			wallet_balance, commission_balance, user_created_at, last_ip, last_ua, site_domain,
			report_count, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(token, tenant) DO UPDATE SET
			uuid=excluded.uuid, email=excluded.email,
			traffic_used=excluded.traffic_used, traffic_total=excluded.traffic_total,
			wallet_balance=excluded.wallet_balance, commission_balance=excluded.commission_balance,
			user_created_at=excluded.user_created_at, last_ip=excluded.last_ip, last_ua=excluded.last_ua,
			site_domain=excluded.site_domain,
			report_count=report_count+1, last_seen=excluded.last_seen`,
		r.Token, r.Tenant, r.UUID, r.Email, r.TrafficUsed, r.TrafficTotal,
		r.WalletBalance, r.CommissionBalance, r.UserCreatedAt, r.LastIP, r.LastUA, r.SiteDomain,
		now, now)
	return err
}

func (s *Store) ListUserReports(tenant string) ([]UserReport, error) {
	q := `SELECT token, tenant, uuid, email, traffic_used, traffic_total,
		wallet_balance, commission_balance, user_created_at, last_ip, last_ua, site_domain,
		report_count, first_seen, last_seen FROM user_reports`
	var args []any
	if tenant != "" {
		q += ` WHERE tenant=?`
		args = append(args, tenant)
	}
	q += ` ORDER BY last_seen DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserReport
	for rows.Next() {
		var r UserReport
		if err := rows.Scan(&r.Token, &r.Tenant, &r.UUID, &r.Email, &r.TrafficUsed, &r.TrafficTotal,
			&r.WalletBalance, &r.CommissionBalance, &r.UserCreatedAt, &r.LastIP, &r.LastUA, &r.SiteDomain,
			&r.ReportCount, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SuspectRow 是嫌疑分析结果:events 行为聚合 + 可选 user_report 画像。
type SuspectRow struct {
	UserReport
	PullCount      int      `json:"pull_count"`
	DistinctIPs    int      `json:"distinct_ips"`
	DistinctUAs    int      `json:"distinct_uas"`
	CloudPullCount int      `json:"cloud_pull_count"`
	CloudProviders []string `json:"cloud_providers"`
	CloudASNs      []string `json:"cloud_asns"`
	ReTriggered    bool     `json:"retriggered"`
}

func (s *Store) QuerySuspects(tenant string, since time.Time) ([]SuspectRow, error) {
	// 先拿 user_reports 作为画像补充。嫌疑判断本身不能依赖上游上报,
	// 因为 SubPanel 处在 CDN -> SubPanel -> V2Board 的前置过滤位置。
	reports, err := s.ListUserReports(tenant)
	if err != nil {
		return nil, err
	}

	// 已处理记录用于区分“旧记录已归档”和“处理后再次触发”。
	resolvedSet := make(map[string]bool)
	resolvedRows, _ := s.db.Query(`SELECT token, COALESCE(tenant,'') FROM resolved_tokens`)
	if resolvedRows != nil {
		defer resolvedRows.Close()
		for resolvedRows.Next() {
			var token, t string
			if resolvedRows.Scan(&token, &t) == nil {
				resolvedSet[t+"\x00"+token] = true
			}
		}
	}
	isResolved := func(tenant, token string) bool {
		return resolvedSet[tenant+"\x00"+token] || resolvedSet["\x00"+token]
	}

	sinceMs := since.UnixMilli()

	// 一次性从 events 表聚合所有 token 的行为统计。即使 user_reports 为空,
	// 也能按多 IP、多 UA、频率把嫌疑 token 列出来。
	tenantCond := ""
	args := []any{sinceMs}
	if tenant != "" {
		tenantCond = " AND e.tenant=?"
		args = append(args, tenant)
	}
	rows, err := s.db.Query(`
		SELECT e.token_hash, e.tenant, COUNT(*), COUNT(DISTINCT e.client_ip), COUNT(DISTINCT COALESCE(e.ua,'')), MAX(e.ts),
		       SUM(CASE WHEN COALESCE(e.cloud_provider,'')<>'' THEN 1 ELSE 0 END),
		       COALESCE(GROUP_CONCAT(DISTINCT NULLIF(e.cloud_provider,'')),''),
		       COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN COALESCE(e.cloud_provider,'')<>''
		              THEN NULLIF(e.asn,'') END),'')
		FROM events e WHERE e.ts>=? AND e.token_hash<>''`+tenantCond+`
		  AND NOT EXISTS (SELECT 1 FROM resolved_tokens rt
		      WHERE rt.token=e.token_hash AND (rt.tenant='' OR rt.tenant=e.tenant) AND e.ts<=rt.resolved_ts)
		GROUP BY e.token_hash, e.tenant`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type evStats struct {
		pullCount      int
		distinctIPs    int
		distinctUAs    int
		lastSeen       int64
		lastIP         string
		lastUA         string
		tenant         string
		cloudPullCount int
		cloudProviders []string
		cloudASNs      []string
	}
	statsMap := make(map[string]evStats)
	for rows.Next() {
		var token string
		var st evStats
		var providers, asns string
		if err := rows.Scan(&token, &st.tenant, &st.pullCount, &st.distinctIPs, &st.distinctUAs, &st.lastSeen,
			&st.cloudPullCount, &providers, &asns); err != nil {
			continue
		}
		if providers != "" {
			st.cloudProviders = strings.Split(providers, ",")
		}
		if asns != "" {
			st.cloudASNs = strings.Split(asns, ",")
		}
		statsMap[st.tenant+"\x00"+token] = st
	}
	latestRows, err := s.db.Query(`
		SELECT token_hash, tenant, client_ip, COALESCE(ua,'')
		FROM (
			SELECT e.token_hash, e.tenant, e.client_ip, e.ua,
			       ROW_NUMBER() OVER (PARTITION BY e.token_hash, e.tenant ORDER BY e.ts DESC, e.id DESC) AS rn
			FROM events e WHERE e.ts>=? AND e.token_hash<>''`+tenantCond+`
			  AND NOT EXISTS (SELECT 1 FROM resolved_tokens rt
			      WHERE rt.token=e.token_hash AND (rt.tenant='' OR rt.tenant=e.tenant) AND e.ts<=rt.resolved_ts)
		) WHERE rn=1`, args...)
	if err != nil {
		return nil, err
	}
	defer latestRows.Close()
	for latestRows.Next() {
		var token, t, ip, ua string
		if err := latestRows.Scan(&token, &t, &ip, &ua); err != nil {
			continue
		}
		key := t + "\x00" + token
		st, ok := statsMap[key]
		if !ok {
			continue
		}
		st.lastIP = ip
		st.lastUA = ua
		statsMap[key] = st
	}

	out := make([]SuspectRow, 0, len(reports)+len(statsMap))
	seen := make(map[string]bool, len(reports))
	for _, r := range reports {
		key := r.Tenant + "\x00" + r.Token
		st, hasNewEvents := statsMap[key]
		if isResolved(r.Tenant, r.Token) && !hasNewEvents {
			continue
		}
		seen[key] = true
		if r.LastIP == "" {
			r.LastIP = st.lastIP
		}
		if r.LastUA == "" {
			r.LastUA = st.lastUA
		}
		pullCount := st.pullCount
		distinctIPs := st.distinctIPs
		distinctUAs := st.distinctUAs

		out = append(out, SuspectRow{
			UserReport:     r,
			PullCount:      pullCount,
			DistinctIPs:    distinctIPs,
			DistinctUAs:    distinctUAs,
			CloudPullCount: st.cloudPullCount,
			CloudProviders: st.cloudProviders,
			CloudASNs:      st.cloudASNs,
			ReTriggered:    isResolved(r.Tenant, r.Token),
		})
	}
	for key, st := range statsMap {
		if seen[key] {
			continue
		}
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, SuspectRow{
			UserReport: UserReport{
				Token:    parts[1],
				Tenant:   parts[0],
				LastIP:   st.lastIP,
				LastUA:   st.lastUA,
				LastSeen: st.lastSeen / 1000,
			},
			PullCount:      st.pullCount,
			DistinctIPs:    st.distinctIPs,
			DistinctUAs:    st.distinctUAs,
			CloudPullCount: st.cloudPullCount,
			CloudProviders: st.cloudProviders,
			CloudASNs:      st.cloudASNs,
			ReTriggered:    isResolved(parts[0], parts[1]),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}

	// 按邮箱合并:同邮箱只保留最近的 token(last_seen 最大的)
	emailMap := make(map[string]int, len(out)) // email -> index in merged
	merged := make([]SuspectRow, 0, len(out))
	for _, row := range out {
		key := row.Email + "\x00" + row.Tenant
		if row.Email == "" {
			// 无邮箱不合并
			merged = append(merged, row)
			continue
		}
		if idx, exists := emailMap[key]; exists {
			// 保留 last_seen 更大的
			if row.LastSeen > merged[idx].LastSeen {
				merged[idx] = row
			}
		} else {
			emailMap[key] = len(merged)
			merged = append(merged, row)
		}
	}
	out = merged

	// 按独立 IP 降序,同分按 pull_count 降序(共享/倒卖最直观信号)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if (out[j].ReTriggered && !out[i].ReTriggered) ||
				(out[j].ReTriggered == out[i].ReTriggered && (out[j].DistinctIPs > out[i].DistinctIPs ||
					(out[j].DistinctIPs == out[i].DistinctIPs && out[j].PullCount > out[i].PullCount))) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	// 最多返回 top 1000，保证云厂商/ASN 客户端筛选不会只看到前 100 条。
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

// SuspectDetail 单用户的 IP 列表和 UA 列表
type SuspectDetail struct {
	IPs []IPDetail `json:"ips"`
	UAs []UADetail `json:"uas"`
}

type IPDetail struct {
	IP            string `json:"ip"`
	Country       string `json:"country"`
	ISP           string `json:"isp"`
	ASN           string `json:"asn"`
	ASNOrg        string `json:"asn_org"`
	CloudProvider string `json:"cloud_provider"`
	UsageType     string `json:"usage_type"`
	UsageSource   string `json:"usage_source"`
	HitCount      int    `json:"hit_count"`
	LastSeen      int64  `json:"last_seen"` // unix ms
}

type UADetail struct {
	UA       string `json:"ua"`
	HitCount int    `json:"hit_count"`
	LastSeen int64  `json:"last_seen"`
}

func (s *Store) QuerySuspectDetail(token, tenant string, since time.Time) (*SuspectDetail, error) {
	sinceMs := since.UnixMilli()
	detail := &SuspectDetail{}

	// IP 明细
	tenantCond := ""
	args := []any{token, sinceMs}
	if tenant != "" {
		tenantCond = " AND tenant=?"
		args = append(args, tenant)
	}
	ipRows, err := s.db.Query(`
		SELECT client_ip, COALESCE(country,''), COALESCE(isp,''), COUNT(*), MAX(ts)
		FROM events WHERE token_hash=? AND ts>=?`+tenantCond+`
		GROUP BY client_ip ORDER BY COUNT(*) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer ipRows.Close()
	for ipRows.Next() {
		var d IPDetail
		if err := ipRows.Scan(&d.IP, &d.Country, &d.ISP, &d.HitCount, &d.LastSeen); err != nil {
			continue
		}
		detail.IPs = append(detail.IPs, d)
	}

	// UA 明细
	args2 := []any{token, sinceMs}
	tenantCond2 := ""
	if tenant != "" {
		tenantCond2 = " AND tenant=?"
		args2 = append(args2, tenant)
	}
	uaRows, err := s.db.Query(`
		SELECT COALESCE(ua,''), COUNT(*), MAX(ts)
		FROM events WHERE token_hash=? AND ts>=?`+tenantCond2+`
		GROUP BY ua ORDER BY COUNT(*) DESC`, args2...)
	if err != nil {
		return nil, err
	}
	defer uaRows.Close()
	for uaRows.Next() {
		var d UADetail
		if err := uaRows.Scan(&d.UA, &d.HitCount, &d.LastSeen); err != nil {
			continue
		}
		detail.UAs = append(detail.UAs, d)
	}

	return detail, nil
}
