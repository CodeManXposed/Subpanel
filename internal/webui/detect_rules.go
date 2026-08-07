// 触发规则管理 API:增删改启停 + DB 反序列化 + 推到 detector 热生效。
//
// 字段层(JSON):
//   - name / desc:             字符串
//   - enabled:                 bool
//   - sort_order:              int(列表展示顺序)
//   - 条件:                   4 个 *Cond + 高级 GeoIP/云 IP 字段
//
// 校验:
//   - name 必填 + 唯一
//   - 至少一个条件不为空(否则规则等于死规则,不允许保存)
//   - 任何 Cond 的 window/gte 不能为 0
package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// detectRuleAPI:对外 JSON 形态,字段平铺,前端表单填起来方便。
// 时长统一用秒数(yaml 用 Duration 字符串,这里 API 端用整数秒便于前端处理)。
type detectRuleAPI struct {
	Name   string `json:"name"`
	Desc   string `json:"desc"`
	Action string `json:"action"` // fake|deny
	// Severity 已废弃,API 不再返回也不再接收。
	Enabled   bool `json:"enabled"`
	SortOrder int  `json:"sort_order"`

	// 计数条件:都以"窗口 + 阈值"成对出现,任一字段为 0 视为未启用该条件
	TokenFreqWindowSec        int `json:"token_freq_window_sec"`
	TokenFreqGTE              int `json:"token_freq_gte"`
	IPFreqWindowSec           int `json:"ip_freq_window_sec"`
	IPFreqGTE                 int `json:"ip_freq_gte"`
	TokenDistinctIPsWindowSec int `json:"token_distinct_ips_window_sec"`
	TokenDistinctIPsGTE       int `json:"token_distinct_ips_gte"`
	IPDistinctTokensWindowSec int `json:"ip_distinct_tokens_window_sec"`
	IPDistinctTokensGTE       int `json:"ip_distinct_tokens_gte"`
	CloudTokenUAsWindowSec    int `json:"cloud_token_distinct_uas_window_sec"`
	CloudTokenUAsGTE          int `json:"cloud_token_distinct_uas_gte"`

	// 云 IP / GeoIP / ISP(高级,可选)
	FromCloudIP    bool     `json:"from_cloud_ip"`
	UncommonUA     bool     `json:"uncommon_ua"`
	CountryIn      []string `json:"country_in"`
	CountryNotIn   []string `json:"country_not_in"`
	UsageTypeIn    []string `json:"usage_type_in"`
	UsageTypeNotIn []string `json:"usage_type_not_in"`
	ISPContains    []string `json:"isp_contains"`

	UpdatedTS int64 `json:"updated_ts"`
}

// rowToAPI 把 DB 行转成 API 对外格式。
func rowToAPI(r store.DetectRuleRow) (*detectRuleAPI, error) {
	var w config.When
	if err := json.Unmarshal([]byte(r.WhenJSON), &w); err != nil {
		return nil, err
	}
	a := &detectRuleAPI{
		Name:           r.Name,
		Desc:           r.Desc,
		Action:         ruleAction(r.Action),
		Enabled:        r.Enabled,
		SortOrder:      r.SortOrder,
		FromCloudIP:    w.FromCloudIP,
		UncommonUA:     w.UncommonUA,
		CountryIn:      w.CountryIn,
		CountryNotIn:   w.CountryNotIn,
		UsageTypeIn:    w.UsageTypeIn,
		UsageTypeNotIn: w.UsageTypeNotIn,
		ISPContains:    w.ISPContains,
		UpdatedTS:      r.UpdatedTS.Unix(),
	}
	if w.TokenFreq != nil {
		a.TokenFreqWindowSec = int(w.TokenFreq.Window.Std().Seconds())
		a.TokenFreqGTE = w.TokenFreq.GTE
	}
	if w.IPFreq != nil {
		a.IPFreqWindowSec = int(w.IPFreq.Window.Std().Seconds())
		a.IPFreqGTE = w.IPFreq.GTE
	}
	if w.TokenDistinctIPs != nil {
		a.TokenDistinctIPsWindowSec = int(w.TokenDistinctIPs.Window.Std().Seconds())
		a.TokenDistinctIPsGTE = w.TokenDistinctIPs.GTE
	}
	if w.IPDistinctTokens != nil {
		a.IPDistinctTokensWindowSec = int(w.IPDistinctTokens.Window.Std().Seconds())
		a.IPDistinctTokensGTE = w.IPDistinctTokens.GTE
	}
	if w.CloudTokenDistinctUAs != nil {
		a.CloudTokenUAsWindowSec = int(w.CloudTokenDistinctUAs.Window.Std().Seconds())
		a.CloudTokenUAsGTE = w.CloudTokenDistinctUAs.GTE
	}
	return a, nil
}

func ruleAction(action string) string {
	if strings.EqualFold(strings.TrimSpace(action), "deny") {
		return "deny"
	}
	return "fake"
}

// apiToWhen 把对外平铺字段还原成 config.When。
func apiToWhen(a *detectRuleAPI) (config.When, error) {
	w := config.When{
		FromCloudIP:    a.FromCloudIP,
		UncommonUA:     a.UncommonUA,
		CountryIn:      trimList(a.CountryIn),
		CountryNotIn:   trimList(a.CountryNotIn),
		UsageTypeIn:    trimList(a.UsageTypeIn),
		UsageTypeNotIn: trimList(a.UsageTypeNotIn),
		ISPContains:    trimList(a.ISPContains),
	}
	// 计数条件:窗口和阈值必须同时给,否则视为关闭该条件
	mkCond := func(winSec, gte int, name string) (*config.Cond, error) {
		if winSec == 0 && gte == 0 {
			return nil, nil
		}
		if winSec <= 0 || gte <= 0 {
			return nil, fmt.Errorf("%s: 窗口和阈值必须同时大于 0", name)
		}
		return &config.Cond{
			Window: config.Duration(secToNs(winSec)),
			GTE:    gte,
		}, nil
	}
	var err error
	if w.TokenFreq, err = mkCond(a.TokenFreqWindowSec, a.TokenFreqGTE, "单 token 频次"); err != nil {
		return w, err
	}
	if w.IPFreq, err = mkCond(a.IPFreqWindowSec, a.IPFreqGTE, "单 IP 频次"); err != nil {
		return w, err
	}
	if w.TokenDistinctIPs, err = mkCond(a.TokenDistinctIPsWindowSec, a.TokenDistinctIPsGTE, "单 token 多 IP"); err != nil {
		return w, err
	}
	if w.IPDistinctTokens, err = mkCond(a.IPDistinctTokensWindowSec, a.IPDistinctTokensGTE, "单 IP 多 token"); err != nil {
		return w, err
	}
	if w.CloudTokenDistinctUAs, err = mkCond(a.CloudTokenUAsWindowSec, a.CloudTokenUAsGTE, "云 IP 单 token 多 UA"); err != nil {
		return w, err
	}
	// 至少一个条件不为空
	if w.TokenFreq == nil && w.IPFreq == nil && w.TokenDistinctIPs == nil && w.IPDistinctTokens == nil && w.CloudTokenDistinctUAs == nil &&
		!w.FromCloudIP && !w.UncommonUA && len(w.CountryIn) == 0 && len(w.CountryNotIn) == 0 &&
		len(w.UsageTypeIn) == 0 && len(w.UsageTypeNotIn) == 0 && len(w.ISPContains) == 0 {
		return w, fmt.Errorf("至少配置一个触发条件")
	}
	return w, nil
}

func secToNs(s int) int64 { return int64(s) * 1_000_000_000 }

func trimList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x != "" {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) apiDetectRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListDetectRules()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	out := make([]*detectRuleAPI, 0, len(rows))
	for _, row := range rows {
		a, err := rowToAPI(row)
		if err != nil {
			// 坏数据跳过,前端少展示一条而已,不让整页崩
			continue
		}
		out = append(out, a)
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiDetectRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		detectRuleAPI
		OriginalName string `json:"original_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "规则名必填"})
		return
	}
	body.Action = strings.ToLower(strings.TrimSpace(body.Action))
	if body.Action == "" {
		body.Action = "fake"
	}
	if body.Action != "fake" && body.Action != "deny" {
		writeJSON(w, 400, map[string]any{"error": "处置动作只能是 fake 或 deny"})
		return
	}
	when, err := apiToWhen(&body.detectRuleAPI)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	buf, err := json.Marshal(when)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "序列化条件失败: " + err.Error()})
		return
	}
	// 改名:先删旧
	if body.OriginalName != "" && body.OriginalName != body.Name {
		if err := s.st.DeleteDetectRule(body.OriginalName); err != nil {
			writeJSON(w, 500, map[string]any{"error": "删除旧规则失败: " + err.Error()})
			return
		}
	}
	if err := s.st.UpsertDetectRule(store.DetectRuleRow{
		Name:      body.Name,
		Desc:      body.Desc,
		Severity:  "", // 已废弃,DB 列保留兼容
		Action:    body.Action,
		WhenJSON:  string(buf),
		Enabled:   body.Enabled,
		SortOrder: body.SortOrder,
	}); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.reloadDetectRules(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "热生效失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiDetectRuleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "name 必填"})
		return
	}
	if err := s.st.DeleteDetectRule(body.Name); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.reloadDetectRules(); err != nil {
		writeJSON(w, 500, map[string]any{"error": "热生效失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiUAWhitelistList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListUARules("whitelist")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	type item struct {
		ID        int64  `json:"id"`
		Pattern   string `json:"pattern"`
		Note      string `json:"note"`
		CreatedTS int64  `json:"created_ts"`
	}
	out := make([]item, 0, len(rows))
	for _, row := range rows {
		out = append(out, item{ID: row.ID, Pattern: row.Pattern, Note: row.Note, CreatedTS: row.CreatedTS.Unix()})
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiUAWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Pattern string `json:"pattern"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if s.rules == nil {
		writeJSON(w, 503, map[string]any{"error": "规则管理器未就绪"})
		return
	}
	if err := s.rules.AddUAWhitelist(body.Pattern, body.Note); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiUAWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if body.ID <= 0 {
		writeJSON(w, 400, map[string]any{"error": "id 必填"})
		return
	}
	if s.rules == nil {
		writeJSON(w, 503, map[string]any{"error": "规则管理器未就绪"})
		return
	}
	if err := s.rules.DeleteUAWhitelist(body.ID); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// reloadDetectRules 从 DB 读启用的规则,推到 detector 热生效。
func (s *Server) reloadDetectRules() error {
	rows, err := s.st.ListDetectRules()
	if err != nil {
		return err
	}
	out := make([]config.Rule, 0, len(rows))
	for _, r := range rows {
		if !r.Enabled {
			continue
		}
		var w config.When
		if err := json.Unmarshal([]byte(r.WhenJSON), &w); err != nil {
			return fmt.Errorf("规则 %s 反序列化失败: %w", r.Name, err)
		}
		out = append(out, config.Rule{
			Name:   r.Name,
			Desc:   r.Desc,
			Action: ruleAction(r.Action),
			When:   w,
		})
	}
	s.det.SetRules(out)
	return nil
}
