package webui

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

// POST /api/report/{tenant} — v2board 上报接口(不走登录,用 secret key 鉴权)
func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}

	// 鉴权: X-Report-Key header
	secret := s.cfg.Admin.ReportSecret
	if secret != "" {
		key := r.Header.Get("X-Report-Key")
		if key != secret {
			writeJSON(w, 403, map[string]any{"error": "invalid report key"})
			return
		}
	}

	// 从路径提取 tenant: /api/report/{tenant}
	tenant := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if tenant == "" || tenant == r.URL.Path {
		writeJSON(w, 400, map[string]any{"error": "missing tenant in path"})
		return
	}

	var body struct {
		Token             string `json:"token"`
		UUID              string `json:"uuid"`
		Email             string `json:"email"`
		TrafficUsed       int64  `json:"traffic_used"`
		TrafficTotal      int64  `json:"traffic_total"`
		WalletBalance     int64  `json:"wallet_balance"`
		CommissionBalance int64  `json:"commission_balance"`
		UserCreatedAt     string `json:"user_created_at"`
		IP                string `json:"ip"`
		UserAgent         string `json:"user_agent"`
		SiteDomain        string `json:"site_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json: " + err.Error()})
		return
	}
	if body.Token == "" {
		writeJSON(w, 400, map[string]any{"error": "token required"})
		return
	}

	report := store.UserReport{
		Token:             body.Token,
		Tenant:            tenant,
		UUID:              body.UUID,
		Email:             body.Email,
		TrafficUsed:       body.TrafficUsed,
		TrafficTotal:      body.TrafficTotal,
		WalletBalance:     body.WalletBalance,
		CommissionBalance: body.CommissionBalance,
		UserCreatedAt:     body.UserCreatedAt,
		LastIP:            body.IP,
		LastUA:            body.UserAgent,
		SiteDomain:        body.SiteDomain,
	}
	if err := s.st.UpsertUserReport(report); err != nil {
		s.logger.Error("upsert user report", "err", err)
		writeJSON(w, 500, map[string]any{"error": "store error"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/suspects?tenant=xxx&window=24h — 嫌疑用户列表(需登录)
func (s *Server) apiSuspects(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	windowStr := r.URL.Query().Get("window")
	if windowStr == "" {
		windowStr = "168h" // 默认 7 天
	}
	dur, err := time.ParseDuration(windowStr)
	if err != nil {
		dur = 168 * time.Hour
	}
	since := time.Now().Add(-dur)

	rows, err := s.st.QuerySuspects(tenant, since)
	if err != nil {
		s.logger.Error("query suspects", "err", err)
		writeJSON(w, 500, map[string]any{"error": "query error"})
		return
	}
	if rows == nil {
		rows = []store.SuspectRow{}
	}
	writeJSON(w, 200, rows)
}

// GET /api/user-reports?tenant=xxx — 原始上报列表(需登录)
func (s *Server) apiUserReports(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	reports, err := s.st.ListUserReports(tenant)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "query error"})
		return
	}
	if reports == nil {
		reports = []store.UserReport{}
	}
	writeJSON(w, 200, reports)
}

// GET /api/report-info — 返回上报接入信息(URL前缀 + secret),供机场管理页展示
func (s *Server) apiReportInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"report_secret": s.cfg.Admin.ReportSecret,
		"admin_listen":  s.cfg.AdminListen,
	})
}
