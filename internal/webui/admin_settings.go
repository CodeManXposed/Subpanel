// admin_settings.go: 改密码 + 一键透传
package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// apiChangePassword 改密。
// body: {old_password, new_password}
// 校验旧密码 → bcrypt 新密码 → 写入 store.meta admin_password_hash
// 不重启即生效(apiLogin 会优先读 meta)
func (s *Server) apiChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if len(body.NewPassword) < 8 {
		writeJSON(w, 400, map[string]any{"error": "新密码至少 8 位"})
		return
	}
	// 校验旧密码:meta 优先
	pwHash := s.cfg.Admin.PasswordHash
	if v, _ := s.st.GetMeta("admin_password_hash"); v != "" {
		pwHash = v
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(body.OldPassword)); err != nil {
		writeJSON(w, 401, map[string]any{"error": "原密码错误"})
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.st.SetMeta("admin_password_hash", string(newHash)); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 顺手销毁所有会话,强制重新登录
	s.sessionMu.Lock()
	s.sessions = map[string]session{}
	s.sessionMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// apiPassthrough 一键透传开关。
// GET:查当前状态。POST {enabled: bool}:写 store.meta passthrough_all,网关代理入口短路。
func (s *Server) apiPassthrough(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, _ := s.st.GetMeta("passthrough_all")
		writeJSON(w, 200, map[string]any{"enabled": strings.EqualFold(v, "true")})
		return
	}
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	v := "false"
	if body.Enabled {
		v = "true"
	}
	if err := s.st.SetMeta("passthrough_all", v); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// 热生效:通知 gateway
	if s.gw != nil {
		s.gw.SetPassthroughAll(body.Enabled)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": body.Enabled})
}
