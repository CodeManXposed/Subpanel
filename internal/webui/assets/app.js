// Sub-Panel web UI

const state = { tenant: '', window: '24h' };

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleString('zh-CN', { hour12: false });
}
function fmtSince(ts) {
  if (!ts) return '从未';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60_000) return Math.floor(diff/1000) + ' 秒前';
  if (diff < 3600_000) return Math.floor(diff/60_000) + ' 分钟前';
  if (diff < 86400_000) return Math.floor(diff/3600_000) + ' 小时前';
  return Math.floor(diff/86400_000) + ' 天前';
}
function escapeHTML(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
function tokenShort(h) {
  // 用户要求所有页面直接显示 token 原文,不截断。
  // 保留函数名避免到处改调用点;CSS 用 word-break:break-all 处理长字符串。
  return h || '';
}
const ACTION_CN = {
  pass: '放行',
  fake: '投毒',
  deny: '拒绝',
  block_path: '路径拦截',
  fake_failed: '投毒失败',
};
function actionLabel(a) { return ACTION_CN[a] || a || '-'; }

// tag 中文翻译。带 `:` 的 tag(如 bl_oversea:US / cloud_ip:aws / token_freq=10>=5 window=60s)
// 拆开拼:前缀翻译 + 后缀(国家/服务商/数值)原样附加。
const TAG_PREFIX_CN = {
  // 全局黑名单
  'bl_oversea':     '黑名单·海外',
  'bl_cloud':       '黑名单·云厂商',
  'bl_cn_idc':      '黑名单·国内IDC',
  'bl_browser':     '黑名单·浏览器直访',
  'bl_isp':         '黑名单·运营商',
  // 白名单 / 路径
  'ip_whitelist':   '白名单放行',
  'banlist_ip':     'IP 黑名单',
  'path_not_match': '路径不匹配',
  // 上游
  'upstream_bad':   '上游异常',
  // 触发规则
  'token_freq':           '单 token 频次',
  'ip_freq':              '单 IP 频次',
  'token_distinct_ips':   '单 token 多 IP',
  'ip_distinct_tokens':   '单 IP 多 token',
  'cloud_ip':             '命中云厂商',
  'country_in':           '国家命中',
  'country_not_in':       '国家排除',
  'usage_type_in':        '用途命中',
  'usage_type_not_in':    '用途排除',
  'isp_contains':         '运营商关键字',
};

// usage_type 中文映射(IPIP xdb 字段值)
const USAGE_LABEL = {
  'IDC':   '数据中心',
  'CDN':   '内容分发',
  'DNS':   '域名解析',
  'EDU':   '教育机构',
  'GTW':   '企业专线',
  'GOV':   '政府机构',
  'DYN':   '家庭宽带',
  'MOB':   '移动网络',
  'COM':   '商业宽带',
  'ORG':   '组织机构',
  'NET':   '基础设施',
  'BOGON': '保留IP',
};
function usageLabel(u) {
  if (!u) return '';
  const k = String(u).toUpperCase().trim();
  return USAGE_LABEL[k] || u;
}

function tagLabel(t) {
  if (!t) return '';
  // 处理 token_freq=10>=5 window=60s 这种带 = 的格式
  const eqIdx = t.indexOf('=');
  if (eqIdx > 0) {
    const head = t.slice(0, eqIdx);
    if (TAG_PREFIX_CN[head]) return TAG_PREFIX_CN[head] + ' ' + t.slice(eqIdx + 1);
  }
  // 处理 bl_oversea:US / cloud_ip:aws / banlist_ip:reason 这种带 : 的
  const colonIdx = t.indexOf(':');
  if (colonIdx > 0) {
    const head = t.slice(0, colonIdx);
    if (TAG_PREFIX_CN[head]) return TAG_PREFIX_CN[head] + '(' + t.slice(colonIdx + 1) + ')';
  }
  return TAG_PREFIX_CN[t] || t;
}
// 等级常量已废弃:命中即投毒,无等级。

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + kind;
  setTimeout(() => t.className = 'toast ' + kind, 3000);
}

async function api(path) {
  const r = await fetch(path);
  if (r.status === 401) { location.href = '/login'; return null; }
  if (!r.ok) { toast('API ' + r.status, 'error'); return null; }
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (r.status === 401) { location.href = '/login'; return null; }
  return r.json();
}

// ---- 路由 ----

const TAB_TITLES = {
  'dashboard': '概览',
  'events': '请求日志',
  'resolved': '已处理 Token',
  'ip-bans': '黑名单',
  'ip-whitelist': 'IP 白名单',
  'cloud-ip': 'GeoIP 库',
  'tenants': '机场管理',
  'settings': '设置',
};

const TAB_LOADERS = {
  'dashboard': () => loadSummary(),
  'events': () => loadEvents(),
  'resolved': () => loadResolved(),
  'ip-bans': () => loadBans(),
  'ip-whitelist': () => loadIPWhitelist(),
  'cloud-ip': () => loadGeoIPInfo(),
  'detect-rules': () => loadRulesTable(),
  'tenants': () => loadTenantsTable(),
  'settings': () => { loadSettings(); loadPassthrough(); },
};

$$('.navlink').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    $$('.navlink').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    const tab = a.dataset.tab;
    $$('.tab').forEach(s => s.classList.remove('active'));
    const sec = document.getElementById('tab-' + tab);
    if (sec) sec.classList.add('active');
    $('#pageTitle').textContent = TAB_TITLES[tab] || tab;
    if (TAB_LOADERS[tab]) TAB_LOADERS[tab]();
  });
});

$('#refreshBtn').addEventListener('click', () => {
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

$('#logoutBtn').addEventListener('click', async () => {
  await apiPost('/api/logout', {});
  location.href = '/login';
});

$('#tenantSel').addEventListener('change', e => {
  state.tenant = e.target.value;
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

$('#windowSel').addEventListener('change', e => {
  state.window = e.target.value;
  const active = document.querySelector('.navlink.active');
  if (active && TAB_LOADERS[active.dataset.tab]) TAB_LOADERS[active.dataset.tab]();
});

// ---- tenants ----
async function loadTenants() {
  const ts = await api('/api/tenants');
  if (!ts) return;
  const sel = $('#tenantSel');
  sel.innerHTML = '<option value="">全部机场</option>';
  for (const t of ts) {
    const o = document.createElement('option');
    o.value = t.name;
    o.textContent = t.name + ' (' + (t.subscribe_path || '') + ')';
    sel.appendChild(o);
  }
}

// ---- dashboard ----
async function loadSummary() {
  const q = new URLSearchParams({ tenant: state.tenant, window: state.window });
  const s = await api('/api/summary?' + q);
  if (!s) return;
  const cards = $('#summaryCards');
  cards.innerHTML = '';
  const data = [
    ['total', '总请求', s.total_events],
    ['pass', '放行', s.pass],
    ['fake', '投毒', s.fake],
    ['deny', '拒绝', s.deny],
    ['', '独立 IP', s.unique_ips],
    ['', '独立 订阅', s.unique_tokens],
  ];
  for (const [cls, label, val] of data) {
    const c = document.createElement('div');
    c.className = 'stat-card ' + cls;
    c.innerHTML = `<div class="label">${cls ? '<span class="dot"></span>' : ''}${label}</div><div class="value">${val ?? 0}</div>`;
    cards.appendChild(c);
  }
  // 异常等级已废弃,命中即投毒,无等级统计。
  const ipTbody = $('#topIPs tbody'); ipTbody.innerHTML = '';
  (s.top_ips || []).forEach(k => {
    const tr = document.createElement('tr');
    const region = k.region || '<span class="muted">未知</span>';
    const isp = k.isp ? escapeHTML(k.isp) : '<span class="muted">未知</span>';
    tr.innerHTML = `<td class="mono">${escapeHTML(k.key)}</td><td>${k.region ? escapeHTML(k.region) : '<span class="muted">未知</span>'}</td><td>${isp}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    ipTbody.appendChild(tr);
  });
  const tokTbody = $('#topTokens tbody'); tokTbody.innerHTML = '';
  (s.top_tokens || []).forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono copyable ev-token-expand" data-copy="${escapeHTML(k.key)}" data-full="${escapeHTML(k.key)}" data-short="${escapeHTML(tokenShort(k.key))}" title="点击展开 / 再点复制">${escapeHTML(tokenShort(k.key))}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    tokTbody.appendChild(tr);
  });
  bindCopyHandlers(tokTbody);
}

// ---- events ----
const EV_PAGE_SIZE = 50;
let evOffset = 0;

function renderEventCard(e) {
  const card = document.createElement('div');
  card.className = 'ev-card';
  const region = [e.CountryName, e.Province, e.City].filter(x => x && x !== '0').join(' · ') || '未知';
  const isp = e.ISP && e.ISP !== '0' ? escapeHTML(e.ISP) : '<span class="muted">未知</span>';
  const tags = (e.RuleTags || []).length
    ? (e.RuleTags || []).map(t => `<span class="pill tag" title="${escapeHTML(t)}">${escapeHTML(tagLabel(t))}</span>`).join(' ')
    : '';
  const tokenFull = e.TokenHash || '';
  const ua = e.UA || '';
  const flagBit = e.Flag ? `<span class="kv-sep">·</span><span class="mono">${escapeHTML(e.Flag)}</span>` : '';
  const tenantBit = (e.Tenant && e.Tenant !== '_unmatched') ? `<span class="kv-sep">·</span><span class="ev-tenant">${escapeHTML(e.Tenant)}</span>` : '';
  const pathBit = e.Path ? `<span class="mono ev-path" title="${escapeHTML(e.Path)}">${escapeHTML(e.Path)}</span>` : '<span class="muted">(无)</span>';
  const usageBit = e.Usage
    ? `<span class="pill usage ${escapeHTML(String(e.Usage).toLowerCase())}" title="${escapeHTML(e.Usage)}">${escapeHTML(usageLabel(e.Usage))}</span>`
    : '';
  // 已处理按钮:仅当有 token 时显示。data-tenant 用事件自己的 tenant(不是当前过滤)。
  const resolveBtn = tokenFull
    ? `<button class="ev-resolve" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(e.Tenant || '')}" title="标记此 token 为已处理,后续不再出现">已处理</button>`
    : '';
  // 重置滑窗按钮:把此 token 在风控滑窗里的累计计数清掉,把它"拉出来"。
  // 不是免疫——下次再命中规则照样投毒。仅对 fake / fake_failed 事件显示。
  const resetBtn = (tokenFull && (e.Action === 'fake' || e.Action === 'fake_failed'))
    ? `<button class="ev-reset" data-token="${escapeHTML(tokenFull)}" title="清掉此 token 的风控累计窗口,等于'本次解毒'。下次命中规则仍会重新投毒">重置窗口</button>`
    : '';
  card.innerHTML = `
    <div class="ev-card-head">
      <span class="pill ${e.Action || ''}">${escapeHTML(actionLabel(e.Action))}</span>
      <span class="ev-time mono">${escapeHTML(fmtTime(e.TS))}</span>
      <span class="ev-status mono">HTTP ${e.Status || '—'}</span>
      <span class="ev-spacer"></span>
      ${tags}
      ${resetBtn}
      ${resolveBtn}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">订阅</span>
      ${tokenFull
        ? `<span class="mono copyable ev-token ev-token-expand" data-copy="${escapeHTML(tokenFull)}" data-full="${escapeHTML(tokenFull)}" data-short="${escapeHTML(tokenShort(tokenFull))}" title="点击展开 / 再点复制">${escapeHTML(tokenShort(tokenFull))}</span>`
        : '<span class="muted">(无)</span>'}
      ${flagBit}${tenantBit}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">路径</span>
      ${pathBit}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">UA</span>
      ${ua
        ? `<span class="mono ev-ua">${escapeHTML(ua)}</span>`
        : '<span class="muted">(无)</span>'}
    </div>
    <div class="ev-meta">
      <span class="ev-meta-item"><span class="ev-label">IP</span>
        <span class="mono">${escapeHTML(e.ClientIP || '—')}</span>
      </span>
      <span class="ev-meta-item"><span class="ev-label">地区</span><span>${escapeHTML(region)}</span></span>
      <span class="ev-meta-item"><span class="ev-label">ISP</span><span>${isp}</span></span>
      <span class="ev-meta-item"><span class="ev-label">ASN</span><span class="mono">${e.ASN ? escapeHTML(e.ASN) : '—'}</span></span>
      ${usageBit ? `<span class="ev-meta-item"><span class="ev-label">用途</span>${usageBit}</span>` : ''}
    </div>
  `;
  return card;
}

function bindCopyHandlers(scope) {
  scope.querySelectorAll('.copyable').forEach(el => {
    if (el.dataset.copyBound) return;
    el.dataset.copyBound = '1';
    el.addEventListener('click', async () => {
      // 带 ev-token-expand:第一次点展开,展开后再点才复制
      if (el.classList.contains('ev-token-expand') && !el.classList.contains('expanded')) {
        el.textContent = el.dataset.full || '';
        el.classList.add('expanded');
        el.setAttribute('title', '点击复制完整 token / 再点收起');
        return;
      }
      const txt = el.getAttribute('data-copy') || '';
      if (!txt) return;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(txt);
          ok = true;
        } else {
          const ta = document.createElement('textarea');
          ta.value = txt;
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.focus(); ta.select();
          ok = document.execCommand('copy');
          document.body.removeChild(ta);
        }
      } catch (err) {
        console.warn('复制失败', err);
      }
      if (ok) {
        el.classList.add('copied');
        const old = el.getAttribute('title') || '';
        el.setAttribute('title', '已复制 ✓');
        setTimeout(() => { el.classList.remove('copied'); el.setAttribute('title', old); }, 1200);
      }
    });
  });
}

async function loadEvents(append = false) {
  if (!append) evOffset = 0;
  const q = new URLSearchParams({
    tenant: state.tenant, window: state.window,
    limit: String(EV_PAGE_SIZE), offset: String(evOffset),
    ip: $('#evIP').value, token: $('#evToken').value, action: $('#evAction').value,
    usage: $('#evUsage').value,
    show_whitelist: $('#evShowWL').checked ? '1' : '0',
  });
  const evs = await api('/api/events?' + q);
  if (!evs) return;
  const list = $('#evList');
  if (!append) list.innerHTML = '';
  if (!append && evs.length === 0) {
    list.innerHTML = '<div class="empty-state">没有匹配的事件</div>';
    updateEvMore(0);
  } else {
    for (const e of evs) list.appendChild(renderEventCard(e));
    bindCopyHandlers(list);
    evOffset += evs.length;
    updateEvMore(evs.length);
  }
  if (!append) loadEvTopIP();  // 顶部 Top 20 跟 events 同步刷新
}

function updateEvMore(lastCount) {
  let btn = $('#evMoreBtn');
  if (!btn) {
    const list = $('#evList');
    if (!list || !list.parentNode) return;
    btn = document.createElement('button');
    btn.id = 'evMoreBtn';
    btn.className = 'ev-more-btn';
    btn.addEventListener('click', () => loadEvents(true));
    list.parentNode.insertBefore(btn, list.nextSibling);
  }
  if (lastCount < EV_PAGE_SIZE) {
    btn.style.display = 'none';
  } else {
    btn.style.display = '';
    btn.textContent = `加载更多(已显示 ${evOffset} 条)`;
  }
}
$('#evQuery').addEventListener('click', () => loadEvents(false));

// 清空日志:针对当前选中的机场;选"全部机场"时清全部。
// 二次确认 + 显示删了多少行。
$('#evPurge').addEventListener('click', async () => {
  const t = state.tenant || '';
  const scope = t ? `机场 [${t}]` : '【全部机场】';
  if (!confirm(`确定清空 ${scope} 的请求日志和异常记录?\n\n此操作不可撤销!`)) return;
  const body = t ? { tenant: t } : { all: true };
  const r = await apiPost('/api/events/purge', body);
  if (r && r.ok) {
    alert(`已清空。请求事件 ${r.events_deleted} 条,异常事件 ${r.incidents_deleted} 条。`);
    loadEvents();
    if (typeof loadSummary === 'function') loadSummary();
  } else {
    alert('清空失败:' + (r && r.error ? r.error : '未知错误'));
  }
});

// 事件卡片"已处理"按钮:事件委托。
$('#evList').addEventListener('click', async (e) => {
  const resetBtn = e.target.closest('.ev-reset');
  if (resetBtn) {
    const token = resetBtn.dataset.token || '';
    if (!token) return;
    if (!confirm(`重置此 token 在风控滑窗里的累计?\n\n${token}\n\n本次会被"拉出来",但下次再触发规则仍会照常投毒。`)) return;
    const r = await apiPost('/api/detector/reset-token', { token });
    if (r && r.ok) {
      toast('已重置滑窗,客户端刷一下订阅试试', 'success');
    } else {
      alert('重置失败:' + (r && r.error ? r.error : '未知错误'));
    }
    return;
  }
  const btn = e.target.closest('.ev-resolve');
  if (!btn) return;
  const token = btn.dataset.token || '';
  const tenant = btn.dataset.tenant || '';
  if (!token) return;
  const note = prompt(`标记 token 为已处理(备注可选):\n\n${token}`, '');
  if (note === null) return; // 用户取消
  const r = await apiPost('/api/resolved/add', { token, tenant, note });
  if (r && r.ok) {
    loadEvents(false);
  } else {
    alert('标记失败:' + (r && r.error ? r.error : '未知错误'));
  }
});

// ---- 已处理 Token 列表 ----
async function loadResolved() {
  const q = new URLSearchParams();
  if (state.tenant) q.set('tenant', state.tenant);
  const rows = await api('/api/resolved' + (q.toString() ? '?' + q : ''));
  const tbody = $('#resolvedTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">无已处理 token</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono copyable" data-copy="${escapeHTML(r.token)}" title="点击复制">${escapeHTML(r.token)}</td>
      <td>${escapeHTML(r.tenant || '-')}</td>
      <td>${escapeHTML(r.note || '-')}</td>
      <td class="mono">${escapeHTML(fmtTime(new Date(r.resolved_ts)))}</td>
      <td><button class="danger res-restore" data-token="${escapeHTML(r.token)}">恢复</button></td>
    `;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}
$('#resolvedTbody')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('.res-restore');
  if (!btn) return;
  if (!confirm('恢复后此 token 将重新出现在请求日志里,确定?')) return;
  const r = await apiPost('/api/resolved/remove', { token: btn.dataset.token });
  if (r && r.ok) loadResolved();
  else alert('恢复失败:' + (r && r.error ? r.error : '未知错误'));
});

// ---- 请求日志页顶部:异常 IP Top 20(复用 /api/incidents/agg_ip) ----
async function loadEvTopIP() {
  const q = new URLSearchParams({
    tenant: state.tenant, window: state.window, limit: '20',
    action: $('#evAction').value,
  });
  const aggs = await api('/api/incidents/agg_ip?' + q);
  const tbody = $('#evTopIPTbody'); if (!tbody) return;
  tbody.innerHTML = '';
  if (!aggs || !aggs.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">本时间窗内无异常 IP</td></tr>';
    return;
  }
  for (const a of aggs) {
    const tr = document.createElement('tr');
    const actsHTML = (a.actions || [])
      .map(x => `<span class="pill ${x}">${escapeHTML(actionLabel(x))}</span>`).join(' ');
    const tagsHTML = (a.tags || []).map(t => `<code title="${escapeHTML(t)}">${escapeHTML(tagLabel(t))}</code>`).join(' ');
    tr.innerHTML = `
      <td class="mono">${escapeHTML(a.client_ip)}</td>
      <td style="text-align:right" class="mono"><strong>${a.count}</strong></td>
      <td>${actsHTML}</td>
      <td class="mono" style="font-size:11.5px">${tagsHTML}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(new Date(a.last_ts)))}</td>
      <td>
        <button class="btn-mini" data-ip="${escapeHTML(a.client_ip)}" data-act="filter">看详情</button>
        <button class="danger btn-mini" data-ip="${escapeHTML(a.client_ip)}" data-act="ban">封禁</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
  $$('#evTopIPTbody button[data-act="filter"]').forEach(btn => {
    btn.addEventListener('click', () => {
      $('#evIP').value = btn.dataset.ip;
      loadEvents();
    });
  });
  $$('#evTopIPTbody button[data-act="ban"]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.ip;
      if (!confirm('封禁 ' + ip + ' ?')) return;
      const r = await apiPost('/api/bans/add', { kind: 'ip', target: ip, reason: '请求日志页手动封禁' });
      if (r && r.ok) { toast('已封禁 ' + ip, 'success'); }
      else { toast((r && r.error) || '封禁失败', 'error'); }
    });
  });
}

// ---- bans (仅 IP,token 黑名单已废弃) ----
async function loadBans() {
  await loadBlacklistCfg();
  const bs = await api('/api/bans');
  if (!bs) return;
  const ipTbody = $('#ipBanTbody'); ipTbody.innerHTML = '';
  let ipCount = 0;
  for (const b of bs || []) {
    if (b.Kind !== 'ip') continue;  // 兼容老库残留的 token 行,直接跳过
    const exp = b.ExpiresTS ? fmtTime(b.ExpiresTS) : '<span style="color:var(--danger)">永久</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono" title="${escapeHTML(b.Target)}">${escapeHTML(b.Target)}</td>
      <td>${escapeHTML(b.Reason || '')}</td>
      <td class="mono" title="${escapeHTML((b.RuleTags || []).join(','))}">${escapeHTML((b.RuleTags || []).map(tagLabel).join(','))}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(b.CreatedTS))}</td>
      <td class="mono" style="white-space:nowrap">${exp}</td>
      <td><span class="pill ${b.CreatedBy === 'auto' ? 'red' : ''}">${b.CreatedBy === 'auto' ? '自动' : (b.CreatedBy === 'manual' ? '手动' : escapeHTML(b.CreatedBy))}</span></td>
      <td><button class="danger" data-kind="${escapeHTML(b.Kind)}" data-target="${escapeHTML(b.Target)}">解封</button></td>
    `;
    ipTbody.appendChild(tr); ipCount++;
  }
  if (!ipCount) ipTbody.innerHTML = '<tr><td colspan="7" class="empty-state">无封禁 IP</td></tr>';
  $$('#ipBanTbody button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('解封 ' + btn.dataset.target + ' ?')) return;
      const r = await apiPost('/api/bans/remove', { kind: btn.dataset.kind, target: btn.dataset.target });
      if (r && r.ok) { toast('已解封', 'success'); loadBans(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}

$('#banIPAddBtn').addEventListener('click', async () => {
  const target = $('#banIPTarget').value.trim();
  if (!target) return toast('IP 不能为空', 'error');
  const r = await apiPost('/api/bans/add', {
    kind: 'ip', target,
    reason: $('#banIPReason').value.trim(),
    ttl: $('#banIPTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banIPTarget').value = ''; $('#banIPReason').value = ''; $('#banIPTTL').value = '';
    toast('已添加', 'success'); loadBans();
  } else toast((r && r.error) || '失败', 'error');
});

// token 黑名单已废弃(v2board 重置 token 后 hash 失效),不再注册按钮。

// ---- 全局黑名单配置(海外/云/ISP/浏览器)----
async function loadBlacklistCfg() {
  const cfg = await api('/api/blacklist');
  if (!cfg) return;
  $('#blOversea').checked = !!cfg.oversea_enabled;
  $('#blCloud').checked = !!cfg.cloud_enabled;
  $('#blCNIDC').checked = !!cfg.cn_idc_enabled;
  $('#blBrowser').checked = !!cfg.browser_enabled;
  $('#blISPKw').value = (cfg.isp_keywords || []).join(', ');
}
$('#blSaveBtn').addEventListener('click', async () => {
  const kw = $('#blISPKw').value.split(',').map(s => s.trim()).filter(Boolean);
  const r = await apiPost('/api/blacklist/save', {
    oversea_enabled: $('#blOversea').checked,
    cloud_enabled: $('#blCloud').checked,
    cn_idc_enabled: $('#blCNIDC').checked,
    browser_enabled: $('#blBrowser').checked,
    isp_keywords: kw,
  });
  if (r && r.ok) toast('已保存', 'success');
  else toast((r && r.msg) || '保存失败', 'error');
});

// ---- IP 白名单 ----
async function loadIPWhitelist() {
  const list = await api('/api/ip-whitelist') || [];
  const tbody = $('#ipWLTbody'); tbody.innerHTML = '';
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">还没有白名单条目</td></tr>';
    return;
  }
  for (const e of list) {
    const tr = document.createElement('tr');
    tr.dataset.id = e.ID;
    tr.dataset.target = e.Target || '';
    tr.dataset.note = e.Note || '';
    tr.innerHTML = `
      <td class="mono ipwl-target">${escapeHTML(e.Target)}</td>
      <td class="ipwl-note">${escapeHTML(e.Note || '')}</td>
      <td class="mono">${escapeHTML(fmtTime(e.CreatedTS))}</td>
      <td class="ipwl-ops">
        <button class="ipwl-edit" data-id="${e.ID}">编辑</button>
        <button class="danger ipwl-del" data-id="${e.ID}">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

// 行内编辑:点'编辑'把两格替换成 input,按钮换'保存/取消'。
$('#ipWLTbody').addEventListener('click', async (ev) => {
  const tr = ev.target.closest('tr'); if (!tr) return;
  const id = parseInt(tr.dataset.id, 10);

  if (ev.target.matches('.ipwl-del')) {
    if (!confirm('删除该白名单?')) return;
    const r = await apiPost('/api/ip-whitelist/remove', { id });
    if (r && r.ok) { toast('已删除', 'success'); loadIPWhitelist(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }

  if (ev.target.matches('.ipwl-edit')) {
    const curTarget = tr.dataset.target;
    const curNote = tr.dataset.note;
    tr.querySelector('.ipwl-target').innerHTML = `<input class="ipwl-edit-target" value="${escapeHTML(curTarget)}" style="width:100%">`;
    tr.querySelector('.ipwl-note').innerHTML = `<input class="ipwl-edit-note" value="${escapeHTML(curNote)}" style="width:100%">`;
    tr.querySelector('.ipwl-ops').innerHTML = `
      <button class="primary ipwl-save" data-id="${id}">保存</button>
      <button class="ipwl-cancel">取消</button>
    `;
    tr.querySelector('.ipwl-edit-target').focus();
    return;
  }

  if (ev.target.matches('.ipwl-cancel')) {
    loadIPWhitelist();
    return;
  }

  if (ev.target.matches('.ipwl-save')) {
    const target = tr.querySelector('.ipwl-edit-target').value.trim();
    const note = tr.querySelector('.ipwl-edit-note').value.trim();
    if (!target) return toast('IP/CIDR 不能为空', 'error');
    const r = await apiPost('/api/ip-whitelist/update', { id, target, note });
    if (r && r.ok) { toast('已保存', 'success'); loadIPWhitelist(); }
    else toast((r && r.error) || '保存失败', 'error');
    return;
  }
});

$('#ipWLAddBtn').addEventListener('click', async () => {
  const target = $('#ipWLTarget').value.trim();
  if (!target) return toast('请输入 IP/CIDR', 'error');
  const r = await apiPost('/api/ip-whitelist/add', { target, note: $('#ipWLNote').value.trim() });
  if (r && r.ok) {
    $('#ipWLTarget').value = ''; $('#ipWLNote').value = '';
    toast('已添加', 'success'); loadIPWhitelist();
  } else toast((r && r.error) || '失败', 'error');
});

// ---- 云 IP ----
async function loadGeoIPInfo() {
  const s = await api('/api/geoip');
  if (!s) return;
  const el = $('#geoipStatus');
  if (s.loaded) {
    el.innerHTML = `已加载 · 版本 <strong>${escapeHTML(s.version || '-')}</strong> · 路径 <code>${escapeHTML(s.path || '-')}</code>`;
  } else {
    el.innerHTML = `<span style="color:var(--danger)">未加载</span> — 请检查 <code>geoip.xdb_path</code> 配置`;
  }
}

function renderGeoInfo(info) {
  // 字段空的不显示,保持精简
  const rows = [
    ['国家', info.country, info.iso_code ? ` (${info.iso_code})` : ''],
    ['省市区', [info.province, info.city, info.district].filter(Boolean).join(' / ')],
    ['ISP', info.isp],
    ['用途', info.usage_type ? `${usageLabel(info.usage_type)} (${info.usage_type})` : ''],
    ['云厂商', info.cloud_provider],
    ['ASN', info.asn],
    ['经纬度', (info.lon && info.lat) ? `${info.lon}, ${info.lat}` : ''],
    ['时区', info.timezone],
    ['邮编', info.zip_code],
  ];
  let html = '<table style="width:100%;border-collapse:collapse"><tbody>';
  for (const [k, v, suffix] of rows) {
    if (!v) continue;
    html += `<tr><td style="padding:6px 12px 6px 0;color:var(--muted);width:90px;vertical-align:top">${k}</td>
             <td style="padding:6px 0"><strong>${escapeHTML(String(v))}</strong>${suffix ? '<span class="muted">' + escapeHTML(suffix) + '</span>' : ''}</td></tr>`;
  }
  html += '</tbody></table>';
  // 云厂商单独标红/橙
  if (info.cloud_provider) {
    html = `<div style="margin-bottom:10px;padding:8px 12px;background:#fff7ed;border-left:3px solid #f97316;border-radius:4px">
      命中云厂商 IP · <strong>${escapeHTML(info.cloud_provider)}</strong>
    </div>` + html;
  }
  return html;
}

$('#cloudCheckBtn').addEventListener('click', async () => {
  const ip = $('#cloudCheckIP').value.trim();
  if (!ip) return;
  const r = await api('/api/geoip/lookup?ip=' + encodeURIComponent(ip));
  const el = $('#geoipResult');
  if (!r) { el.innerHTML = '<span class="muted">请求失败</span>'; return; }
  if (!r.found) {
    el.innerHTML = `<span class="muted">未找到 ${escapeHTML(ip)} 的记录(IP 不在 xdb 库内或格式错误)</span>`;
    return;
  }
  el.innerHTML = renderGeoInfo(r.info);
});
$('#cloudCheckIP').addEventListener('keydown', e => {
  if (e.key === 'Enter') $('#cloudCheckBtn').click();
});

// ---- 设置 ----
async function loadSettings() {
  const c = await api('/api/config');
  if (c) $('#rulesPre').textContent = JSON.stringify({
    detector: c.detector,
    actions: c.actions,
    paths: c.paths,
    faker: c.faker,
  }, null, 2);
}

// ---- 工具(token hash 工具已删除,v2board 重置就失效) ----

// ---- 启动 ----
(async function () {
  await loadTenants();
  loadSummary();
})();

// ---- 机场管理 ----
async function loadTenantsTable() {
  const list = await api('/api/tenants') || [];
  const tbody = $('#tenantsTbody'); tbody.innerHTML = '';
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">还没配置机场,点右上「+ 新增机场」开始</td></tr>';
    return;
  }
  // 同步刷新顶栏 tenantSel,保持其他页机场筛选器同步
  refreshTenantSelector(list);
  for (const t of list) {
    const tr = document.createElement('tr');
    const upPath = t.upstream_path ? escapeHTML(t.upstream_path) : '<span class="muted">(透传)</span>';
    const statusBadge = t.enabled
      ? '<span style="color:#10b981;font-weight:600">● 启用</span>'
      : '<span style="color:#9ca3af">○ 禁用</span>';
    tr.innerHTML = `
      <td><strong>${escapeHTML(t.name)}</strong></td>
      <td class="mono">${escapeHTML(t.subscribe_path)}</td>
      <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(t.upstream)}">${escapeHTML(t.upstream)}</td>
      <td class="mono">${upPath}</td>
      <td>${statusBadge}</td>
      <td>
        <button data-act="edit" data-name="${escapeHTML(t.name)}">编辑</button>
        <button data-act="toggle" data-name="${escapeHTML(t.name)}">${t.enabled ? '禁用' : '启用'}</button>
        <button class="danger" data-act="del" data-name="${escapeHTML(t.name)}">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
  $$('#tenantsTbody button').forEach(btn => {
    btn.addEventListener('click', () => onTenantAction(btn.dataset.act, btn.dataset.name, list));
  });
}

function refreshTenantSelector(list) {
  const sel = $('#tenantSel');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">全部机场</option>';
  for (const t of list) {
    const opt = document.createElement('option');
    opt.value = t.name; opt.textContent = t.name;
    sel.appendChild(opt);
  }
  // 当前选中机场如果还在,保持选中
  if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
}

async function onTenantAction(act, name, list) {
  const t = list.find(x => x.name === name);
  if (!t) return;
  if (act === 'edit') {
    openTenantModal(t);
    return;
  }
  if (act === 'toggle') {
    const r = await apiPost('/api/tenants/save', {
      name: t.name,
      subscribe_path: t.subscribe_path,
      upstream: t.upstream,
      upstream_path: t.upstream_path,
      enabled: !t.enabled,
      original_name: t.name,
    });
    if (r && r.ok) { toast(t.enabled ? '已禁用' : '已启用', 'success'); loadTenantsTable(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }
  if (act === 'del') {
    if (!confirm(`确定删除机场「${name}」? 客户端订阅将立即失效。`)) return;
    const r = await apiPost('/api/tenants/remove', { name });
    if (r && r.ok) { toast('已删除', 'success'); loadTenantsTable(); }
    else toast((r && r.error) || '失败', 'error');
  }
}

function openTenantModal(t) {
  const isEdit = !!t;
  $('#tenantModalTitle').textContent = isEdit ? `编辑机场 - ${t.name}` : '新增机场';
  $('#tenantFormName').value = isEdit ? t.name : '';
  $('#tenantFormSubPath').value = isEdit ? t.subscribe_path : '';
  $('#tenantFormUpstream').value = isEdit ? t.upstream : '';
  $('#tenantFormUpPath').value = isEdit ? (t.upstream_path || '') : '';
  $('#tenantFormEnabled').checked = isEdit ? !!t.enabled : true;
  $('#tenantModal').dataset.originalName = isEdit ? t.name : '';
  $('#tenantModal').style.display = 'flex';
  setTimeout(() => $('#tenantFormName').focus(), 50);
}

function closeTenantModal() { $('#tenantModal').style.display = 'none'; }

$('#tenantAddBtn').addEventListener('click', () => openTenantModal(null));
$('#tenantModalClose').addEventListener('click', closeTenantModal);
$('#tenantFormCancel').addEventListener('click', closeTenantModal);
$('#tenantModal').addEventListener('click', e => {
  if (e.target.id === 'tenantModal') closeTenantModal();
});

$('#tenantFormSave').addEventListener('click', async () => {
  const original = $('#tenantModal').dataset.originalName || '';
  const body = {
    name: $('#tenantFormName').value.trim(),
    subscribe_path: $('#tenantFormSubPath').value.trim(),
    upstream: $('#tenantFormUpstream').value.trim(),
    upstream_path: $('#tenantFormUpPath').value.trim(),
    enabled: $('#tenantFormEnabled').checked,
    original_name: original,
  };
  if (!body.name || !body.subscribe_path || !body.upstream) {
    return toast('机场名、订阅路径、上游地址都必填', 'error');
  }
  const r = await apiPost('/api/tenants/save', body);
  if (r && r.ok) {
    toast(original ? '已更新' : '已新增', 'success');
    closeTenantModal();
    loadTenantsTable();
  } else {
    toast((r && r.error) || '失败', 'error');
  }
});

// ============ 触发规则 ============

const SEV_CN = {}; // 等级已废弃,保留空对象避免外部偶发引用报错

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTs(unix) {
  if (!unix) return '-';
  const d = new Date(unix * 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// 把 API 规则压成一行人话摘要,放表格里看。
function ruleSummary(r) {
  const parts = [];
  const fmt = (label, win, gte, suffix) => {
    if (win > 0 && gte > 0) {
      parts.push(`<strong>${label}</strong> ${win}s/${gte}${suffix}`);
    }
  };
  fmt('Tok频', r.token_freq_window_sec, r.token_freq_gte, '次');
  fmt('IP频',  r.ip_freq_window_sec, r.ip_freq_gte, '次');
  fmt('Tok×IP', r.token_distinct_ips_window_sec, r.token_distinct_ips_gte, 'IP');
  fmt('IP×Tok', r.ip_distinct_tokens_window_sec, r.ip_distinct_tokens_gte, 'Tok');
  if (r.from_cloud_ip) parts.push('<strong>云IP</strong>');
  if (r.country_in && r.country_in.length) parts.push(`<strong>国家∈</strong>${r.country_in.join(',')}`);
  if (r.country_not_in && r.country_not_in.length) parts.push(`<strong>国家∉</strong>${r.country_not_in.join(',')}`);
  if (r.usage_type_in && r.usage_type_in.length) parts.push(`<strong>用途∈</strong>${r.usage_type_in.map(usageLabel).join(',')}`);
  if (r.usage_type_not_in && r.usage_type_not_in.length) parts.push(`<strong>用途∉</strong>${r.usage_type_not_in.map(usageLabel).join(',')}`);
  if (r.isp_contains && r.isp_contains.length) parts.push(`<strong>ISP⊇</strong>${r.isp_contains.join(',')}`);
  return parts.length ? parts.join(' · ') : '<span style="color:#dc2626">⚠ 无任何条件</span>';
}

async function loadRulesTable() {
  const r = await api('/api/detect_rules');
  const tbody = $('#rulesTbody'); tbody.innerHTML = '';
  if (!Array.isArray(r) || !r.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">暂无规则,点右上角「+ 新增规则」开始</td></tr>';
    return;
  }
  for (const x of r) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escapeHtml(x.name)}</td>
      <td>${escapeHtml(x.desc || '-')}</td>
      <td class="rule-summary">${ruleSummary(x)}</td>
      <td>${x.enabled ? '✓' : '<span style="color:#9ca3af">×</span>'}</td>
      <td class="mono" style="color:#6b7280">${fmtTs(x.updated_ts)}</td>
      <td>
        <button data-act="edit"   data-name="${escapeHtml(x.name)}">编辑</button>
        <button data-act="toggle" data-name="${escapeHtml(x.name)}">${x.enabled ? '禁用' : '启用'}</button>
        <button data-act="delete" data-name="${escapeHtml(x.name)}" class="danger">删除</button>
      </td>`;
    tbody.appendChild(tr);
  }
  $$('#rulesTbody button').forEach(btn => {
    btn.addEventListener('click', () => onRuleAction(btn.dataset.act, btn.dataset.name, r));
  });
}

async function onRuleAction(act, name, list) {
  const item = list.find(x => x.name === name);
  if (!item) return;
  if (act === 'edit') { openRuleModal(item); return; }
  if (act === 'toggle') {
    const body = { ...item, enabled: !item.enabled, original_name: item.name };
    const r = await apiPost('/api/detect_rules/save', body);
    if (r && r.ok) { toast(item.enabled ? '已禁用' : '已启用', 'success'); loadRulesTable(); }
    else toast((r && r.error) || '失败', 'error');
    return;
  }
  if (act === 'delete') {
    if (!confirm(`确认删除规则 ${name}?(立即热生效,不可撤销)`)) return;
    const r = await apiPost('/api/detect_rules/remove', { name });
    if (r && r.ok) { toast('已删除', 'success'); loadRulesTable(); }
    else toast((r && r.error) || '失败', 'error');
  }
}

function listToCSV(list) { return (list && list.length) ? list.join(', ') : ''; }
function csvToList(s) {
  return String(s || '').split(/[,，\s]+/).map(x => x.trim()).filter(Boolean);
}

function openRuleModal(r) {
  const isEdit = !!r;
  $('#ruleModalTitle').textContent = isEdit ? `编辑规则 - ${r.name}` : '新增规则';
  const set = (id, v) => { $('#' + id).value = v == null ? '' : v; };
  set('ruleFormName',          isEdit ? r.name : '');
  set('ruleFormDesc',          isEdit ? r.desc : '');
  // 等级字段已废弃,命中即投毒。
  set('ruleFormTfWin',         isEdit ? (r.token_freq_window_sec || '') : '');
  set('ruleFormTfGte',         isEdit ? (r.token_freq_gte || '') : '');
  set('ruleFormIfWin',         isEdit ? (r.ip_freq_window_sec || '') : '');
  set('ruleFormIfGte',         isEdit ? (r.ip_freq_gte || '') : '');
  set('ruleFormTdWin',         isEdit ? (r.token_distinct_ips_window_sec || '') : '');
  set('ruleFormTdGte',         isEdit ? (r.token_distinct_ips_gte || '') : '');
  set('ruleFormIdWin',         isEdit ? (r.ip_distinct_tokens_window_sec || '') : '');
  set('ruleFormIdGte',         isEdit ? (r.ip_distinct_tokens_gte || '') : '');
  set('ruleFormCountryIn',     isEdit ? listToCSV(r.country_in) : '');
  set('ruleFormCountryNotIn',  isEdit ? listToCSV(r.country_not_in) : '');
  set('ruleFormUsageIn',       isEdit ? listToCSV(r.usage_type_in) : '');
  set('ruleFormUsageNotIn',    isEdit ? listToCSV(r.usage_type_not_in) : '');
  set('ruleFormISP',           isEdit ? listToCSV(r.isp_contains) : '');
  $('#ruleFormFromCloud').checked = isEdit ? !!r.from_cloud_ip : false;
  const enabledOn = isEdit ? !!r.enabled : true;
  $('#ruleFormEnabledOn').checked  = enabledOn;
  $('#ruleFormEnabledOff').checked = !enabledOn;
  $('#ruleModal').dataset.originalName = isEdit ? r.name : '';
  $('#ruleModal').dataset.sortOrder = isEdit ? String(r.sort_order || 0) : '0';
  $('#ruleModal').style.display = 'flex';
}

function closeRuleModal() { $('#ruleModal').style.display = 'none'; }

$('#ruleAddBtn').addEventListener('click', () => openRuleModal(null));
$('#ruleModalClose').addEventListener('click', closeRuleModal);
$('#ruleFormCancel').addEventListener('click', closeRuleModal);
$('#ruleModal').addEventListener('click', e => {
  if (e.target.id === 'ruleModal') closeRuleModal();
});

$('#ruleFormSave').addEventListener('click', async () => {
  const num = id => {
    const v = parseInt($('#' + id).value, 10);
    return isNaN(v) || v < 0 ? 0 : v;
  };
  const name = $('#ruleFormName').value.trim();
  if (!name) { toast('规则名必填', 'error'); return; }
  const body = {
    original_name:                     $('#ruleModal').dataset.originalName || '',
    name,
    desc:                              $('#ruleFormDesc').value.trim(),
    enabled:                           $('#ruleFormEnabledOn').checked,
    sort_order:                        parseInt($('#ruleModal').dataset.sortOrder || '0', 10),
    token_freq_window_sec:             num('ruleFormTfWin'),
    token_freq_gte:                    num('ruleFormTfGte'),
    ip_freq_window_sec:                num('ruleFormIfWin'),
    ip_freq_gte:                       num('ruleFormIfGte'),
    token_distinct_ips_window_sec:     num('ruleFormTdWin'),
    token_distinct_ips_gte:            num('ruleFormTdGte'),
    ip_distinct_tokens_window_sec:     num('ruleFormIdWin'),
    ip_distinct_tokens_gte:            num('ruleFormIdGte'),
    from_cloud_ip:                     $('#ruleFormFromCloud').checked,
    country_in:                        csvToList($('#ruleFormCountryIn').value),
    country_not_in:                    csvToList($('#ruleFormCountryNotIn').value),
    usage_type_in:                     csvToList($('#ruleFormUsageIn').value),
    usage_type_not_in:                 csvToList($('#ruleFormUsageNotIn').value),
    isp_contains:                      csvToList($('#ruleFormISP').value),
  };
  const r = await apiPost('/api/detect_rules/save', body);
  if (r && r.ok) {
    toast('已保存,热生效中', 'success');
    closeRuleModal();
    loadRulesTable();
  } else {
    toast((r && r.error) || '失败', 'error');
  }
});

// ────────────────────────────────────────────────
// 修改密码 + 一键透传(设置页)
// ────────────────────────────────────────────────
async function loadPassthrough() {
  const r = await api('/api/settings/passthrough');
  if (!r) return;
  const cb = $('#passthroughToggle');
  const lbl = $('#passthroughLabel');
  const pill = $('#passthroughStatusPill');
  if (!cb) return;
  cb.checked = !!r.enabled;
  lbl.textContent = r.enabled ? '已开启' : '已关闭';
  pill.style.display = r.enabled ? '' : 'none';
}

$('#pwSaveBtn')?.addEventListener('click', async () => {
  const oldP = $('#pwOld').value;
  const newP = $('#pwNew').value;
  const newP2 = $('#pwNew2').value;
  if (!oldP || !newP) { toast('请填写原密码和新密码', 'error'); return; }
  if (newP.length < 8) { toast('新密码至少 8 位', 'error'); return; }
  if (newP !== newP2) { toast('两次输入的新密码不一致', 'error'); return; }
  const r = await apiPost('/api/auth/change_password', { old_password: oldP, new_password: newP });
  if (r && r.ok) {
    toast('密码已修改,即将退出登录…', 'success');
    setTimeout(() => { location.href = '/login'; }, 1500);
  } else {
    toast((r && r.error) || '修改失败', 'error');
  }
});

$('#passthroughToggle')?.addEventListener('change', async (e) => {
  const want = e.target.checked;
  const msg = want
    ? '⚠️ 开启「一键透传」后,黑名单/触发规则/投毒全部失效,所有请求直接转发到上游。\n\n确认开启?'
    : '关闭「一键透传」,恢复全部规则。\n\n确认关闭?';
  if (!confirm(msg)) {
    e.target.checked = !want;
    return;
  }
  const r = await apiPost('/api/settings/passthrough', { enabled: want });
  if (r && r.ok) {
    toast(want ? '一键透传已开启' : '一键透传已关闭', want ? 'warning' : 'success');
    loadPassthrough();
  } else {
    e.target.checked = !want;
    toast((r && r.error) || '失败', 'error');
  }
});

// ════════════════════════════════════════════════════
// 交互打磨:进度条 / 搜索高亮 / 快捷键 / 验证 / loading
// ════════════════════════════════════════════════════

// ─── 1. 全局进度条(monkey-patch fetch) ───
(function () {
  const bar = document.getElementById('progressBar');
  let inflight = 0;
  const origFetch = window.fetch;
  window.fetch = function (...args) {
    inflight++;
    if (inflight === 1) { bar.className = 'progress-bar loading'; bar.style.width = ''; }
    return origFetch.apply(this, args).finally(() => {
      inflight--;
      if (inflight <= 0) {
        inflight = 0;
        bar.classList.remove('loading');
        bar.classList.add('done');
        setTimeout(() => { bar.className = 'progress-bar'; bar.style.width = '0'; }, 500);
      }
    });
  };
})();

// ─── 2. 搜索高亮:事件卡片内 IP/Token 匹配词标亮 ───
(function () {
  const origLoadEvents = window.loadEvents || loadEvents;
  // 重写 loadEvents 加高亮后处理
  const _origLoadEventsRef = loadEvents;
  const patchedLoadEvents = async function (append) {
    await _origLoadEventsRef(append);
    highlightEventCards();
  };
  // 替换全局引用
  window.loadEvents = patchedLoadEvents;
  // 同时 patch 查询按钮
  $('#evQuery').removeEventListener('click', null); // 无法直接移除,改用下面的重绑
  $('#evQuery').addEventListener('click', () => patchedLoadEvents(false), true);

  function highlightEventCards() {
    const ipVal = ($('#evIP').value || '').trim();
    const tokVal = ($('#evToken').value || '').trim();
    if (!ipVal && !tokVal) return;
    const list = $('#evList');
    if (!list) return;
    const keywords = [];
    if (ipVal) keywords.push(ipVal);
    if (tokVal) keywords.push(tokVal);
    // walk text nodes inside ev-cards
    const walker = document.createTreeWalker(list, NodeFilter.SHOW_TEXT);
    const hits = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      for (const kw of keywords) {
        if (node.nodeValue && node.nodeValue.includes(kw)) {
          hits.push({ node, kw });
          break;
        }
      }
    }
    for (const { node, kw } of hits) {
      const parent = node.parentNode;
      if (!parent || parent.tagName === 'MARK') continue;
      const parts = node.nodeValue.split(kw);
      const frag = document.createDocumentFragment();
      parts.forEach((p, i) => {
        if (i > 0) {
          const mark = document.createElement('mark');
          mark.className = 'hl';
          mark.textContent = kw;
          frag.appendChild(mark);
        }
        if (p) frag.appendChild(document.createTextNode(p));
      });
      parent.replaceChild(frag, node);
    }
  }
})();

// ─── 3. 键盘快捷键 ───
document.addEventListener('keydown', (e) => {
  // 忽略:在 input/textarea/select 中时只响应 Esc
  const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);

  // Esc 关弹窗
  if (e.key === 'Escape') {
    const modals = ['#tenantModal', '#ruleModal'];
    for (const sel of modals) {
      const m = document.querySelector(sel);
      if (m && m.style.display === 'flex') {
        m.style.display = 'none';
        e.preventDefault();
        return;
      }
    }
    // Esc 还可以 blur 当前输入框
    if (inInput) { document.activeElement.blur(); e.preventDefault(); }
    return;
  }

  if (inInput) return;

  // R = 刷新当前 tab
  if (e.key === 'r' || e.key === 'R') {
    e.preventDefault();
    $('#refreshBtn').click();
    return;
  }
  // / = 聚焦事件搜索 IP 输入框(如果在事件页)
  if (e.key === '/') {
    const evTab = document.getElementById('tab-events');
    if (evTab && evTab.classList.contains('active')) {
      e.preventDefault();
      $('#evIP').focus();
    }
    return;
  }
});

// ─── 4. 表单验证:shake + 红框 ───
function validateRequired(el, msg) {
  if (!el.value.trim()) {
    el.classList.add('input-error');
    el.closest('form, .card, .modal-body, section')?.classList.add('shake');
    toast(msg || '此项不能为空', 'error');
    el.focus();
    setTimeout(() => {
      el.classList.remove('input-error');
      el.closest('.shake')?.classList.remove('shake');
    }, 800);
    return false;
  }
  return true;
}
// 暴露给可能需要用的地方
window.validateRequired = validateRequired;

// ─── 5. 按钮 loading 态工具函数 ───
function withLoading(btn, asyncFn) {
  if (btn.classList.contains('loading')) return;
  btn.classList.add('loading');
  asyncFn().finally(() => btn.classList.remove('loading'));
}
window.withLoading = withLoading;

// 给刷新按钮加 loading
(function () {
  const origClick = $('#refreshBtn').onclick;
  $('#refreshBtn').addEventListener('click', function () {
    withLoading(this, async () => {
      const active = document.querySelector('.navlink.active');
      if (active && TAB_LOADERS[active.dataset.tab]) {
        await TAB_LOADERS[active.dataset.tab]();
      }
    });
  }, true);
})();

// 给事件「查询」按钮加 loading
(function () {
  const btn = $('#evQuery');
  if (!btn) return;
  btn.addEventListener('click', function () {
    withLoading(this, () => loadEvents(false));
  }, true);
})();
