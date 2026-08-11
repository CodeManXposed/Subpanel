// Sub-Panel web UI

const state = { tenant: '', window: '168h' };

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
  rate_limit: '限流',
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
  'ip_whitelist':   '白名单（旧版放行）',
  'ip_whitelist_multi_token_exempt': '白名单·豁免多Token',
  'banlist_ip':     'IP 黑名单',
  'banlist_token':  'Token 黑名单',
  'path_not_match': '路径不匹配',
  // 上游
  'upstream_bad':   '上游异常',
  'global_rate_limit': '全局速率保护',
  'upstream_concurrency_limit': '源站并发保护',
  'ip_upstream_concurrency': '单 IP 并发保护',
  // 触发规则
  'token_freq':           '单 token 频次',
  'ip_freq':              '单 IP 频次',
  'token_distinct_ips':   '单 token 多 IP',
  'ip_distinct_tokens':   '单 IP 多 token',
  'cloud_token_distinct_uas': '云 IP 单 token 多 UA',
  'cloud_ua_probe':        '云 IP 多 UA 测活',
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

const CLOUD_PROVIDER_LABEL = {
  aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', oracle: 'Oracle Cloud',
  aliyun: '阿里云', tencent: '腾讯云', huawei: '华为云', bytedance: '火山/字节云',
  baidu: '百度云', jdcloud: '京东云', kingsoft: '金山云', ucloud: 'UCloud', qingcloud: '青云',
  vultr: 'Vultr', digitalocean: 'DigitalOcean', linode: 'Linode/Akamai',
  hetzner: 'Hetzner', ovh: 'OVH', cloudflare: 'Cloudflare', akamai: 'Akamai', fastly: 'Fastly',
};
function cloudProviderLabel(p) { return CLOUD_PROVIDER_LABEL[p] || p || ''; }

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
  'resolved': 'Token 黑名单',
  'ip-bans': 'IP / 全局黑名单',
  'ip-whitelist': 'IP 白名单',
  'cloud-ip': 'GeoIP 库',
  'detect-rules': '触发规则',
  'suspects': '嫌疑用户',
  'aws-suspects': '嫌疑用户（By AWS）',
  'panel-analysis': '面板强检测',
  'aws-ip-changes': 'AWS 换IP追踪',
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
  'detect-rules': () => { loadRulesTable(); loadUAWhitelist(); },
  'suspects': () => loadSuspects(),
  'aws-suspects': () => loadAWSSuspects(),
  'panel-analysis': () => loadPanelAnalysisPage(),
  'aws-ip-changes': () => loadAWSIPChanges(),
  'tenants': () => loadTenantsTable(),
  'settings': () => { loadSettings(); loadCDNSettings(); loadPassthrough(); loadReportSecret(); },
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
    document.body.classList.remove('mobile-nav-open');
    if (TAB_LOADERS[tab]) TAB_LOADERS[tab]();
  });
});

function setMobileNav(open) {
  document.body.classList.toggle('mobile-nav-open', Boolean(open));
}
$('#mobileMenuBtn').addEventListener('click', () => setMobileNav(true));
$('#sidebarCloseBtn').addEventListener('click', () => setMobileNav(false));
$('#sidebarBackdrop').addEventListener('click', () => setMobileNav(false));
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') setMobileNav(false);
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
    ['rate-limit', '限流 429', s.rate_limit],
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
    const isp = k.isp ? escapeHTML(k.isp) : '<span class="muted">未知</span>';
    tr.innerHTML = `<td><div class="dashboard-ip-cell"><span class="mono" title="${escapeHTML(k.key)}">${escapeHTML(k.key)}</span>${k.whitelisted ? '<span class="dashboard-whitelist-pill" title="仅豁免单 IP 多 Token 检测；高频请求及其他规则继续生效">白名单</span>' : ''}</div></td><td title="${escapeHTML(k.region || '未知')}">${k.region ? escapeHTML(k.region) : '<span class="muted">未知</span>'}</td><td title="${escapeHTML(k.isp || '未知')}">${isp}</td><td style="text-align:right" class="mono">${k.count}</td>`;
    ipTbody.appendChild(tr);
  });
  const tokTbody = $('#topTokens tbody'); tokTbody.innerHTML = '';
  (s.top_tokens || []).forEach(k => {
    const tr = document.createElement('tr');
    const site = String(k.tenant || '-').toLowerCase();
    const shown = `(${site})${k.key || ''}`;
    tr.innerHTML = `<td><div class="dashboard-token-cell"><span class="mono" title="${escapeHTML(shown)}">${escapeHTML(shown)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(k.key || '')}" title="只复制原始 Token">复制</button></div></td><td style="text-align:right" class="mono">${k.count}</td>`;
    tokTbody.appendChild(tr);
  });
  bindCopyHandlers(tokTbody);
}

// ---- events ----
const EV_PAGE_SIZE = 50;
let evOffset = 0;

function renderEventCard(e) {
  const card = document.createElement('div');
  card.className = `ev-card${e.UAUncommon ? ' ev-card-uncommon-ua' : ''}`;
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
	? `<span class="pill usage ${escapeHTML(String(e.Usage).toLowerCase())}" title="${escapeHTML(e.UsageSource === 'inferred' ? '根据 ISP/ASN 推断' : e.Usage)}">${escapeHTML(usageLabel(e.Usage))}${e.UsageSource === 'inferred' ? ' *' : ''}</span>`
	: '';
  const cloudBit = e.CloudProvider
    ? `<span class="pill red" title="命中云厂商 ASN">云厂商 · ${escapeHTML(cloudProviderLabel(e.CloudProvider))}</span>`
    : '';
  const clientMismatchBit = e.ClientMatch === 'mismatch'
    ? `<span class="pill red" title="订阅后缀：${escapeHTML(e.SuffixClient || e.Flag || '未知')}；实际 UA：${escapeHTML(e.UAClient || '未知')}">后缀 ≠ UA</span>`
    : '';
  const uncommonUABit = e.UAUncommon
    ? '<span class="pill orange" title="未命中常规订阅客户端 UA 库，仅作风险提示">非常见 UA</span>'
    : '';
  // 拉黑 Token:仅当有 token 时显示。data-tenant 用事件自己的 tenant(不是当前过滤)。
  const resolveBtn = tokenFull
    ? `<button class="danger ev-token-block" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(e.Tenant || '')}" title="将此 Token 加入黑名单">拉黑 Token</button>`
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
      ${e.ReTriggered ? '<span class="pill red">⚠ 历史处理后再次触发</span>' : ''}
      ${e.Focused ? '<span class="pill red">⚠ 重点关注对象行为</span>' : ''}
      ${cloudBit}
      ${clientMismatchBit}
      ${uncommonUABit}
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
	  <span class="ev-meta-item"><span class="ev-label">ASN</span><span class="mono">${e.ASN ? escapeHTML(e.ASN) : '—'}</span>${e.ASNOrg ? `<span title="${escapeHTML(e.ASNOrg)}"> · ${escapeHTML(e.ASNOrg)}</span>` : ''}</span>
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
    cloud: $('#evCloud').value,
    client_match: $('#evClientMatch').value,
    provider: $('#evProvider').value,
    asn: $('#evASN').value.trim(),
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

// 事件卡片 Token 拉黑 / 重置窗口：事件委托。
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
  const btn = e.target.closest('.ev-token-block');
  if (!btn) return;
  const token = btn.dataset.token || '';
  const tenant = btn.dataset.tenant || '';
  if (!token) return;
  openTokenBlockModal(token, tenant, 'events');
});

// ---- 已拉黑 Token 列表 ----
async function loadResolved() {
  const q = new URLSearchParams();
  if (state.tenant) q.set('tenant', state.tenant);
  const rows = await api('/api/token-blocks' + (q.toString() ? '?' + q : ''));
  const tbody = $('#resolvedTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">暂无拉黑 Token</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr = document.createElement('tr');
    const action = r.action === 'deny' ? 'deny' : 'fake';
    const exp = r.expires_ts ? fmtTime(new Date(r.expires_ts)) : '<span style="color:var(--danger)">永久</span>';
    tr.innerHTML = `
      <td class="mono copyable" data-copy="${escapeHTML(r.token)}" title="点击复制">${escapeHTML(r.token)}</td>
      <td>${escapeHTML(r.tenant || '-')}</td>
      <td><span class="pill ${action}">${action === 'deny' ? '全拒绝 · 403' : '全投毒 · 200'}</span></td>
      <td>${escapeHTML(r.reason || '-')}</td>
      <td class="mono">${escapeHTML(fmtTime(new Date(r.created_ts)))}</td>
      <td class="mono">${exp}</td>
      <td><button class="danger res-restore" data-token="${escapeHTML(r.token)}">解除拉黑</button></td>
    `;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}
$('#resolvedTbody')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('.res-restore');
  if (!btn) return;
  if (!confirm('解除后此 Token 将恢复到正常检测流程，并重新出现在嫌疑/请求列表，确定？')) return;
  const r = await apiPost('/api/token-blocks/remove', { token: btn.dataset.token });
  if (r && r.ok) loadResolved();
  else alert('解除失败:' + (r && r.error ? r.error : '未知错误'));
});

let tokenBlockContext = null;

function openTokenBlockModal(token, tenant, source) {
  tokenBlockContext = { token, tenant: tenant || '', source: source || '' };
  $('#tokenBlockValue').textContent = token;
  $('#tokenBlockCopy').dataset.copy = token;
  $('#tokenBlockAction').value = 'fake';
  $('#tokenBlockReason').value = '';
  $('#tokenBlockTTL').value = '';
  $('#tokenBlockModal').style.display = 'flex';
  bindCopyHandlers($('#tokenBlockModal'));
}

function closeTokenBlockModal() {
  $('#tokenBlockModal').style.display = 'none';
  tokenBlockContext = null;
}

$('#tokenBlockClose')?.addEventListener('click', closeTokenBlockModal);
$('#tokenBlockCancel')?.addEventListener('click', closeTokenBlockModal);
$('#tokenBlockModal')?.addEventListener('click', e => {
  if (e.target.id === 'tokenBlockModal') closeTokenBlockModal();
});
$('#tokenBlockConfirm')?.addEventListener('click', async e => {
  if (!tokenBlockContext) return;
  const btn = e.currentTarget;
  btn.classList.add('loading');
  const action = $('#tokenBlockAction').value === 'deny' ? 'deny' : 'fake';
  const r = await apiPost('/api/token-blocks/add', {
    token: tokenBlockContext.token,
    tenant: tokenBlockContext.tenant,
    action,
    reason: $('#tokenBlockReason').value.trim(),
    ttl: $('#tokenBlockTTL').value.trim(),
  });
  btn.classList.remove('loading');
  if (!r || !r.ok) {
    toast((r && r.error) || '拉黑失败', 'error');
    return;
  }
  const source = tokenBlockContext.source;
  closeTokenBlockModal();
  toast(action === 'deny' ? 'Token 已拉黑：全拒绝' : 'Token 已拉黑：全投毒', 'success');
  if (source === 'events') loadEvents(false);
  if (source === 'suspects' || source === 'focus') loadSuspects();
  if (source === 'aws-suspects') loadAWSSuspects();
  if (source === 'panel-analysis') runPanelAnalysis(panelAnalysisOffset);
  if (document.querySelector('.navlink.active')?.dataset.tab === 'resolved') loadResolved();
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
      const r = await apiPost('/api/bans/add', { kind: 'ip', target: ip, action: 'deny', reason: '请求日志页手动 REJECT' });
      if (r && r.ok) { toast('已封禁 ' + ip, 'success'); }
      else { toast((r && r.error) || '封禁失败', 'error'); }
    });
  });
}

// ---- IP / Token 黑名单 ----
async function loadBans() {
  await loadBlacklistCfg();
  const bs = await api('/api/bans');
  if (!bs) return;
  const ipTbody = $('#ipBanTbody'); ipTbody.innerHTML = '';
  let ipCount = 0;
  for (const b of bs || []) {
    const exp = b.ExpiresTS ? fmtTime(b.ExpiresTS) : '<span style="color:var(--danger)">永久</span>';
    const tr = document.createElement('tr');
    if (b.Kind === 'token') {
      continue;
    }
    if (b.Kind !== 'ip') continue;
    const action = b.Action === 'deny' ? 'deny' : 'fake';
    tr.innerHTML = `
      <td class="mono" title="${escapeHTML(b.Target)}">${escapeHTML(b.Target)}</td>
      <td><span class="pill ${action}">${action === 'deny' ? 'REJECT · 403' : '投毒 · 200'}</span></td>
      <td>${escapeHTML(b.Reason || '')}</td>
      <td class="mono" title="${escapeHTML((b.RuleTags || []).join(','))}">${escapeHTML((b.RuleTags || []).map(tagLabel).join(','))}</td>
      <td class="mono" style="white-space:nowrap">${escapeHTML(fmtTime(b.CreatedTS))}</td>
      <td class="mono" style="white-space:nowrap">${exp}</td>
      <td><span class="pill ${b.CreatedBy === 'auto' ? 'red' : ''}">${b.CreatedBy === 'auto' ? '自动' : (b.CreatedBy === 'manual' ? '手动' : escapeHTML(b.CreatedBy))}</span></td>
      <td><button class="danger" data-kind="${escapeHTML(b.Kind)}" data-target="${escapeHTML(b.Target)}">解封</button></td>
    `;
    ipTbody.appendChild(tr); ipCount++;
  }
  if (!ipCount) ipTbody.innerHTML = '<tr><td colspan="8" class="empty-state">无封禁 IP</td></tr>';
  $$('#ipBanTbody button.danger').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('解除 ' + (btn.dataset.kind === 'token' ? 'Token ' : 'IP ') + btn.dataset.target + ' ?')) return;
      const r = await apiPost('/api/bans/remove', { kind: btn.dataset.kind, target: btn.dataset.target });
      if (r && r.ok) { toast('已解除', 'success'); loadBans(); }
      else toast((r && r.error) || '失败', 'error');
    });
  });
}

$('#banIPAddBtn').addEventListener('click', async () => {
  const target = $('#banIPTarget').value.trim();
  if (!target) return toast('IP 不能为空', 'error');
  const r = await apiPost('/api/bans/add', {
    kind: 'ip', target,
    action: $('#banIPAction').value === 'fake' ? 'fake' : 'deny',
    reason: $('#banIPReason').value.trim(),
    ttl: $('#banIPTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banIPTarget').value = ''; $('#banIPReason').value = ''; $('#banIPTTL').value = '';
    const updated = Number(r.updated || 0);
    const actionText = r.action === 'deny' ? 'REJECT' : '投毒';
    toast(`已按 ${actionText} 新增 ${r.added || 0} 个${updated ? `，更新 ${updated} 个` : ''}`, 'success'); loadBans();
  } else toast((r && r.error) || '失败', 'error');
});

$('#banTokenAddBtn').addEventListener('click', async () => {
  const target = $('#banTokenTarget').value.trim();
  if (!target) return toast('Token 不能为空', 'error');
  const action = $('#banTokenAction').value === 'deny' ? 'deny' : 'fake';
  const r = await apiPost('/api/bans/add', {
    kind: 'token', target, action,
    reason: $('#banTokenReason').value.trim(),
    ttl: $('#banTokenTTL').value.trim(),
  });
  if (r && r.ok) {
    $('#banTokenTarget').value = '';
    $('#banTokenReason').value = '';
    $('#banTokenTTL').value = '';
    const updated = Number(r.updated || 0);
    const actionText = action === 'deny' ? '全拒绝' : '全投毒';
    toast(`已${actionText}拉黑 ${r.added || 0} 个${updated ? `，更新 ${updated} 个` : ''}`, 'success');
    loadResolved();
  } else toast((r && r.error) || '失败', 'error');
});

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
  await loadDomainWhitelist();
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

async function loadDomainWhitelist() {
  const list = await api('/api/ip-whitelist/domains') || [];
  const tbody = $('#domainWLTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">还没有域名白名单</td></tr>';
    return;
  }
  for (const e of list) {
    const tr = document.createElement('tr');
    const ips = (e.ResolvedIPs || []).map(ip => `<span class="pill tag mono">${escapeHTML(ip)}</span>`).join(' ') || '<span class="muted">暂无结果</span>';
    tr.innerHTML = `<td class="mono">${escapeHTML(e.Domain)}</td><td>${ips}${e.LastError ? `<div style="color:var(--red);font-size:11px;margin-top:4px">${escapeHTML(e.LastError)}</div>` : ''}</td><td>${escapeHTML(e.Note || '')}</td><td class="mono">${e.LastResolvedTS ? escapeHTML(fmtTime(new Date(e.LastResolvedTS))) : '-'}</td><td><button class="danger domain-wl-del" data-id="${e.ID}">删除</button></td>`;
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

$('#domainWLAddBtn').addEventListener('click', async () => {
  const domain = $('#domainWLTarget').value.trim();
  if (!domain) return toast('请输入域名', 'error');
  const r = await apiPost('/api/ip-whitelist/domains/add', { domain, note: $('#domainWLNote').value.trim() });
  if (r && r.ok) {
    $('#domainWLTarget').value = ''; $('#domainWLNote').value = '';
    toast('域名白名单已添加', 'success'); loadIPWhitelist();
  } else toast((r && r.error) || '添加失败', 'error');
});

$('#domainWLRefreshBtn').addEventListener('click', async () => {
  const r = await apiPost('/api/ip-whitelist/domains/refresh', {});
  if (r && r.ok) { toast('解析完成', 'success'); loadIPWhitelist(); }
  else toast((r && r.error) || '解析失败', 'error');
});

$('#domainWLTbody').addEventListener('click', async (e) => {
  const btn = e.target.closest('.domain-wl-del');
  if (!btn || !confirm('删除这个域名及其动态白名单 IP？')) return;
  const r = await apiPost('/api/ip-whitelist/domains/remove', { id: Number(btn.dataset.id) });
  if (r && r.ok) { toast('已删除', 'success'); loadIPWhitelist(); }
});

// ---- 云 IP ----
async function loadGeoIPInfo() {
  const s = await api('/api/geoip');
  if (!s) return;
  const el = $('#geoipStatus');
  if (s.loaded) {
	const asn = s.asn_loaded ? ` · ASN <strong>${Number(s.asn_records || 0).toLocaleString()}</strong> 条` : ' · <span style="color:var(--danger)">ASN 未加载</span>';
	el.innerHTML = `已加载 · 版本 <strong>${escapeHTML(s.version || '-')}</strong>${asn} · 路径 <code>${escapeHTML(s.path || '-')}</code>`;
  } else {
    el.innerHTML = `<span style="color:var(--danger)">未加载</span> — 请检查 <code>geoip.xdb_path</code> 配置`;
  }
}

function renderIPPolicy(policy) {
  if (!policy) return '';
  const badges = [];
  if (policy.whitelisted) badges.push('<span class="geo-policy-badge allow">IP 白名单 · 仅豁免多 Token</span>');
  if (policy.ip_blacklisted) {
    const ipAction = policy.ip_blacklist_action === 'deny' ? 'REJECT · 403' : '投毒 · 200';
    badges.push(`<span class="geo-policy-badge deny" title="${escapeHTML(policy.ip_blacklist_reason || '')}">手工 IP 黑名单 · ${ipAction}${policy.ip_blacklist_reason ? ' · ' + escapeHTML(policy.ip_blacklist_reason) : ''}</span>`);
  }
  for (const rawHit of (policy.global_hits || [])) {
    let hit = String(rawHit || '');
    if (hit.startsWith('云厂商 IP · ')) hit = '云厂商 IP · ' + cloudProviderLabel(hit.slice('云厂商 IP · '.length));
    badges.push(`<span class="geo-policy-badge warn">全局黑名单 · ${escapeHTML(hit)}</span>`);
  }
  if (!badges.length) return '<div class="geo-policy-strip clear"><span>策略状态</span><strong>未命中 IP 黑名单、IP 白名单或已开启的全局 IP 拦截</strong></div>';
  return `<div class="geo-policy-strip${policy.whitelisted ? ' whitelisted' : ''}"><span>策略状态</span><div>${badges.join('')}</div>${policy.whitelisted ? '<small>仅跳过单 IP 多 Token 条件；其余命中仍按对应动作处理</small>' : ''}</div>`;
}

function renderGeoInfo(info, policy) {
  // 字段空的不显示,保持精简
  const rows = [
    ['国家', info.country, info.iso_code ? ` (${info.iso_code})` : ''],
    ['省市区', [info.province, info.city, info.district].filter(Boolean).join(' / ')],
    ['ISP', info.isp],
	['用途', info.usage_type ? `${usageLabel(info.usage_type)} (${info.usage_type})${info.usage_type_source === 'inferred' ? ' · 推断' : ''}` : ''],
	['云厂商', info.cloud_provider ? cloudProviderLabel(info.cloud_provider) : ''],
	['ASN', info.asn],
	['ASN 组织', info.asn_org],
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
      命中云厂商 IP · <strong>${escapeHTML(cloudProviderLabel(info.cloud_provider))}</strong>
    </div>` + html;
  }
  return renderIPPolicy(policy) + html;
}

$('#cloudCheckBtn').addEventListener('click', async () => {
  const ip = $('#cloudCheckIP').value.trim();
  if (!ip) return;
  const r = await api('/api/geoip/lookup?ip=' + encodeURIComponent(ip));
  const el = $('#geoipResult');
  if (!r) { el.innerHTML = '<span class="muted">请求失败</span>'; return; }
  if (!r.found) {
    el.innerHTML = renderIPPolicy(r.policy) + `<div class="muted geo-not-found">未找到 ${escapeHTML(ip)} 的 GeoIP 记录（IP 不在 xdb 库内或格式错误）</div>`;
    return;
  }
  el.innerHTML = renderGeoInfo(r.info, r.policy);
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

function renderList(items) {
  if (!items || !items.length) return '<span class="muted">未配置</span>';
  return items.map(x => `<code>${escapeHTML(x)}</code>`).join(' ');
}

const CDN_GUIDE_MODES = {
  generic: {
    hint: '适用于大多数商业 CDN。把厂商提供的“回源节点 IP / CIDR”逐行加入 trust_proxies，不是填写访客 IP。',
    code: `# /opt/Sub-Panel/config.yml
real_ip:
  cloudflare: false
  trust_headers:
    - "X-Real-IP"
    - "X-Forwarded-For"
  trust_proxies:
    - "127.0.0.1"
    - "::1"
    - "你的 CDN 回源 IP 或 CIDR"`,
  },
  cloudflare: {
    hint: 'Cloudflare 模式会自动加入其官方 IPv4/IPv6 网段，并优先读取 CF-Connecting-IP，无需手工维护 Cloudflare IP 段。',
    code: `# /opt/Sub-Panel/config.yml
real_ip:
  cloudflare: true
  trust_headers:
    - "CF-Connecting-IP"
    - "X-Real-IP"
    - "X-Forwarded-For"
  trust_proxies:
    - "127.0.0.1"
    - "::1"`,
  },
  nginx: {
    hint: '适用于 CDN → aaPanel/Nginx → Sub-Panel。信任本机反代，并优先读取包含完整代理链的 X-Forwarded-For。',
    code: `# /opt/Sub-Panel/config.yml
real_ip:
  cloudflare: false
  trust_headers:
    - "X-Forwarded-For"
    - "X-Real-IP"
  trust_proxies:
    - "127.0.0.1"
    - "::1"

# aaPanel/Nginx 反向代理应包含：
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`,
  },
};

async function copyGuideText(text, btn) {
  let ok = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      ok = true;
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;left:-9999px';
      document.body.appendChild(ta);
      ta.select();
      ok = document.execCommand('copy');
      ta.remove();
    }
  } catch (err) { console.warn('复制失败', err); }
  if (!ok) return toast('复制失败，请手工选择代码', 'error');
  const old = btn.textContent;
  btn.textContent = '已复制 ✓';
  setTimeout(() => { btn.textContent = old; }, 1200);
}

function setCDNGuideMode(mode) {
  const selected = CDN_GUIDE_MODES[mode] || CDN_GUIDE_MODES.generic;
  const code = $('#cdnGuideConfigCode');
  const hint = $('#cdnGuideModeHint');
  if (code) code.textContent = selected.code;
  if (hint) hint.textContent = selected.hint;
  $$('[data-cdn-guide-mode]').forEach(btn => btn.classList.toggle('active', btn.dataset.cdnGuideMode === mode));
}

function setCDNGuideCheck(index, pass) {
  const item = $$('#cdnGuideChecks > div')[index];
  if (!item) return;
  const icon = item.querySelector('i');
  icon.className = pass ? 'pass' : 'fail';
  icon.textContent = pass ? '✓' : '!';
}

$$('[data-cdn-guide-mode]').forEach(btn => btn.addEventListener('click', () => setCDNGuideMode(btn.dataset.cdnGuideMode)));
setCDNGuideMode('generic');
$('#cdnGuideConfigCopy')?.addEventListener('click', e => copyGuideText($('#cdnGuideConfigCode').textContent, e.currentTarget));
$('#cdnGuideRestartCopy')?.addEventListener('click', e => copyGuideText($('#cdnGuideRestartCode').textContent, e.currentTarget));
$('#cdnDiagnosticRefresh')?.addEventListener('click', e => {
  const btn = e.currentTarget;
  btn.classList.add('loading');
  loadCDNSettings().finally(() => btn.classList.remove('loading'));
});

async function loadCDNSettings() {
  const box = $('#cdnSettingsBox');
  if (!box) return;
  const r = await api('/api/settings/cdn');
  if (!r || !r.real_ip || !r.diagnostic) {
    box.innerHTML = '<span style="color:var(--danger)">读取 CDN 诊断失败</span>';
    return;
  }
  const cfg = r.real_ip;
  const d = r.diagnostic;
  const selectedHeader = (d.headers || []).some(h => h.selected);
  const headerRows = (d.headers || []).map(h => {
    const mark = h.selected ? '✅' : '·';
    const value = h.value ? escapeHTML(h.value) : '<span class="muted">空</span>';
    return `<div>${mark} <code>${escapeHTML(h.name)}</code>: ${value} <span class="muted">(${escapeHTML(h.reason || '-')})</span></div>`;
  }).join('') || '<div class="muted">当前请求没有可检查的真实 IP Header</div>';
  const ok = d.trusted_proxy && d.client_ip && d.client_ip !== d.remote_ip;
  setCDNGuideCheck(0, Boolean(d.trusted_proxy));
  setCDNGuideCheck(1, selectedHeader);
  setCDNGuideCheck(2, Boolean(ok));
  let status;
  if (ok) {
    status = '<div class="diagnostic-status pass">✓ 配置通过：已从可信代理 Header 识别真实访客 IP</div>';
  } else if (!d.trusted_proxy) {
    status = '<div class="diagnostic-status fail">! 第 3 步未通过：当前 Remote IP 尚未加入 trust_proxies</div>';
  } else {
    status = '<div class="diagnostic-status fail">! 第 2 步未通过：代理已可信，但没有收到可用的真实访客 IP Header</div>';
  }
  box.innerHTML = `
    <div style="display:grid;gap:4px">
      ${status}
      <div>Cloudflare 模式: <strong>${cfg.cloudflare ? '开启' : '关闭'}</strong></div>
      <div>信任 Header: ${renderList(cfg.trust_headers)}</div>
      <div>信任代理: ${renderList(cfg.trust_proxies)}</div>
      <div>当前 RemoteAddr: <code>${escapeHTML(d.remote_addr || '-')}</code></div>
      <div>当前 Remote IP: <code>${escapeHTML(d.remote_ip || '-')}</code> · 可信代理: <strong>${d.trusted_proxy ? '是' : '否'}</strong></div>
      <div>最终 Client IP: <code>${escapeHTML(d.client_ip || '-')}</code> · 来源: <code>${escapeHTML(d.source || '-')}</code></div>
      <div style="margin-top:6px;border-top:1px solid #e5e7eb;padding-top:6px">${headerRows}</div>
    </div>`;
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
        <button data-act="report" data-name="${escapeHTML(t.name)}">接入代码</button>
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
  if (act === 'report') {
    openReportCodeModal(t.name, t.report_id);
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

// ============ 上报接入代码弹窗 ============

let _reportInfo = null;
async function getReportInfo() {
  if (!_reportInfo) _reportInfo = await api('/api/report-info');
  return _reportInfo || {};
}

async function openReportCodeModal(tenantName, reportId) {
  const info = await getReportInfo();
  // 上报走订阅网关(80端口),用同域名拼 report_id
  // sub_listen 格式如 ":80" / "0.0.0.0:8080",提取端口
  const subListen = info.sub_listen || ':80';
  const subPort = subListen.split(':').pop();
  const host = location.hostname;
  const portBit = (subPort === '80' || subPort === '443') ? '' : ':' + subPort;
  const proto = subPort === '443' ? 'https' : 'http';
  const reportUrl = `${proto}://${host}${portBit}/r/${reportId}`;
  const secret = info.report_secret || '(未配置,请在设置页「上报密钥」中配置)';

  $('#reportCodeTitle').textContent = `上报接入 — ${tenantName}`;
  $('#reportCodeURL').textContent = reportUrl;
  $('#reportCodeURL').dataset.copy = reportUrl;
  $('#reportCodeKey').textContent = secret;
  $('#reportCodeKey').dataset.copy = secret;

  const phpCode = `// ─── Sub-Panel 上报 (${tenantName}) ───
$subPanelUrl = '${reportUrl}';
$subPanelKey = '${secret}';

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
    \\Illuminate\\Support\\Facades\\Http::timeout(3)
        ->withHeaders(['X-Report-Key' => $subPanelKey])
        ->post($subPanelUrl, $reportData);
} catch (\\Exception $e) {
    // 静默失败,不影响订阅下发
}
// ─── Sub-Panel 上报结束 ───`;

  $('#reportCodePHP').textContent = phpCode;
  $('#reportCodeModal').dataset.php = phpCode;
  $('#reportCodeModal').style.display = 'flex';
  bindCopyHandlers($('#reportCodeModal'));
}

function closeReportCodeModal() { $('#reportCodeModal').style.display = 'none'; }
$('#reportCodeClose').addEventListener('click', closeReportCodeModal);
$('#reportCodeModal').addEventListener('click', e => {
  if (e.target.id === 'reportCodeModal') closeReportCodeModal();
});
$('#reportCodeCopyBtn').addEventListener('click', async () => {
  const code = $('#reportCodeModal').dataset.php || '';
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(code);
    } else {
      const ta = document.createElement('textarea');
      ta.value = code; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta);
    }
    toast('已复制 PHP 代码', 'success');
  } catch (e) { toast('复制失败', 'error'); }
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
  fmt('云IP×UA', r.cloud_token_distinct_uas_window_sec, r.cloud_token_distinct_uas_gte, 'UA');
  if (r.uncommon_ua) parts.push('<strong>非常见UA</strong>');
  if (r.from_cloud_ip) parts.push('<strong>云IP</strong>');
  if (r.country_in && r.country_in.length) parts.push(`<strong>国家∈</strong>${r.country_in.join(',')}`);
  if (r.country_not_in && r.country_not_in.length) parts.push(`<strong>国家∉</strong>${r.country_not_in.join(',')}`);
  if (r.usage_type_in && r.usage_type_in.length) parts.push(`<strong>用途∈</strong>${r.usage_type_in.map(usageLabel).join(',')}`);
  if (r.usage_type_not_in && r.usage_type_not_in.length) parts.push(`<strong>用途∉</strong>${r.usage_type_not_in.map(usageLabel).join(',')}`);
  if (r.isp_contains && r.isp_contains.length) parts.push(`<strong>ISP⊇</strong>${r.isp_contains.join(',')}`);
  return parts.length ? parts.join(' · ') : '<span style="color:#dc2626">⚠ 无任何条件</span>';
}

function ruleActionLabel(action) {
  if (action === 'deny') return '禁止访问 · 403';
  if (action === 'rate_limit') return '请求限流 · 429';
  return '投毒订阅 · 200';
}

function ruleActionClass(action) {
  return action === 'deny' || action === 'rate_limit' ? action.replace('_', '-') : 'fake';
}

async function loadRulesTable() {
  const r = await api('/api/detect_rules');
  const tbody = $('#rulesTbody'); tbody.innerHTML = '';
  const allRules = Array.isArray(r) ? r : [];
  const uncommonRule = allRules.find(x => x.name === 'uncommon_ua') || null;
  renderUncommonUARule(uncommonRule);
  const normalRules = allRules.filter(x => x.name !== 'uncommon_ua');
  if (!normalRules.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">暂无规则,点右上角「+ 新增规则」开始</td></tr>';
    return;
  }
  for (const x of normalRules) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td data-label="名称"><span class="mono rule-name" title="${escapeHtml(x.name)}">${escapeHtml(x.name)}</span></td>
      <td data-label="描述"><span class="rule-desc" title="${escapeHtml(x.desc || '-')}">${escapeHtml(x.desc || '-')}</span></td>
      <td data-label="条件摘要" class="rule-summary">${ruleSummary(x)}</td>
      <td data-label="命中后处置"><span class="rule-action-pill ${ruleActionClass(x.action)}">${ruleActionLabel(x.action)}</span></td>
      <td data-label="状态"><span class="rule-state-pill ${x.enabled ? 'on' : 'off'}">${x.enabled ? '已启用' : '已停用'}</span></td>
      <td data-label="更新时间"><span class="mono rule-time">${fmtTs(x.updated_ts)}</span></td>
      <td data-label="操作"><div class="rule-row-actions">
        <button data-act="edit"   data-name="${escapeHtml(x.name)}">编辑</button>
        <button data-act="toggle" data-name="${escapeHtml(x.name)}">${x.enabled ? '禁用' : '启用'}</button>
        <button data-act="delete" data-name="${escapeHtml(x.name)}" class="danger">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
  $$('#rulesTbody button').forEach(btn => {
    btn.addEventListener('click', () => onRuleAction(btn.dataset.act, btn.dataset.name, normalRules));
  });
}

function uncommonRuleDefault() {
  return {
    original_name: '', name: 'uncommon_ua',
    desc: '请求 UA 未命中常规订阅客户端库且不在 UA 白名单时自动处置',
    action: 'fake', enabled: true, sort_order: 45, uncommon_ua: true,
  };
}

function renderUncommonUARule(rule) {
  const state = $('#uncommonUAState');
  const action = $('#uncommonUAAction');
  const toggle = $('#uncommonUAToggle');
  const save = $('#uncommonUASave');
  if (!state || !action || !toggle || !save) return;
  const current = rule || uncommonRuleDefault();
  action.value = ['fake', 'deny', 'rate_limit'].includes(current.action) ? current.action : 'fake';
  if (rule) {
    state.className = `pill ${rule.enabled ? 'green' : 'empty'}`;
    state.textContent = rule.enabled ? '已启用' : '已停用';
    toggle.textContent = rule.enabled ? '停用规则' : '启用规则';
    toggle.className = rule.enabled ? 'danger' : 'primary';
  } else {
    state.className = 'pill red';
    state.textContent = '规则缺失';
    toggle.textContent = '创建并启用';
    toggle.className = 'primary';
  }
  save.disabled = !rule;
  save.onclick = async () => {
    const body = { ...rule, original_name: rule.name, action: action.value, uncommon_ua: true };
    const result = await apiPost('/api/detect_rules/save', body);
    if (result && result.ok) { toast('非常见 UA 处置已保存', 'success'); loadRulesTable(); }
    else toast((result && result.error) || '保存失败', 'error');
  };
  toggle.onclick = async () => {
    const body = rule
      ? { ...rule, original_name: rule.name, enabled: !rule.enabled, uncommon_ua: true }
      : uncommonRuleDefault();
    const result = await apiPost('/api/detect_rules/save', body);
    if (result && result.ok) { toast(rule && rule.enabled ? '规则已停用' : '规则已启用', 'success'); loadRulesTable(); }
    else toast((result && result.error) || '操作失败', 'error');
  };
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
  set('ruleFormAction',        isEdit ? (r.action || 'fake') : 'fake');
  // 等级字段已废弃。
  set('ruleFormTfWin',         isEdit ? (r.token_freq_window_sec || '') : '');
  set('ruleFormTfGte',         isEdit ? (r.token_freq_gte || '') : '');
  set('ruleFormIfWin',         isEdit ? (r.ip_freq_window_sec || '') : '');
  set('ruleFormIfGte',         isEdit ? (r.ip_freq_gte || '') : '');
  set('ruleFormTdWin',         isEdit ? (r.token_distinct_ips_window_sec || '') : '');
  set('ruleFormTdGte',         isEdit ? (r.token_distinct_ips_gte || '') : '');
  set('ruleFormIdWin',         isEdit ? (r.ip_distinct_tokens_window_sec || '') : '');
  set('ruleFormIdGte',         isEdit ? (r.ip_distinct_tokens_gte || '') : '');
  set('ruleFormCloudUAWin',    isEdit ? (r.cloud_token_distinct_uas_window_sec || '') : '');
  set('ruleFormCloudUAGte',    isEdit ? (r.cloud_token_distinct_uas_gte || '') : '');
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
    action:                            $('#ruleFormAction').value,
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
    cloud_token_distinct_uas_window_sec: num('ruleFormCloudUAWin'),
    cloud_token_distinct_uas_gte:        num('ruleFormCloudUAGte'),
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

async function loadUAWhitelist() {
  const list = await api('/api/ua-whitelist');
  const tbody = $('#uaWLTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!Array.isArray(list) || !list.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">暂无自定义 UA 白名单；内置常规订阅客户端无需重复添加</td></tr>';
    return;
  }
  for (const row of list) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${escapeHtml(row.pattern)}</td><td>${escapeHtml(row.note || '-')}</td><td class="mono">${fmtTs(row.created_ts)}</td><td><button class="danger ua-wl-remove" data-id="${row.id}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  $$('.ua-wl-remove').forEach(btn => btn.addEventListener('click', async () => {
    if (!confirm('确认删除该 UA 白名单？')) return;
    const r = await apiPost('/api/ua-whitelist/remove', { id: Number(btn.dataset.id) });
    if (r && r.ok) { toast('已删除', 'success'); loadUAWhitelist(); }
    else toast((r && r.error) || '删除失败', 'error');
  }));
}

$('#uaWLAddBtn').addEventListener('click', async () => {
  const pattern = $('#uaWLPattern').value.trim();
  if (!pattern) { toast('请输入 UA 正则表达式', 'error'); return; }
  const r = await apiPost('/api/ua-whitelist/add', { pattern, note: $('#uaWLNote').value.trim() });
  if (r && r.ok) {
    $('#uaWLPattern').value = '';
    $('#uaWLNote').value = '';
    toast('UA 白名单已添加并热生效', 'success');
    loadUAWhitelist();
  } else toast((r && r.error) || '添加失败', 'error');
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

// ─── 上报密钥设置 ───
async function loadReportSecret() {
  const r = await api('/api/report-info');
  if (!r) return;
  const input = $('#reportSecretInput');
  if (input) input.value = r.report_secret || '';
  // 清除缓存,让接入代码弹窗下次重新拉取
  _reportInfo = null;
}

$('#reportSecretSave')?.addEventListener('click', async () => {
  const val = ($('#reportSecretInput').value || '').trim();
  const r = await apiPost('/api/report-info/save', { report_secret: val });
  if (r && r.ok) {
    toast(val ? '密钥已保存' : '密钥已清除(上报接口不校验)', 'success');
    _reportInfo = null; // 清缓存
  } else {
    toast((r && r.error) || '保存失败', 'error');
  }
});

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
// 嫌疑用户
// ════════════════════════════════════════════════════

function fmtBytes(b) {
  if (!b || b <= 0) return '0';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
}

let suspectLoadLimit = 500;
let suspectSearchTimer = null;

async function loadSuspects() {
  const q = new URLSearchParams({
    tenant: state.tenant,
    window: $('#suspectWindow').value || '168h',
    paged: '1', limit: String(suspectLoadLimit),
    search: $('#suspectSearch').value.trim(),
    cloud: $('#suspectCloud').value,
    provider: $('#suspectProvider').value,
    asn: $('#suspectASN').value.trim(),
    sort: $('#suspectSort').value,
  });
  const page = await api('/api/suspects?' + q);
  window._suspectsData = (page && page.rows) || [];
  window._suspectsTotal = Number(page && page.total || window._suspectsData.length);
  renderSuspects();
  await Promise.all([loadSuspectResolved(), loadSuspectFocus()]);
}

async function loadSuspectResolved() {
  const q = new URLSearchParams();
  if (state.tenant) q.set('tenant', state.tenant);
  const rows = await api('/api/token-blocks' + (q.toString() ? '?' + q : ''));
  const tbody = $('#suspectResolvedTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">暂无拉黑 Token</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr = document.createElement('tr');
    const action = r.action === 'deny' ? 'deny' : 'fake';
    tr.innerHTML = `
      <td class="mono copyable" data-copy="${escapeHTML(r.token)}" title="点击复制">${escapeHTML(r.token)}</td>
      <td>${escapeHTML(r.tenant || '-')}</td>
      <td><span class="pill ${action}">${action === 'deny' ? '全拒绝 · 403' : '全投毒 · 200'}</span></td>
      <td class="mono">${escapeHTML(fmtTime(new Date(r.created_ts)))}</td>
      <td><button class="danger suspect-res-restore" data-token="${escapeHTML(r.token)}">解除拉黑</button></td>
    `;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}

async function loadSuspectFocus() {
  const q = new URLSearchParams();
  if (state.tenant) q.set('tenant', state.tenant);
  const rows = await api('/api/focus' + (q.toString() ? '?' + q : ''));
  const tbody = $('#suspectFocusTbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">暂无重点关注用户</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr = document.createElement('tr');
    const latest = [r.last_ip, r.last_ua].filter(Boolean).join(' / ') || '-';
    tr.innerHTML = `
      <td class="mono"><span>${escapeHTML(r.token)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(r.token)}">复制</button></td>
      <td>${escapeHTML(r.tenant || '-')}</td>
      <td class="mono">${escapeHTML(fmtTime(new Date(r.focused_ts)))}</td>
      <td><span class="pill red">重点关注对象行为 ${r.activity_count || 0}</span>${r.last_activity_ts ? `<div class="mono muted" style="margin-top:4px">${escapeHTML(fmtTime(new Date(r.last_activity_ts)))}</div>` : ''}</td>
      <td class="mono" style="max-width:300px;word-break:break-all">${escapeHTML(latest)}</td>
      <td><div class="focus-row-actions">
        <button class="danger solid suspect-focus-block" data-token="${escapeHTML(r.token)}" data-tenant="${escapeHTML(r.tenant || '')}">拉黑 Token</button>
        <button class="danger suspect-focus-remove" data-token="${escapeHTML(r.token)}">取消关注</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
}

function renderSuspects() {
  let rows = window._suspectsData || [];
  const list = $('#suspectsList'); list.innerHTML = '';

  // 搜索过滤
  const search = ($('#suspectSearch').value || '').trim().toLowerCase();
  if (search) {
    rows = rows.filter(r =>
      (r.token || '').toLowerCase().includes(search) ||
      (r.email || '').toLowerCase().includes(search) ||
      (r.last_ip || '').toLowerCase().includes(search) ||
      (r.cloud_providers || []).some(x => String(x).toLowerCase().includes(search)) ||
      (r.cloud_asns || []).some(x => String(x).toLowerCase().includes(search))
    );
  }

  const cloudFilter = $('#suspectCloud').value;
  const providerFilter = ($('#suspectProvider').value || '').toLowerCase();
  const asnFilter = ($('#suspectASN').value || '').trim().toUpperCase();
  if (cloudFilter === 'yes' || cloudFilter === 'only') rows = rows.filter(r => Number(r.cloud_pull_count || 0) > 0);
  if (cloudFilter === 'no') rows = rows.filter(r => Number(r.cloud_pull_count || 0) === 0);
  if (providerFilter) rows = rows.filter(r => (r.cloud_providers || []).some(x => String(x).toLowerCase() === providerFilter));
  if (asnFilter) rows = rows.filter(r => (r.cloud_asns || []).some(x => String(x).split('|')[0].toUpperCase() === asnFilter));

  // 排序
  const sort = $('#suspectSort').value;
  rows = [...rows].sort((a, b) => {
    if (!!a.retriggered !== !!b.retriggered) return b.retriggered ? 1 : -1;
    if (cloudFilter === 'only') return (b.cloud_pull_count || 0) - (a.cloud_pull_count || 0) || b.distinct_ips - a.distinct_ips;
    if (sort === 'pull') return b.pull_count - a.pull_count;
    if (sort === 'uas') return b.distinct_uas - a.distinct_uas || b.distinct_ips - a.distinct_ips;
    if (sort === 'usage') {
      const ra = a.traffic_total > 0 ? a.traffic_used / a.traffic_total : 2;
      const rb = b.traffic_total > 0 ? b.traffic_used / b.traffic_total : 2;
      return ra - rb; // 低使用率排前面
    }
    // 默认 + ips: 独立IP 降序,同分按拉取降序
    return b.distinct_ips - a.distinct_ips || b.pull_count - a.pull_count;
  });

  if (!rows.length) {
    list.innerHTML = '<div class="empty-state">暂无上报数据或无匹配结果</div>';
    return;
  }
  for (const r of rows) {
    list.appendChild(renderSuspectCard(r));
  }
  if (window._suspectsTotal > window._suspectsData.length) {
    const more = document.createElement('div');
    more.className = 'card aws-suspect-load-more';
    more.innerHTML = `<span>已按当前条件加载 ${window._suspectsData.length}/${window._suspectsTotal} 个用户</span><button id="suspectLoadMore">继续加载 ${Math.min(500, window._suspectsTotal - window._suspectsData.length)} 个</button>`;
    list.appendChild(more);
    $('#suspectLoadMore')?.addEventListener('click', () => { suspectLoadLimit += 500; loadSuspects(); });
  }
  bindCopyHandlers(list);
}

// 嫌疑用户卡片:与请求日志 .ev-card 同款样式
function renderSuspectCard(r) {
  const card = document.createElement('div');
  card.className = 'ev-card';
  const tokenFull = r.token || '';
  const usageRatio = r.traffic_total > 0 ? (r.traffic_used / r.traffic_total * 100) : -1;
  // 主指标:独立 IP 数。共享/倒卖最直观的信号 → 卡片头部大号数字,按数量上色阶
  // <5 正常(灰) / 5-9 注意(琥珀) / 10+ 高危(红)
  const ipCls = r.distinct_ips >= 10 ? 'sus-ip-hi' : (r.distinct_ips >= 5 ? 'sus-ip-mid' : 'sus-ip-lo');
  // 使用率 pill:<5% 红、<20% 黄、其余靛蓝
  const usageCls = usageRatio < 0 ? 'empty' : (usageRatio < 5 ? 'red' : (usageRatio < 20 ? 'yellow' : 'tag'));
  const usageTxt = usageRatio < 0 ? '使用率 -' : '使用率 ' + usageRatio.toFixed(1) + '%';
  const cloudProviders = (r.cloud_providers || []).map(cloudProviderLabel);
  const cloudASNs = (r.cloud_asns || []).map(String).filter(Boolean);

  card.innerHTML = `
    <div class="ev-card-head sus-head">
      <span class="sus-ip ${ipCls}">
        <span class="sus-ip-num">${r.distinct_ips}</span>
        <span class="sus-ip-lbl">独立 IP</span>
      </span>
      <span class="ev-tenant mono">${escapeHTML(r.tenant)}</span>
      <span class="ev-spacer"></span>
      ${r.retriggered ? '<span class="pill red">⚠ 历史处理后再次触发</span>' : ''}
      ${r.cloud_pull_count > 0 ? `<span class="pill red" title="云厂商网络拉取次数">云拉取 ${r.cloud_pull_count}</span>` : ''}
      <span class="pill ${usageCls}">${usageTxt}</span>
    </div>
    <div class="ev-row-full">
      <span class="ev-label">订阅</span>
      ${tokenFull
        ? `<span class="mono ev-token">${escapeHTML(tokenShort(tokenFull))}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(tokenFull)}" title="复制原始订阅 Token">复制订阅</button>`
        : '<span class="muted">(无)</span>'}
    </div>
    <div class="ev-row-full">
      <span class="ev-label">邮箱</span>
      ${r.email ? `<span class="mono">${escapeHTML(r.email)}</span>` : '<span class="muted">(无)</span>'}
    </div>
    <div class="ev-meta">
      <span class="ev-meta-item"><span class="ev-label">拉取</span><span class="mono"><strong>${r.pull_count}</strong></span></span>
      <span class="ev-meta-item"><span class="ev-label">独立UA</span><span class="mono">${r.distinct_uas}</span></span>
      <span class="ev-meta-item"><span class="ev-label">已用</span><span class="mono">${fmtBytes(r.traffic_used)}</span></span>
      <span class="ev-meta-item"><span class="ev-label">总量</span><span class="mono">${fmtBytes(r.traffic_total)}</span></span>
    </div>
    ${cloudProviders.length ? `<div class="ev-row-full"><span class="ev-label">云厂商</span><span>${cloudProviders.map(x => `<span class="pill red">${escapeHTML(x)}</span>`).join(' ')}</span></div>` : ''}
    ${cloudASNs.length ? `<div class="ev-row-full"><span class="ev-label">云 ASN</span><span class="mono">${cloudASNs.map(escapeHTML).join('<br>')}</span></div>` : ''}
    <div class="sus-actions suspect-card-actions">
      ${tokenFull ? `<button class="sus-associate" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(r.tenant || '')}">关联Token</button><button class="danger sus-token-block" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(r.tenant || '')}">拉黑Token</button><button class="primary sus-focus" data-token="${escapeHTML(tokenFull)}" data-tenant="${escapeHTML(r.tenant || '')}">重点关注</button>` : ''}
    </div>
    <div class="suspect-detail" style="display:none"></div>
  `;
  card.style.cursor = 'pointer';
  card.title = '点击展开详情';
  card.addEventListener('click', (e) => {
    if (e.target.closest('.copyable') || e.target.closest('.sus-associate') || e.target.closest('.sus-token-block') || e.target.closest('.sus-focus')) return;
    toggleSuspectDetail(card, r);
  });
  return card;
}

async function toggleSuspectDetail(card, r) {
  const box = card.querySelector('.suspect-detail');
  if (!box) return;
  // 已展开 → 收起
  if (box.style.display !== 'none' && box.dataset.loaded) {
    box.style.display = 'none';
    return;
  }
  // 收起其他已展开的
  document.querySelectorAll('#suspectsList .suspect-detail').forEach(el => {
    if (el !== box) { el.style.display = 'none'; }
  });

  box.style.display = 'block';
  if (box.dataset.loaded) return; // 已加载过,直接显示

  box.innerHTML = '<div style="padding:8px 0;color:#6b7280;font-size:12px">加载中...</div>';

  const q = new URLSearchParams({
    token: r.token,
    tenant: r.tenant,
    window: $('#suspectWindow').value || '168h',
  });
  const detail = await api('/api/suspect-detail?' + q);
  if (!detail) { box.innerHTML = '<div style="padding:8px 0;color:#ef4444">加载失败</div>'; return; }

  let html = '';
  if (detail.tokens && detail.tokens.length > 1) {
    html += `<div style="margin-top:10px;padding-top:10px;border-top:1px dashed var(--border)"><div style="font-weight:600;font-size:12px;margin-bottom:7px;color:#374151">关联 Token（同一账户 ${detail.tokens.length} 个）</div><div style="display:flex;flex-wrap:wrap;gap:7px">`;
    for (const linked of detail.tokens) {
      html += `<span class="pill tag mono"><span>${escapeHTML(linked.token)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(linked.token)}">复制</button></span>`;
    }
    html += '</div></div>';
  }
  html += '<div class="suspect-detail-grid">';

  // IP 列表
  html += '<div><div style="font-weight:600;font-size:12px;margin-bottom:6px;color:#374151">IP 列表 (' + (detail.ips||[]).length + ')</div>';
  if (detail.ips && detail.ips.length) {
    html += '<table style="width:100%;font-size:11.5px;border-collapse:collapse">';
	  html += '<tr style="color:#6b7280;border-bottom:1px solid #e5e7eb"><th style="text-align:left;padding:2px 6px">IP</th><th style="text-align:left;padding:2px 6px">位置</th><th style="text-align:left;padding:2px 6px">ISP</th><th style="text-align:left;padding:2px 6px">ASN</th><th style="text-align:left;padding:2px 6px">云厂商</th><th style="text-align:left;padding:2px 6px">类型</th><th style="text-align:right;padding:2px 6px">次数</th><th style="text-align:right;padding:2px 6px">最近</th></tr>';
    for (const ip of detail.ips) {
      const loc = ip.country || '-';
      const isp = ip.isp || '-';
	  const asn = ip.asn || '-';
	  const usage = ip.usage_type ? `${usageLabel(ip.usage_type)}${ip.usage_source === 'inferred' ? ' *' : ''}` : '-';
      const last = new Date(ip.last_seen).toLocaleString('zh-CN', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});
	  html += `<tr style="border-bottom:1px solid #f3f4f6"><td class="mono" style="padding:3px 6px;white-space:nowrap"><span>${escapeHTML(ip.ip)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(ip.ip)}" title="复制此 IP">复制</button></td><td style="padding:3px 6px">${escapeHTML(loc)}</td><td style="padding:3px 6px">${escapeHTML(isp)}</td><td class="mono" style="padding:3px 6px" title="${escapeHTML(ip.asn_org || '')}">${escapeHTML(asn)}</td><td style="padding:3px 6px">${ip.cloud_provider ? escapeHTML(cloudProviderLabel(ip.cloud_provider)) : '-'}</td><td style="padding:3px 6px">${escapeHTML(usage)}</td><td class="mono" style="text-align:right;padding:3px 6px">${ip.hit_count}</td><td class="mono" style="text-align:right;padding:3px 6px">${last}</td></tr>`;
    }
    html += '</table>';
  } else { html += '<div style="color:#9ca3af;font-size:11px">无记录</div>'; }
  html += '</div>';

  // UA 列表
  html += '<div><div style="font-weight:600;font-size:12px;margin-bottom:6px;color:#374151">UA 列表 (' + (detail.uas||[]).length + ')</div>';
  if (detail.uas && detail.uas.length) {
    html += '<table style="width:100%;font-size:11.5px;border-collapse:collapse">';
    html += '<tr style="color:#6b7280;border-bottom:1px solid #e5e7eb"><th style="text-align:left;padding:2px 6px">User-Agent</th><th style="text-align:right;padding:2px 6px">次数</th><th style="text-align:right;padding:2px 6px">最近</th></tr>';
    for (const ua of detail.uas) {
      const last = new Date(ua.last_seen).toLocaleString('zh-CN', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});
      html += `<tr class="${ua.ua_uncommon ? 'ua-row-uncommon' : ''}" style="border-bottom:1px solid #f3f4f6"><td class="mono" style="padding:3px 6px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHTML(ua.ua)}">${ua.ua_uncommon ? '<span class="pill orange">非常见</span> ' : ''}${escapeHTML(ua.ua || '(空 UA)')}</td><td class="mono" style="text-align:right;padding:3px 6px">${ua.hit_count}</td><td class="mono" style="text-align:right;padding:3px 6px">${last}</td></tr>`;
    }
    html += '</table>';
  } else { html += '<div style="color:#9ca3af;font-size:11px">无记录</div>'; }
  html += '</div></div>';

  box.innerHTML = html;
  box.dataset.loaded = '1';
  bindCopyHandlers(box);
}

function resetSuspectServerView() { suspectLoadLimit = 500; loadSuspects(); }
$('#suspectWindow').addEventListener('change', resetSuspectServerView);
$('#suspectSort').addEventListener('change', resetSuspectServerView);
$('#suspectSearch').addEventListener('input', () => { clearTimeout(suspectSearchTimer); suspectSearchTimer = setTimeout(resetSuspectServerView, 350); });
$('#suspectCloud').addEventListener('change', resetSuspectServerView);
$('#suspectProvider').addEventListener('change', resetSuspectServerView);
$('#suspectASN').addEventListener('input', () => { clearTimeout(suspectSearchTimer); suspectSearchTimer = setTimeout(resetSuspectServerView, 350); });

// 嫌疑卡片 Token 拉黑 / 重点关注：事件委托
$('#suspectsList').addEventListener('click', async (e) => {
	const associateBtn = e.target.closest('.sus-associate');
	if (associateBtn) {
		e.stopPropagation();
		const relatedToken = prompt('输入同一账户重置前或重置后的另一个 Token：');
		if (!relatedToken || !relatedToken.trim()) return;
		const r = await apiPost('/api/token-associations/add', {
			token: associateBtn.dataset.token,
			related_token: relatedToken.trim(),
			tenant: associateBtn.dataset.tenant || '',
		});
		if (r && r.ok) {
			toast('Token 已关联为同一账户', 'success');
			loadSuspects();
		} else {
			alert('关联失败：' + ((r && r.error) || '未知错误'));
		}
		return;
	}
  const blockBtn = e.target.closest('.sus-token-block');
  const focusBtn = e.target.closest('.sus-focus');
  if (!blockBtn && !focusBtn) return;
  e.stopPropagation();
  if (blockBtn) {
    openTokenBlockModal(blockBtn.dataset.token, blockBtn.dataset.tenant || '', 'suspects');
    return;
  }
  const btn = focusBtn;
  const body = { token: btn.dataset.token, tenant: btn.dataset.tenant || '', note: '' };
  const r = await apiPost('/api/focus/add', body);
  if (r && r.ok) {
    toast('已加入重点关注', 'success');
    loadSuspects();
  }
});

$('#suspectFocusTbody').addEventListener('click', async (e) => {
  const blockBtn = e.target.closest('.suspect-focus-block');
  if (blockBtn) {
    openTokenBlockModal(blockBtn.dataset.token, blockBtn.dataset.tenant || '', 'focus');
    return;
  }
  const btn = e.target.closest('.suspect-focus-remove');
  if (!btn) return;
  if (!confirm('取消关注后，该用户将回到普通嫌疑用户列表，确定？')) return;
  const r = await apiPost('/api/focus/remove', { token: btn.dataset.token });
  if (r && r.ok) loadSuspects();
});

$('#suspectResolvedTbody').addEventListener('click', async (e) => {
  const btn = e.target.closest('.suspect-res-restore');
  if (!btn) return;
  if (!confirm('解除后此 Token 将恢复到正常检测流程，并重新出现在嫌疑列表，确定？')) return;
  const r = await apiPost('/api/token-blocks/remove', { token: btn.dataset.token });
  if (r && r.ok) loadSuspects();
  else alert('解除失败:' + (r && r.error ? r.error : '未知错误'));
});

// ════════════════════════════════════════════════════
// ════════════════════════════════════════════════════
// 面板强检测：稳定期 / 墙前时序分析
// ════════════════════════════════════════════════════

let panelAnalysisOffset = 0;
const panelAnalysisLimit = 100;
let panelAnalysisSearchTimer = null;
let panelAnalysisWatchers = [];

function toLocalDateTimeInput(date) {
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function setPanelAnalysisEnabled(enabled) {
  $('#panelAnalysisToggle').checked = Boolean(enabled);
  $('#panelAnalysisToggleText').textContent = enabled ? '已开启' : '未开启';
  $('#panelAnalysisControls').hidden = !enabled;
  $('#panelAnalysisDisabled').hidden = enabled;
  if (!enabled) $('#panelAnalysisResult').hidden = true;
}

async function loadPanelAnalysisPage() {
  const start = $('#panelAnalysisStart');
  const end = $('#panelAnalysisEnd');
  if (!start.value || !end.value) {
    const now = new Date();
    end.value = toLocalDateTimeInput(now);
    start.value = toLocalDateTimeInput(new Date(now.getTime() - 7 * 24 * 3600 * 1000));
  }
  const [settings, watchers, tenants] = await Promise.all([
    api('/api/panel-analysis/settings'), api('/api/dns-watchers'), api('/api/tenants'),
  ]);
  const tenantSelect = $('#panelAnalysisTenant');
  const oldTenant = tenantSelect.value;
  panelAnalysisWatchers = watchers || [];
  tenantSelect.innerHTML = '<option value="">全部站点</option>' + (tenants || []).filter(x => x.enabled !== false)
    .map(x => `<option value="${escapeHTML(x.name)}">${escapeHTML(x.name)}</option>`).join('');
  tenantSelect.value = (tenants || []).some(x => x.name === oldTenant) ? oldTenant : '';
  renderPanelAnalysisDNSOptions();
  setPanelAnalysisEnabled(Boolean(settings && settings.enabled));
  if (settings && settings.enabled) await runPanelAnalysis(0);
}

function renderPanelAnalysisDNSOptions() {
  const dnsSelect = $('#panelAnalysisDNS');
  const tenant = $('#panelAnalysisTenant').value;
  const oldDNS = dnsSelect.value;
  const dnsMeta = new Map();
  for (const watcher of panelAnalysisWatchers) {
    const watcherTenant = watcher.tenant || '';
    if (tenant && watcherTenant && watcherTenant !== tenant) continue;
    const current = dnsMeta.get(watcher.dns_name);
    if (!current || (watcher.note && !current.note)) dnsMeta.set(watcher.dns_name, { note: watcher.note || '', tenant: watcherTenant });
  }
  dnsSelect.innerHTML = '<option value="">全部入口</option>' + [...dnsMeta.entries()].sort((a, b) => a[0].localeCompare(b[0]))
    .map(([dns, meta]) => `<option value="${escapeHTML(dns)}">${escapeHTML(meta.note ? meta.note + ' · ' + dns : dns)}</option>`).join('');
  dnsSelect.value = dnsMeta.has(oldDNS) ? oldDNS : '';
}

function panelAnalysisClassInfo(value) {
  const map = {
    wall_only: ['墙前专用', 'red'],
    repeated: ['重复墙前出现', 'orange'],
    weak: ['证据不足', 'tag'],
    mixed: ['混合行为', 'pass'],
  };
  return map[value] || ['待观察', 'tag'];
}

async function runPanelAnalysis(offset = 0) {
  if (!$('#panelAnalysisToggle').checked) return;
  const startTS = new Date($('#panelAnalysisStart').value).getTime();
  const endTS = new Date($('#panelAnalysisEnd').value).getTime();
  if (!Number.isFinite(startTS) || !Number.isFinite(endTS) || endTS <= startTS) {
    toast('请选择正确的开始和结束时间', 'error');
    return;
  }
  panelAnalysisOffset = Math.max(0, Number(offset) || 0);
  const params = new URLSearchParams({
    start_ts: String(startTS), end_ts: String(endTS),
    dns_name: $('#panelAnalysisDNS').value,
    tenant: $('#panelAnalysisTenant').value,
    lookback_minutes: $('#panelAnalysisLookback').value,
    classification: $('#panelAnalysisClass').value,
    search: $('#panelAnalysisSearch').value.trim(),
    limit: String(panelAnalysisLimit), offset: String(panelAnalysisOffset),
  });
  const btn = $('#panelAnalysisRun');
  btn.classList.add('loading');
  btn.disabled = true;
  $('#panelAnalysisResult').hidden = false;
  $('#panelAnalysisTbody').innerHTML = '<tr><td colspan="7" class="empty-state">正在对比稳定期与墙前快照...</td></tr>';
  const data = await api('/api/panel-analysis?' + params);
  btn.classList.remove('loading');
  btn.disabled = false;
  if (!data || data.enabled === false) {
    setPanelAnalysisEnabled(false);
    return;
  }
  renderPanelAnalysis(data);
}

function renderPanelAnalysis(data) {
  const summary = data.summary || {};
  $('#panelAnalysisStats').innerHTML = `
    <div><small>订阅请求</small><strong>${Number(summary.request_count || 0).toLocaleString()}</strong></div>
    <div><small>独立 Token</small><strong>${Number(summary.token_count || 0).toLocaleString()}</strong></div>
    <div><small>取得真实订阅</small><strong>${Number(summary.real_token_count || 0).toLocaleString()}</strong></div>
    <div><small>被墙记录</small><strong>${summary.wall_event_count || 0}</strong></div>
    <div class="danger"><small>墙前专用</small><strong>${summary.wall_only_count || 0}</strong></div>
    <div class="warning"><small>重复墙前</small><strong>${summary.repeated_count || 0}</strong></div>`;
  const rows = data.rows || [];
  const tbody = $('#panelAnalysisTbody');
  tbody.innerHTML = '';
  const scopeTenant = $('#panelAnalysisTenant').value || '全部站点';
  const scopeDNS = $('#panelAnalysisDNS').selectedOptions[0]?.textContent || '全部入口';
  const lookback = $('#panelAnalysisLookback').selectedOptions[0]?.textContent || '20 分钟';
  $('#panelAnalysisMeta').textContent = `${scopeTenant} · ${scopeDNS} · 墙前 ${lookback} · 匹配 ${data.total || 0} 个 · 查询 ${data.elapsed_ms || 0} ms`;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">该范围没有符合条件的墙前候选 Token</td></tr>';
  }
  for (const row of rows) {
    const [label, pill] = panelAnalysisClassInfo(row.classification);
    const network = [cloudProviderLabel(row.cloud_provider), row.last_asn, row.last_asn_org].filter(Boolean).join(' · ') || '-';
    const tr = document.createElement('tr');
    tr.className = `panel-analysis-row ${row.classification || 'mixed'}`;
    tr.innerHTML = `
      <td data-label="Token / 结论"><div class="panel-analysis-token"><div class="aws-copy-wrap"><span class="mono aws-cell-value" title="${escapeHTML(row.token)}">${escapeHTML(row.token)}</span><button class="ip-copy-btn copyable" data-copy="${escapeHTML(row.token)}">复制</button></div><div><span class="pill ${pill}">${label}</span>${row.blocked ? `<span class="pill red">已拉黑 · ${row.block_action === 'deny' ? '拒绝' : '投毒'}</span>` : ''}${row.focused ? '<span class="pill orange">重点关注</span>' : ''}</div>${row.account ? `<small class="muted mono" title="关联账户">${escapeHTML(row.account)}</small>` : ''}</div></td>
      <td data-label="入口 / 站点"><div class="panel-analysis-scope-cell"><div><span class="panel-analysis-field-label">入口</span><strong title="${escapeHTML(row.entry_note || row.dns_name)}">${escapeHTML(row.entry_note || '未备注')}</strong></div><small class="muted mono" title="${escapeHTML(row.dns_name)}">${escapeHTML(row.dns_name)}</small><div><span class="panel-analysis-field-label site">站点</span><b>${escapeHTML(row.tenant || '全部站点')}</b></div></div></td>
      <td data-label="墙前命中"><strong class="panel-analysis-hit">${row.change_hits || 0}/${row.eligible_changes || 0}</strong><small>墙前拉取 ${row.prewall_pulls || 0}</small></td>
      <td data-label="稳定期 / 真实"><strong>${row.normal_pulls || 0} 次稳定期</strong><small>真实订阅 ${row.real_pulls || 0} / 总拉取 ${row.total_pulls || 0}</small></td>
      <td data-label="最近网络"><div class="mono panel-analysis-ellipsis" title="${escapeHTML(row.last_ip || '-')}">${escapeHTML(row.last_ip || '-')}</div><small class="panel-analysis-ellipsis" title="${escapeHTML(row.last_ua || '(空 UA)')}">${escapeHTML(row.last_ua || '(空 UA)')}</small><small class="panel-analysis-ellipsis" title="${escapeHTML(network)}">${escapeHTML(network)}</small></td>
      <td data-label="首次 / 最近"><small>${escapeHTML(fmtTime(new Date(row.first_seen_ts)))}</small><strong>${escapeHTML(fmtTime(new Date(row.last_seen_ts)))}</strong></td>
      <td data-label="操作"><div class="panel-analysis-actions"><button class="danger solid panel-analysis-block" data-token="${escapeHTML(row.token)}" data-tenant="${escapeHTML(row.tenant || '')}" ${row.blocked ? 'disabled' : ''}>${row.blocked ? '已拉黑' : '拉黑 Token'}</button><button class="panel-analysis-focus" data-token="${escapeHTML(row.token)}" data-tenant="${escapeHTML(row.tenant || '')}" ${row.focused ? 'disabled' : ''}>${row.focused ? '已关注' : '重点关注'}</button></div></td>`;
    tbody.appendChild(tr);
  }
  bindCopyHandlers(tbody);
  const total = Number(data.total || 0);
  const prevDisabled = panelAnalysisOffset <= 0;
  const nextDisabled = panelAnalysisOffset + panelAnalysisLimit >= total;
  $('#panelAnalysisPager').innerHTML = `<span>第 ${total ? Math.floor(panelAnalysisOffset / panelAnalysisLimit) + 1 : 0} 页 · 共 ${total} 个</span><div><button id="panelAnalysisPrev" ${prevDisabled ? 'disabled' : ''}>上一页</button><button id="panelAnalysisNext" ${nextDisabled ? 'disabled' : ''}>下一页</button></div>`;
  $('#panelAnalysisPrev')?.addEventListener('click', () => runPanelAnalysis(panelAnalysisOffset - panelAnalysisLimit));
  $('#panelAnalysisNext')?.addEventListener('click', () => runPanelAnalysis(panelAnalysisOffset + panelAnalysisLimit));
}

$('#panelAnalysisToggle')?.addEventListener('change', async e => {
  const enabled = e.target.checked;
  const result = await apiPost('/api/panel-analysis/settings', { enabled });
  if (!result || !result.ok) {
    e.target.checked = !enabled;
    return toast((result && result.error) || '保存失败', 'error');
  }
  setPanelAnalysisEnabled(enabled);
  toast(enabled ? '面板强检测已开启' : '面板强检测已关闭', enabled ? 'success' : 'warning');
  if (enabled) runPanelAnalysis(0);
});
$('#panelAnalysisRun')?.addEventListener('click', () => runPanelAnalysis(0));
['panelAnalysisDNS', 'panelAnalysisClass', 'panelAnalysisLookback'].forEach(id => {
  $('#' + id)?.addEventListener('change', () => runPanelAnalysis(0));
});
$('#panelAnalysisTenant')?.addEventListener('change', () => {
  renderPanelAnalysisDNSOptions();
  runPanelAnalysis(0);
});
$('#panelAnalysisSearch')?.addEventListener('input', () => {
  clearTimeout(panelAnalysisSearchTimer);
  panelAnalysisSearchTimer = setTimeout(() => runPanelAnalysis(0), 350);
});
$('#panelAnalysisTbody')?.addEventListener('click', async e => {
  const block = e.target.closest('.panel-analysis-block');
  if (block) return openTokenBlockModal(block.dataset.token, block.dataset.tenant || '', 'panel-analysis');
  const focus = e.target.closest('.panel-analysis-focus');
  if (!focus) return;
  const result = await apiPost('/api/focus/add', { token: focus.dataset.token, tenant: focus.dataset.tenant || '' });
  if (result && result.ok) {
    toast('已加入重点关注', 'success');
    runPanelAnalysis(panelAnalysisOffset);
  } else toast((result && result.error) || '操作失败', 'error');
});

// AWS 墙前嫌疑用户 IP 筛选
// ════════════════════════════════════════════════════

let awsSuspectRows = [];
let awsSuspectBlocked = new Set();
let awsSuspectFocused = new Set();
let awsSuspectVisibleLimit = 250;
let awsSuspectTotal = 0;
let awsSuspectSearchTimer = null;

async function loadAWSSuspects() {
  const list = $('#awsSuspectList');
  if (!list) return;
  list.innerHTML = '<div class="empty-state">正在聚合最近的 AWS 墙前快照...</div>';
  const params = new URLSearchParams({
    paged: '1', limit: '1000',
    dns_name: $('#awsSuspectDNS').value,
    tenant: $('#awsSuspectTenant').value,
    search: $('#awsSuspectSearch').value.trim(),
    min_hits: $('#awsSuspectHits').value || '0',
    ua: $('#awsSuspectUA').value,
    sort: $('#awsSuspectSort').value,
  });
  const [page, blocks, focused, watchers, tenantsData] = await Promise.all([
    api('/api/aws-suspects?' + params), api('/api/token-blocks'), api('/api/focus'),
    api('/api/dns-watchers'), api('/api/tenants'),
  ]);
  awsSuspectRows = (page && page.rows) || [];
  awsSuspectTotal = Number(page && page.total || awsSuspectRows.length);
  awsSuspectVisibleLimit = 250;
  awsSuspectBlocked = new Set((blocks || []).map(x => x.token));
  awsSuspectFocused = new Set((focused || []).map(x => x.token));

  const dnsSel = $('#awsSuspectDNS');
  const tenantSel = $('#awsSuspectTenant');
  const oldDNS = dnsSel.value;
  const oldTenant = tenantSel.value;
  const dnsMeta = new Map();
  const tenants = new Set((tenantsData || []).filter(x => x.enabled !== false).map(x => x.name || '-'));
  for (const watcher of (watchers || [])) if (!dnsMeta.has(watcher.dns_name)) dnsMeta.set(watcher.dns_name, watcher.note || '');
  dnsSel.innerHTML = '<option value="">全部入口 DNS</option>' + [...dnsMeta.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([dns, note]) => `<option value="${escapeHTML(dns)}">${escapeHTML(note ? note + ' · ' + dns : dns)}</option>`).join('');
  tenantSel.innerHTML = '<option value="">全部站点</option>' + [...tenants].sort()
    .map(tenant => `<option value="${escapeHTML(tenant)}">${escapeHTML(tenant)}</option>`).join('');
  dnsSel.value = dnsMeta.has(oldDNS) ? oldDNS : '';
  tenantSel.value = tenants.has(oldTenant) ? oldTenant : '';
  renderAWSSuspects();
}

function renderAWSSuspects() {
  const list = $('#awsSuspectList');
  if (!list) return;
  const dns = $('#awsSuspectDNS').value;
  const tenant = $('#awsSuspectTenant').value;
  const search = $('#awsSuspectSearch').value.trim().toLowerCase();
  const minHits = Number($('#awsSuspectHits').value || 0);
  const uaMode = $('#awsSuspectUA').value;
  const sortMode = $('#awsSuspectSort').value;
  let rows = awsSuspectRows.filter(row => {
    if (dns && row.dns_name !== dns) return false;
    if (tenant && (row.tenant || '-') !== tenant) return false;
    if ((row.change_hits || 0) < minHits) return false;
    if (uaMode === 'uncommon' && !row.has_uncommon_ua) return false;
    if (uaMode === 'known' && row.has_uncommon_ua) return false;
    if (search) {
      const hit = String(row.token || '').toLowerCase().includes(search) ||
        (row.ips || []).some(ip => String(ip.ip || '').toLowerCase().includes(search));
      if (!hit) return false;
    }
    return true;
  });
  rows.sort((a, b) => {
    if (sortMode === 'pulls') return (b.pull_count || 0) - (a.pull_count || 0) || (b.last_seen_ts || 0) - (a.last_seen_ts || 0);
    if (sortMode === 'recent') return (b.last_seen_ts || 0) - (a.last_seen_ts || 0);
    if (sortMode === 'closest') return (a.closest_seconds || 0) - (b.closest_seconds || 0) || (b.change_hits || 0) - (a.change_hits || 0);
    return (b.change_hits || 0) - (a.change_hits || 0) || (b.pull_count || 0) - (a.pull_count || 0);
  });

  const matchedRows = rows;
  const uniqueIPs = new Set();
  const entries = new Set();
  const sites = new Set();
  for (const row of matchedRows) {
    entries.add(row.dns_name);
    sites.add(row.tenant || '-');
    for (const ip of (row.ips || [])) uniqueIPs.add(ip.ip);
  }
  $('#awsSuspectStats').innerHTML = `
    <span><small>入口</small><strong>${entries.size}</strong></span>
    <span><small>站点</small><strong>${sites.size}</strong></span>
    <span><small>Token</small><strong>${awsSuspectTotal}</strong></span>
    <span><small>独立 IP</small><strong>${uniqueIPs.size}</strong></span>`;
  if (!matchedRows.length) {
    list.innerHTML = '<div class="card empty-state">没有符合当前条件的 AWS 墙前订阅者</div>';
    return;
  }
  rows = matchedRows.slice(0, awsSuspectVisibleLimit);
  const hiddenCount = matchedRows.length - rows.length;

  const ipTokenMap = new Map();
  for (const row of awsSuspectRows) {
    for (const ip of (row.ips || [])) {
      if (!ipTokenMap.has(ip.ip)) ipTokenMap.set(ip.ip, new Set());
      ipTokenMap.get(ip.ip).add(row.token);
    }
  }
  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.dns_name)) grouped.set(row.dns_name, new Map());
    const siteMap = grouped.get(row.dns_name);
    const site = row.tenant || '-';
    if (!siteMap.has(site)) siteMap.set(site, []);
    siteMap.get(site).push(row);
  }

  let html = '';
  for (const [entry, siteMap] of grouped) {
    const entryRows = [...siteMap.values()].flat();
    const note = entryRows.find(x => x.entry_note)?.entry_note || '';
    const entryChanges = Math.max(...entryRows.map(x => Number(x.change_total || 0)));
    html += `<details class="card aws-suspect-entry" open><summary>
      <span class="pill red">AWS 墙前</span><strong class="mono">${escapeHTML(entry)}</strong>
      ${note ? `<span class="pill tag">${escapeHTML(note)}</span>` : ''}
      <span class="aws-suspect-entry-meta">${siteMap.size} 个站点 · ${entryRows.length} 个 Token · 最近 ${entryChanges} 次记录</span>
    </summary><div class="aws-suspect-entry-body">`;
    for (const [site, siteRows] of siteMap) {
      const siteIPs = new Set(siteRows.flatMap(x => (x.ips || []).map(ip => ip.ip))).size;
      html += `<details class="aws-suspect-site" open><summary><strong>站点：${escapeHTML(site)}</strong><span>${siteRows.length} 个 Token · ${siteIPs} 个 IP</span></summary>
        <div class="datatable"><table class="aws-suspect-table"><thead><tr><th>Token / 风险</th><th>订阅者 IP</th><th>UA / 网络</th><th>行为</th><th>操作</th></tr></thead><tbody>`;
      for (const row of siteRows) {
        const ips = row.ips || [];
        const ipHTML = ips.slice(0, 3).map(ip => {
          const related = ipTokenMap.get(ip.ip)?.size || 1;
          const network = [cloudProviderLabel(ip.cloud_provider), ip.asn, ip.asn_org].filter(Boolean).join(' · ');
          return `<div class="aws-suspect-ip-line"><span class="mono" title="${escapeHTML(network || ip.ip)}">${escapeHTML(ip.ip)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(ip.ip)}">复制</button>${ip.whitelisted ? '<span class="aws-ip-whitelisted" title="该 IP 仅豁免单 IP 多 Token 检测">白名单</span>' : ''}${related > 1 ? `<span class="aws-ip-related" title="该 IP 在当前 AWS 墙前记录中由 ${related} 个不同 Token 使用">共享 ${related} Token</span>` : ''}</div>`;
        }).join('');
        const ua = (row.uas || [])[0] || '(空 UA)';
        const network = ips[0] ? [cloudProviderLabel(ips[0].cloud_provider), ips[0].asn, ips[0].asn_org].filter(Boolean).join(' · ') : '-';
        const hitsClass = (row.change_hits || 0) >= 5 ? 'red' : ((row.change_hits || 0) >= 2 ? 'orange' : 'tag');
        const riskClass = (row.change_hits || 0) >= 5 ? 'risk-high' : ((row.change_hits || 0) >= 2 ? 'risk-medium' : 'risk-low');
        const blocked = awsSuspectBlocked.has(row.token);
        const focused = awsSuspectFocused.has(row.token);
        html += `<tr class="aws-suspect-main-row ${riskClass}">
          <td data-label="Token / 风险"><div class="aws-token-identity"><div class="aws-copy-wrap"><span class="mono aws-cell-value" title="${escapeHTML(row.token)}">${escapeHTML(row.token)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(row.token)}">复制</button></div><div class="aws-token-signals"><span class="pill ${hitsClass}" title="该入口与站点最近最多 50 次换 IP 记录中的独立命中次数">墙前命中 ${row.change_hits || 0}/${row.change_total || 0}</span>${row.has_uncommon_ua ? '<span class="pill orange">非常见 UA</span>' : ''}${blocked ? '<span class="pill red">已在黑名单</span>' : ''}</div></div></td>
          <td data-label="订阅者 IP"><div class="aws-suspect-ip-list">${ipHTML}${ips.length > 3 ? `<span class="muted">另有 ${ips.length - 3} 个，展开查看</span>` : ''}</div></td>
          <td data-label="UA / 网络"><div class="aws-suspect-ellipsis" title="${escapeHTML((row.uas || []).join('\n') || '(空 UA)')}"><span class="mono">${escapeHTML(ua)}</span>${(row.uas || []).length > 1 ? `<span class="muted">等 ${(row.uas || []).length} 种</span>` : ''}</div><div class="muted aws-suspect-network" title="${escapeHTML(network)}">${escapeHTML(network)}</div></td>
          <td data-label="行为"><div class="aws-suspect-activity"><span><small>拉取</small><strong>${row.pull_count || 0}</strong></span><span><small>最近</small><b class="mono">${escapeHTML(fmtTime(new Date(row.last_seen_ts)))}</b></span><span><small>距失联</small><strong>${escapeHTML(fmtBeforeFailure(row.closest_seconds || 0))}</strong></span></div></td>
          <td data-label="操作"><div class="aws-suspect-actions"><button class="danger solid aws-suspect-block aws-token-block-primary" data-token="${escapeHTML(row.token)}" data-tenant="${escapeHTML(row.tenant || '')}" ${blocked ? 'disabled' : ''}>${blocked ? '已加入 Token 黑名单' : '加入 Token 黑名单'}</button><div><button class="aws-suspect-detail-toggle" data-dns="${escapeHTML(row.dns_name)}" data-token="${escapeHTML(row.token)}" data-tenant="${escapeHTML(row.tenant || '')}">查看详情</button><button class="aws-suspect-focus" data-token="${escapeHTML(row.token)}" data-tenant="${escapeHTML(row.tenant || '')}" ${focused ? 'disabled' : ''}>${focused ? '已关注' : '重点关注'}</button></div></div></td>
        </tr><tr class="aws-suspect-detail-row" style="display:none"><td colspan="5"><div class="muted">展开后加载该 Token 的墙前取证明细</div></td></tr>`;
      }
      html += '</tbody></table></div></details>';
    }
    html += '</div></details>';
  }
  if (hiddenCount > 0) html += `<div class="card aws-suspect-load-more"><span>已显示 ${rows.length}/${matchedRows.length} 个 Token</span><button id="awsSuspectLoadMore">继续加载 ${Math.min(250, hiddenCount)} 个</button></div>`;
  list.innerHTML = html;
  bindCopyHandlers(list);
}

function renderAWSSuspectDetail(row) {
  const ips = row.ips || [];
  const ipList = ips.map(ip => `<div class="aws-suspect-detail-ip"><span class="aws-suspect-detail-ip-name"><span class="mono">${escapeHTML(ip.ip)}</span>${ip.whitelisted ? '<span class="aws-ip-whitelisted" title="该 IP 仅豁免单 IP 多 Token 检测">白名单</span>' : ''}</span><span>${escapeHTML([cloudProviderLabel(ip.cloud_provider), ip.asn, ip.asn_org].filter(Boolean).join(' · ') || '-')}</span><strong>${ip.pull_count || 0} 次</strong></div>`).join('');
  const occurrences = (row.occurrences || []).map(item => `<tr><td class="mono">${escapeHTML(fmtTime(new Date(item.failure_ts || item.occurred_ts)))}</td><td class="mono">${escapeHTML(item.client_ip || '-')}</td><td class="mono aws-suspect-detail-ua" title="${escapeHTML(item.ua || '(空 UA)')}">${escapeHTML(item.ua || '(空 UA)')}</td><td><strong>${escapeHTML(fmtBeforeFailure(item.seconds_before_failure || 0))}</strong></td><td>${item.pull_count || 0}</td></tr>`).join('');
  return `<div class="aws-suspect-detail-grid"><div><h4>关联 IP（${ips.length}）</h4>${ipList || '<span class="muted">无 IP</span>'}</div><div><h4>墙前取证明细</h4><div class="datatable"><table><thead><tr><th>失联/换 IP 时间</th><th>订阅者 IP</th><th>UA</th><th>距离</th><th>拉取</th></tr></thead><tbody>${occurrences}</tbody></table></div></div></div>`;
}

function resetAWSSuspectView() {
  awsSuspectVisibleLimit = 250;
  loadAWSSuspects();
}
['awsSuspectDNS', 'awsSuspectTenant', 'awsSuspectHits', 'awsSuspectUA', 'awsSuspectSort'].forEach(id => {
  $('#' + id)?.addEventListener('change', resetAWSSuspectView);
});
$('#awsSuspectSearch')?.addEventListener('input', () => {
  clearTimeout(awsSuspectSearchTimer);
  awsSuspectSearchTimer = setTimeout(resetAWSSuspectView, 350);
});
$('#awsSuspectRefreshBtn')?.addEventListener('click', loadAWSSuspects);
$('#awsSuspectList')?.addEventListener('click', async e => {
  const detailBtn = e.target.closest('.aws-suspect-detail-toggle');
  if (detailBtn) {
    const detailRow = detailBtn.closest('tr')?.nextElementSibling;
    if (!detailRow) return;
    if (detailRow.style.display !== 'none') {
      detailRow.style.display = 'none';
      return;
    }
    detailRow.style.display = '';
    if (!detailRow.dataset.loaded) {
      const cell = detailRow.querySelector('td');
      cell.innerHTML = '<div class="muted">正在加载取证明细...</div>';
      const q = new URLSearchParams({ dns_name: detailBtn.dataset.dns, tenant: detailBtn.dataset.tenant || '', token: detailBtn.dataset.token, details: '1' });
      const detail = await api('/api/aws-suspects?' + q);
      if (detail && detail[0]) {
        cell.innerHTML = renderAWSSuspectDetail(detail[0]);
        detailRow.dataset.loaded = '1';
      } else {
        cell.innerHTML = '<div class="empty-state">未找到该 Token 的取证明细</div>';
      }
    }
    return;
  }
  const moreBtn = e.target.closest('#awsSuspectLoadMore');
  if (moreBtn) {
    awsSuspectVisibleLimit += 250;
    renderAWSSuspects();
    return;
  }
  const focusBtn = e.target.closest('.aws-suspect-focus');
  if (focusBtn && !focusBtn.disabled) {
    const r = await apiPost('/api/focus/add', { token: focusBtn.dataset.token, tenant: focusBtn.dataset.tenant || '', note: 'AWS 墙前筛选' });
    if (r && r.ok) {
      awsSuspectFocused.add(focusBtn.dataset.token);
      toast('已加入重点关注', 'success');
      renderAWSSuspects();
    }
    return;
  }
  const blockBtn = e.target.closest('.aws-suspect-block');
  if (blockBtn && !blockBtn.disabled) openTokenBlockModal(blockBtn.dataset.token, blockBtn.dataset.tenant || '', 'aws-suspects');
});

// ════════════════════════════════════════════════════
// AWS 入口 IP 更换追踪
// ════════════════════════════════════════════════════

function fmtAliveSeconds(total) {
  total = Math.max(0, Math.floor(Number(total) || 0));
  const days = Math.floor(total / 86400); total %= 86400;
  const hours = Math.floor(total / 3600); total %= 3600;
  const minutes = Math.floor(total / 60); const seconds = total % 60;
  if (days) return `${days}天 ${hours}小时 ${minutes}分`;
  if (hours) return `${hours}小时 ${minutes}分 ${seconds}秒`;
  if (minutes) return `${minutes}分 ${seconds}秒`;
  return `${seconds}秒`;
}

function fmtBeforeFailure(seconds) {
  seconds = Math.max(0, Math.floor(Number(seconds) || 0));
  if (seconds < 60) return `${seconds}秒前`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}分${rest ? ` ${rest}秒` : ''}前`;
}

function refreshAWSAliveClocks() {
  document.querySelectorAll('.aws-alive-clock').forEach(el => {
    const started = Number(el.dataset.started || 0);
    if (started > 0) el.textContent = fmtAliveSeconds((Date.now() - started) / 1000);
  });
}
setInterval(refreshAWSAliveClocks, 1000);

async function loadAWSIPChanges() {
  const [watchers, rows, tenants] = await Promise.all([
    api('/api/dns-watchers'), api('/api/aws-ip-changes'), api('/api/tenants'),
  ]);

  const tenantSel = $('#awsWatcherTenant');
  const selectedTenant = tenantSel.value;
  tenantSel.innerHTML = '<option value="">不指定（全部站点）</option>';
  for (const tenant of (tenants || [])) {
    const option = document.createElement('option');
    option.value = tenant.name;
    option.textContent = tenant.name;
    tenantSel.appendChild(option);
  }
  tenantSel.value = selectedTenant;

  const watcherList = $('#awsWatcherList');
  watcherList.innerHTML = '';
  if (!watchers || !watchers.length) {
    watcherList.innerHTML = '<div class="empty-state">暂无 DNS 追踪任务</div>';
  } else {
    for (const watcher of watchers) {
      const card = document.createElement('div');
      card.className = 'ev-card aws-watcher-card';
      const history = watcher.ip_history || [];
      const historyHTML = history.length
        ? `<details class="aws-history-fold"><summary><span>历史 IP</span><strong>${history.length} 条</strong><span class="mono">最近 ${escapeHTML(history[0].ip)}</span><span>${escapeHTML(fmtAliveSeconds(history[0].alive_seconds))}</span></summary><div class="datatable"><table><thead><tr><th>IP 地址</th><th>开始</th><th>结束</th><th>存活时间</th></tr></thead><tbody>${history.map(h => `<tr><td class="mono">${escapeHTML(h.ip)}</td><td class="mono">${escapeHTML(fmtTime(new Date(h.started_ts)))}</td><td class="mono">${escapeHTML(fmtTime(new Date(h.ended_ts)))}</td><td><strong>${escapeHTML(fmtAliveSeconds(h.alive_seconds))}</strong></td></tr>`).join('')}</tbody></table></div></details>`
        : '<div class="aws-no-history">暂无历史 IP</div>';
      card.innerHTML = `
        <div class="aws-watcher-top">
          <div class="aws-watcher-identity">
            <span class="pill ${watcher.enabled ? 'pass' : ''}">${watcher.enabled ? '追踪中' : '已暂停'}</span>
            <strong class="mono aws-watcher-domain">${escapeHTML(watcher.dns_name)}</strong>
            <input class="aws-watcher-note" data-id="${watcher.id}" maxlength="200" value="${escapeHTML(watcher.note || '')}" placeholder="填写备注" title="回车或移开光标自动保存">
          </div>
          <div class="aws-watcher-actions">
            ${watcher.pending_failure_ts ? '<span class="pill orange">已收到 TCP 失联信号</span>' : ''}
            <label class="aws-lookback-inline" title="手动设置下次换 IP 的回溯范围"><input class="aws-watcher-lookback" data-id="${watcher.id}" type="number" min="1" max="120" step="1" value="${watcher.lookback_minutes}" inputmode="numeric"><span>分钟</span></label>
            <button class="aws-watcher-toggle" data-id="${watcher.id}" data-enabled="${watcher.enabled ? '0' : '1'}">${watcher.enabled ? '暂停' : '继续'}</button>
            <button class="danger aws-watcher-remove" data-id="${watcher.id}">删除</button>
          </div>
        </div>
        <div class="aws-watcher-metrics">
          <span><small>范围</small><strong>${escapeHTML(watcher.tenant || '全部站点')}</strong></span>
          <span><small>当前 IP</small><b class="mono">${escapeHTML(watcher.last_ips || '-')}</b></span>
          <span><small>存活</small><strong class="aws-alive-clock" data-started="${watcher.last_changed_ts || 0}">${fmtAliveSeconds(watcher.alive_seconds || 0)}</strong></span>
          <span><small>检查</small><b class="mono">${watcher.last_checked_ts ? escapeHTML(fmtTime(new Date(watcher.last_checked_ts))) : '-'}</b></span>
          ${watcher.pending_failure_ts ? `<span><small>首次失联</small><strong class="aws-failure-time">${escapeHTML(fmtTime(new Date(watcher.pending_failure_ts)))}</strong></span>` : ''}
        </div>
        ${watcher.last_error ? `<div class="aws-watcher-error">${escapeHTML(watcher.last_error)}</div>` : ''}
        ${historyHTML}`;
      watcherList.appendChild(card);
    }
    refreshAWSAliveClocks();
  }

  const list = $('#awsChangeList');
  if (!list) return;
  list.innerHTML = '';
  if (!rows || !rows.length) {
    $('#awsChangeDNSFilter').innerHTML = '<option value="">全部入口 DNS</option>';
    list.innerHTML = '<div class="empty-state">暂无换 IP 记录</div>';
    return;
  }
  const dnsFilter = $('#awsChangeDNSFilter');
  const selectedDNS = dnsFilter.value;
  const dnsStats = new Map();
  for (const row of rows) {
    const dns = row.dns_name || '手动记录';
    const item = dnsStats.get(dns) || { count: 0, note: '' };
    item.count++;
    if (!item.note && row.note) item.note = row.note;
    dnsStats.set(dns, item);
  }
  dnsFilter.innerHTML = '<option value="">全部入口 DNS</option>';
  for (const [dns, item] of [...dnsStats.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const option = document.createElement('option');
    option.value = dns;
    option.textContent = `${item.note ? item.note + ' · ' : ''}${dns}（${item.count}）`;
    dnsFilter.appendChild(option);
  }
  dnsFilter.value = dnsStats.has(selectedDNS) ? selectedDNS : '';
  const visibleRows = dnsFilter.value ? rows.filter(row => (row.dns_name || '手动记录') === dnsFilter.value) : rows;
  if (!visibleRows.length) {
    list.innerHTML = '<div class="empty-state">该入口暂无换 IP 记录</div>';
    return;
  }
  for (const r of visibleRows) {
    const card = document.createElement('div');
    card.className = 'ev-card';
    card.innerHTML = `
      <div class="ev-card-head">
        <span class="pill red">AWS 换 IP</span>
        <strong class="mono">${escapeHTML(r.dns_name || '手动记录')}</strong>
        ${r.note ? `<span class="pill tag">${escapeHTML(r.note)}</span>` : ''}
        <span class="mono">${escapeHTML(fmtTime(new Date(r.occurred_ts)))}</span>
        <span class="ev-spacer"></span>
        <span class="pill ${r.failure_ts ? 'orange' : 'tag'}">${r.failure_ts ? '精准失联锚点' : '仅 DNS 锚点'}</span>
        <span class="pill tag">${r.lookback_minutes} 分钟取证</span>
      </div>
      <div class="ev-row-full">
        <span class="ev-label">入口</span>
        <span class="mono">${escapeHTML(r.old_ip || '-')}</span>
        <span style="padding:0 8px">→</span>
        <span class="mono">${escapeHTML(r.new_ip || '-')}</span>
      </div>
      <div class="ev-meta">
        ${r.failure_ts ? `<span class="ev-meta-item"><span class="ev-label">TCP 首次失联</span><strong class="mono">${escapeHTML(fmtTime(new Date(r.failure_ts)))}</strong></span><span class="ev-meta-item"><span class="ev-label">DNS 变更延迟</span><strong>${escapeHTML(fmtAliveSeconds((r.occurred_ts-r.failure_ts)/1000))}</strong></span>` : ''}
        <span class="ev-meta-item"><span class="ev-label">范围</span><strong>${escapeHTML(r.tenant || '全部站点')}</strong></span>
        <span class="ev-meta-item"><span class="ev-label">站点</span><strong>${r.site_count || 0}</strong></span>
        <span class="ev-meta-item"><span class="ev-label">订阅者</span><strong>${r.subscriber_count || 0}</strong></span>
        <span class="ev-meta-item"><span class="ev-label">拉取</span><strong>${r.pull_count || 0}</strong></span>
      </div>
      <div class="sus-actions">
        <button class="aws-change-detail" data-id="${r.id}">查看前后同现 Token</button>
        <button class="danger aws-change-remove" data-id="${r.id}">删除记录</button>
      </div>
      <div class="aws-change-detail-box" style="display:none"></div>
    `;
    list.appendChild(card);
  }
}

async function toggleAWSChangeDetail(card, id) {
  const box = card.querySelector('.aws-change-detail-box');
  if (!box) return;
  if (box.dataset.loaded) {
    box.style.display = box.style.display === 'none' ? 'block' : 'none';
    return;
  }
  box.style.display = 'block';
  await loadAWSChangeContinuity(box, id, 50);
}

async function loadAWSChangeContinuity(box, id, sampleSize) {
  box.innerHTML = '<div class="muted" style="padding:10px 0">正在对比 DNS 变化前后的请求...</div>';
  const data = await api('/api/aws-ip-changes/detail?id=' + encodeURIComponent(id) + '&sample_size=' + encodeURIComponent(sampleSize));
  if (!data) return;
  const continuity = data.continuity || {};
  const grouped = {};
  for (const row of (continuity.tokens || [])) {
    (grouped[row.tenant] ||= []).push(row);
  }
  const sites = Object.keys(grouped).sort();
  let html = `<div class="aws-snapshot-toolbar"><span>以本次 DNS 变化为分界，只显示前后两侧都出现的同站点 Token。已取换前 <strong>${continuity.before_requests || 0}</strong> 条、换后 <strong>${continuity.after_requests || 0}</strong> 条有效请求，共 <strong>${(continuity.tokens || []).length}</strong> 个交集 Token。</span><label>前后各取 <select class="aws-continuity-size"><option value="20">20 次</option><option value="50">50 次</option><option value="100">100 次</option><option value="200">200 次</option><option value="500">500 次</option></select></label></div>`;
  if (!sites.length) {
    html += '<div class="empty-state">当前取样范围内，没有在 DNS 变化前后均出现的 Token</div>';
  }
  for (const site of sites) {
    const rows = grouped[site];
    html += `<div class="datatable" style="margin-top:12px"><div style="padding:8px 10px;font-weight:650">站点：${escapeHTML(site)} · ${rows.length} 个前后同现 Token</div>`;
    html += '<table class="aws-subscriber-table"><thead><tr><th>Token</th><th>换前 IP → 换后 IP</th><th>换前 UA → 换后 UA</th><th>换后网络</th><th>换前 / 换后</th><th>换前最后</th><th>换后首次</th></tr></thead><tbody>';
    for (const row of rows) {
      const network = [cloudProviderLabel(row.after_cloud_provider), row.after_asn, row.after_asn_org].filter(Boolean).join(' · ') || '-';
      const beforeIP = row.before_ip || '-';
      const afterIP = row.after_ip || '-';
      const beforeUA = row.before_ua || '(空 UA)';
      const afterUA = row.after_ua || '(空 UA)';
      html += `<tr class="aws-subscriber-row-repeat">
        <td class="mono aws-subscriber-token" data-label="Token"><div class="aws-copy-wrap"><span class="aws-cell-value" title="${escapeHTML(row.token)}">${escapeHTML(row.token)}</span><button type="button" class="ip-copy-btn copyable" data-copy="${escapeHTML(row.token)}">复制</button></div></td>
        <td class="mono aws-subscriber-ip" data-label="换前 IP → 换后 IP"><div class="aws-ellipsis-wrap" title="${escapeHTML(beforeIP + ' → ' + afterIP)}"><span class="aws-cell-value">${escapeHTML(beforeIP)} → ${escapeHTML(afterIP)}</span></div></td>
        <td class="mono aws-subscriber-ua" data-label="换前 UA → 换后 UA"><div class="aws-ellipsis-wrap" title="${escapeHTML(beforeUA + ' → ' + afterUA)}"><span class="aws-cell-value">${escapeHTML(beforeUA)} → ${escapeHTML(afterUA)}</span></div></td>
        <td class="aws-subscriber-network" data-label="换后网络"><div class="aws-ellipsis-wrap" title="${escapeHTML(network)}"><span class="aws-cell-value">${escapeHTML(network)}</span></div></td>
        <td class="mono aws-subscriber-count" data-label="换前 / 换后"><span class="pill red">前后同现</span><strong>${row.before_pull_count || 0} / ${row.after_pull_count || 0}</strong></td>
        <td class="mono aws-subscriber-time" data-label="换前最后">${escapeHTML(fmtTime(new Date(row.before_last_seen_ts)))}</td>
        <td class="mono aws-subscriber-time" data-label="换后首次">${escapeHTML(fmtTime(new Date(row.after_first_seen_ts)))}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }
  box.innerHTML = html;
  box.dataset.loaded = '1';
  bindCopyHandlers(box);
  const sizeSelect = box.querySelector('.aws-continuity-size');
  if (sizeSelect) {
    sizeSelect.value = String(continuity.sample_size || sampleSize);
    sizeSelect.addEventListener('change', () => loadAWSChangeContinuity(box, id, Number(sizeSelect.value || 50)));
  }
}

$('#awsWatcherAddBtn').addEventListener('click', async () => {
  const dnsName = $('#awsWatcherDNS').value.trim();
  if (!dnsName) {
    alert('请输入要追踪的 DNS');
    return;
  }
  const body = {
    dns_name: dnsName,
    tenant: $('#awsWatcherTenant').value,
    lookback_minutes: Number($('#awsWatcherLookback').value || 20),
  };
  const r = await apiPost('/api/dns-watchers/add', body);
  if (!r || r.error) {
    alert('开始追踪失败：' + ((r && r.error) || '未知错误'));
    return;
  }
  toast(`已开始追踪 ${r.dns_name}`, 'success');
  $('#awsWatcherDNS').value = '';
  loadAWSIPChanges();
});

$('#awsChangeRefreshBtn').addEventListener('click', () => loadAWSIPChanges());
$('#awsChangeDNSFilter').addEventListener('change', () => loadAWSIPChanges());

$('#awsWatcherList').addEventListener('change', async e => {
  const input = e.target.closest('.aws-watcher-lookback');
  if (!input) return;
  const minutes = Math.floor(Number(input.value));
  if (!Number.isFinite(minutes) || minutes < 1 || minutes > 120) {
    alert('回溯时间必须是 1–120 分钟的整数');
    loadAWSIPChanges();
    return;
  }
  input.disabled = true;
  const r = await apiPost('/api/dns-watchers/lookback', { id: Number(input.dataset.id), minutes });
  input.disabled = false;
  if (!r || r.error) {
    alert('保存回溯时间失败：' + ((r && r.error) || '未知错误'));
    loadAWSIPChanges();
    return;
  }
  input.value = String(r.minutes);
  toast(`回溯时间已改为 ${r.minutes} 分钟`, 'success');
});

$('#awsWatcherList').addEventListener('click', async (e) => {
  const toggleBtn = e.target.closest('.aws-watcher-toggle');
  if (toggleBtn) {
    const r = await apiPost('/api/dns-watchers/toggle', {
      id: Number(toggleBtn.dataset.id), enabled: toggleBtn.dataset.enabled === '1',
    });
    if (r && r.ok) loadAWSIPChanges();
    return;
  }
  const removeBtn = e.target.closest('.aws-watcher-remove');
  if (!removeBtn) return;
  if (!confirm('删除这个 DNS 追踪任务？已产生的换 IP 快照会保留。')) return;
  const r = await apiPost('/api/dns-watchers/remove', { id: Number(removeBtn.dataset.id) });
  if (r && r.ok) loadAWSIPChanges();
});

$('#awsWatcherList').addEventListener('keydown', (e) => {
  if (e.target.matches('.aws-watcher-note') && e.key === 'Enter') {
    e.preventDefault();
    e.target.blur();
  }
});

$('#awsWatcherList').addEventListener('change', async (e) => {
  const input = e.target.closest('.aws-watcher-note');
  if (!input) return;
  const r = await apiPost('/api/dns-watchers/note', { id: Number(input.dataset.id), note: input.value.trim() });
  if (r && r.ok) toast('备注已保存', 'success');
  else toast((r && r.error) || '备注保存失败', 'error');
});

$('#awsChangeList').addEventListener('click', async (e) => {
  const detailBtn = e.target.closest('.aws-change-detail');
  if (detailBtn) {
    toggleAWSChangeDetail(detailBtn.closest('.ev-card'), detailBtn.dataset.id);
    return;
  }
  const removeBtn = e.target.closest('.aws-change-remove');
  if (!removeBtn) return;
  if (!confirm('删除这条换 IP 记录及其订阅者快照？')) return;
  const r = await apiPost('/api/aws-ip-changes/remove', { id: Number(removeBtn.dataset.id) });
  if (r && r.ok) loadAWSIPChanges();
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
    const modals = ['#tenantModal', '#ruleModal', '#reportCodeModal'];
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
