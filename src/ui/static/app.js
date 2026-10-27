/* 家卫 Homeward · Web UI（社区版：只读）
   —— 原生 JS，无框架、无构建步骤、无外部请求。

   一条安全底线写在最前面：
   **页面上的每一个字符串都可能来自网络里的某台设备**（域名、主机名、SNI 都是
   设备自己报上来的，攻击者完全可控）。所以所有插进 innerHTML 的值都必须过 esc()，
   一个都不能漏。这里没有用任何框架的自动转义，漏一个就是存储型 XSS。 */

const REFRESH_MS = 10000;

const state = {
  view: "overview",
  data: {},
  error: null,
  timer: null,
  flash: null,   // 升级面板的一次性提示（导入/清除后反馈），渲染后清空
};

// ------------------------------------------------------------------ 工具

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function ago(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}

const TYPE_LABEL = {
  unknown: "未识别", tv: "电视", camera: "摄像头", phone: "手机",
  router: "路由器", speaker: "音箱", bulb: "灯具", plug: "插座",
  appliance: "家电", nas: "NAS", computer: "电脑", watch: "穿戴",
  sensor: "传感器", printer: "打印机",
};

const SOURCE_LABEL = {
  hostname: "依据主机名", vendor: "依据厂商名", vendor_hint: "依据厂商前缀",
  none: "无依据", unknown: "无依据",
};

function typeText(d) {
  const t = TYPE_LABEL[d.device_type] || d.device_type || "未识别";
  const s = SOURCE_LABEL[d.type_source];
  return s ? `${t}（${s}）` : t;
}

// 设备风险分级（F6）：等级 + 触发理由。理由由服务端逐条给出，
// 前端原样展示 —— 用户看到的每一档风险都能追溯到具体观测数字，不做二次加工。
const RISK_LABEL = { high: "高风险", medium: "需关注", low: "未见异常" };
function riskCell(d) {
  const lv = ["high", "medium", "low"].includes(d.risk_level) ? d.risk_level : "low";
  const reasons = (d.risk_reasons || []).filter(Boolean);
  const tip = reasons.length ? ` title="${esc(reasons.join("；"))}"` : "";
  return `<span class="sev sev-${lv}"${tip}>${esc(RISK_LABEL[lv])}</span>`
    + (reasons.length ? `<div class="small muted">${reasons.map(esc).join("；")}</div>` : "");
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}`);
  return res.json();
}

// ------------------------------------------------------------------ 载入

async function loadAll() {
  // 许可状态单独拉取：即便主面板接口异常，升级面板也能独立工作；反之亦然。
  let lic = state.data.license || {};
  try {
    lic = await api("/api/license/status");
  } catch (err) {
    lic = { error: err.message || String(err) };
  }
  try {
    const [overview, devices, destinations, alerts, unknown, suggestions, blind] =
      await Promise.all([
        api("/api/overview"),
        api("/api/devices"),
        api("/api/destinations"),
        api("/api/alerts"),
        api("/api/unknown-domains"),
        api("/api/suggestions"),
        api("/api/blind-spots"),
      ]);
    state.data = { overview, devices, destinations, alerts, unknown, suggestions, blind, license: lic };
    state.error = null;
  } catch (err) {
    state.error = err.message || String(err);
    state.data.license = lic;
  }
  // P1-4 趋势数据：容错拉取（没启用 trend_store 时返回空对象，不阻塞界面）
  try {
    state.data.trend = await api("/api/trends?days=7");
  } catch {
    state.data.trend = { days: 7, points: [] };
  }
  render();
}

// ------------------------------------------------------------------ 各视图

function renderCheckup(c) {
  if (!c) return "";
  const vcls = c.verdict === "基本可控" ? "low"
            : c.verdict === "需要关注" ? "medium" : "high";
  const top = (c.top_unknown || []).map(esc).join("、");
  return `
    <div class="section">
      <h2>隐私体检 <span class="count">（结论先行）</span></h2>
      <div class="card">
        <div style="display:flex;align-items:center;gap:14px">
          <span class="sev sev-${vcls}" style="font-size:15px;padding:6px 12px">${esc(c.verdict)}</span>
          <span style="font-size:26px;font-weight:700">${esc(c.score)}<span style="font-size:14px;color:var(--muted,#888)"> /100</span></span>
          <span class="small muted">健康分</span>
        </div>
        <div class="grid" style="margin-top:14px">
          <div class="stat"><div class="k">设备</div><div class="v">${esc(c.devices_total ?? 0)}</div>
            <div class="sub">${esc(c.vendors_resolved ?? 0)} 台识别厂商</div></div>
          <div class="stat"><div class="k">活跃告警</div><div class="v">${esc(c.alerts_active ?? 0)}</div>
            <div class="sub">高危 ${esc(c.alerts_high ?? 0)}</div></div>
          <div class="stat"><div class="k">归属覆盖率</div><div class="v">${Math.round((c.coverage_rate || 0) * 100)}%</div>
            <div class="sub">${esc(c.coverage_hit ?? 0)} / ${esc(c.coverage_total ?? 0)}</div></div>
          <div class="stat"><div class="k">未知域名</div><div class="v">${esc(c.unknown_count ?? 0)}</div>
            <div class="sub">盲区 ${esc(c.blind_spots ?? 0)} 项</div></div>
        </div>
        <div class="small muted" style="margin-top:10px">可见设备 ${esc(c.visible_devices ?? 0)} · 疑似不可见 ${esc(c.suspected_invisible_devices ?? 0)}（设备观测覆盖口径，与「盲区 ${esc(c.blind_spots ?? 0)} 项」的消息条数不是一回事）</div>
        ${top ? `<div class="small muted" style="margin-top:10px">重点未知去向：${top}</div>` : ""}
        <div class="item-foot" style="margin-top:12px">
          <button class="btn btn-sm" type="button" data-report="markdown">导出完整体检报告</button>
          <span class="small muted">社区版只看见、不建议，报告仅供你自查</span>
        </div>
      </div>
    </div>`;
}

function renderOverview() {
  const d = state.data.overview || {};
  const s = d.stats || {};
  const cov = d.coverage || {};
  const vis = d.visibility || {};
  const as = d.alerts || {};
  const spots = d.blind_spots || [];
  const rate = Math.round((cov.hit_rate || 0) * 100);
  const visRate = Math.round((vis.rate || 0) * 100);

  const counts = as.by_severity || {};
  const sevLine = ["critical", "high", "medium", "low"]
    .filter((k) => counts[k])
    .map((k) => `<span class="sev sev-${k}">${esc(counts[k])}</span>`)
    .join(" ") || '<span class="muted">无</span>';

  const topDest = (state.data.destinations?.items || []).slice(0, 6);
  const recentAlerts = (state.data.alerts?.items || []).slice(0, 3);

  return `
    ${renderCheckup(d.checkup)}
    <div class="section">
      <div class="grid">
        <div class="stat"><div class="k">设备</div><div class="v">${esc(s.devices_total ?? 0)}</div>
          <div class="sub">${esc(s.vendors_resolved ?? 0)} 台识别出厂商</div></div>
        <div class="stat"><div class="k">观测记录</div><div class="v">${esc(s.flows_processed ?? 0)}</div>
          <div class="sub">决策 ${esc(s.decisions_made ?? 0)} 条</div></div>
        <div class="stat"><div class="k">活跃告警</div><div class="v">${esc(as.active ?? 0)}</div>
          <div class="sub">${sevLine}</div></div>
        <div class="stat"><div class="k">域名归属覆盖率</div><div class="v">${rate}%</div>
          <div class="sub">${esc(cov.hit ?? 0)} / ${esc(cov.total ?? 0)} 个域名认得出来</div>
          <div class="bar" style="margin-top:6px"><i style="width:${rate}%"></i></div></div>
        <div class="stat"><div class="k">设备观测覆盖</div><div class="v">${esc(vis.visible ?? 0)} / ${esc(vis.suspected_invisible ?? 0)}</div>
          <div class="sub">可见 / 疑似不可见</div>
          <div class="bar" style="margin-top:6px"><i style="width:${visRate}%"></i></div></div>
      </div>
    </div>

    ${spots.length ? `<div class="section">
      <h2>当前看不到的地方 <span class="count">（${spots.length} 项）</span></h2>
      <div class="note">设备观测覆盖：可见 ${esc(vis.visible ?? 0)} / 疑似不可见 ${esc(vis.suspected_invisible ?? 0)}（在册 ${esc(vis.total ?? 0)} 台，${visRate}%）——「疑似不可见」不都是盲区，四种可能成因见「盲区」页。</div>
      ${spots.slice(0, 3).map((x) => `<div class="note">${esc(x)}</div>`).join("")}
      ${spots.length > 3 ? `<div class="small muted" style="margin-top:6px">其余 ${spots.length - 3} 项见「盲区」页</div>` : ""}
    </div>` : ""}

    <div class="section">
      <h2>最近告警 <span class="count">（活跃 ${esc(as.active ?? 0)} 条）</span></h2>
      ${recentAlerts.length ? `<div class="list">${recentAlerts.map(alertCard).join("")}</div>`
        : '<div class="card empty">暂无告警。行为识别需要「一段时间内的若干次观测」，刚启动还没有数据是正常的。</div>'}
    </div>

    <div class="section">
      <h2>主要去向 <span class="count">（按涉及设备数排序）</span></h2>
      ${topDest.length ? `<div class="list">${topDest.map(destCard).join("")}</div>`
        : '<div class="card empty">还没有观测到任何外联。</div>'}
    </div>`;
}

function renderDevices() {
  const items = state.data.devices?.items || [];
  if (!items.length) {
    return '<div class="card empty">设备台账为空。家卫通过 DHCP 租约与 ARP 表发现设备 —— 若以单网口 Docker 形态运行，可能读不到这些数据，详见「盲区」页。</div>';
  }
  const rows = items.map((d) => `
    <tr>
      <td>
        <strong>${esc(d.name)}</strong>
        <div class="small muted">${esc(typeText(d))}</div>
        <div class="small muted">观测 ${esc(d.observations ?? 0)} 次 / ${esc(d.domain_count ?? 0)} 个域名</div>
      </td>
      <td class="mono">${(d.ips || []).map(esc).join("<br>") || "—"}</td>
      <td class="mono">${esc(d.mac || "—")}${
        d.random_mac
          ? '<div><span class="tag" title="该设备使用随机 MAC（手机/平板/电脑的隐私保护特性）：MAC 由设备临时生成，查不到厂商、重连后还会变。这是协议层面的盲区，不是家卫没识别出来。">随机 MAC</span></div>'
          : ""}</td>
      <td>${esc(d.vendor || "—")}</td>
      <td>${riskCell(d)}</td>
      <td class="small muted">${esc(ago(d.last_seen))}</td>
      <td>
        <div class="tags">
          ${(d.top_domains || []).slice(0, 5).map((t) =>
            `<span class="tag is-domain">${esc(t.domain)} <b>${esc(t.count)}</b></span>`).join("") ||
            '<span class="muted small">未观测到域名</span>'}
        </div>
      </td>
    </tr>`).join("");

  const high = items.filter((d) => d.risk_level === "high").length;
  const mid = items.filter((d) => d.risk_level === "medium").length;

  return `<div class="section">
    <h2>设备画像 <span class="count">（${items.length} 台，按风险排序；高风险 ${high} 台、需关注 ${mid} 台）</span></h2>
    <div class="card scroll-x">
      <table>
        <thead><tr>
          <th>名称 / 品类</th><th>IP</th><th>MAC</th><th>厂商</th><th>风险</th><th>最近活跃</th><th>主要去向</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </div>`;
}

function destCard(x) {
  const org = x.organization || "未识别";
  const known = x.known;
  return `
    <div class="item ${known ? "" : "is-unknown"}">
      <div class="item-head">
        <div>
          <span class="item-title mono">${esc(x.domain)}</span>
          <div class="item-sub">${esc(org)} · ${esc(x.category || "unknown")} · 置信度 ${esc(x.confidence || "none")}</div>
        </div>
        <span class="small muted">${(x.devices || []).length} 台设备</span>
      </div>
      <div class="item-body small muted">${esc(x.explain || "")}</div>
      ${(x.devices || []).length ? `<div class="tags">${x.devices.map((dv) =>
        `<span class="tag">${esc(dv.name)} <b>${esc(dv.count)}</b></span>`).join("")}</div>` : ""}
    </div>`;
}

function renderDestinations() {
  const d = state.data.destinations || {};
  const items = d.items || [];
  if (!items.length) return '<div class="card empty">还没有观测到任何外联去向。</div>';
  const rate = Math.round((d.hit_rate || 0) * 100);
  return `<div class="section">
    <h2>去向地图 <span class="count">（${items.length} 个域名，认出 ${d.known || 0} 个，覆盖率 ${rate}%）</span></h2>
    <div class="list">${items.map(destCard).join("")}</div>
  </div>`;
}

function alertCard(a) {
  const missing = (a.missing_keys || []).length
    ? `<div class="small" style="color:var(--sev-high)">文案占位符缺失：${(a.missing_keys || []).map(esc).join("、")}</div>`
    : "";
  return `
    <div class="item sev-${esc(a.severity)}">
      <div class="item-head">
        <div>
          <span class="sev sev-${esc(a.severity)}">${esc(a.severity_label)}</span>
          <span class="item-title">${esc(a.title)}</span>
          <div class="item-sub">${esc(a.device_name)} → ${esc(a.domain || a.destination)}
            （归属：${esc(a.organization || "未识别")}）· 置信度 ${esc(a.confidence)}</div>
        </div>
        <span class="small muted">首次 ${esc(fmtTime(a.first_seen))} · 最近 ${esc(fmtTime(a.last_seen))} · ${esc(a.episodes)} 次</span>
      </div>
      <div class="item-body">${esc(a.summary)}</div>
      <div class="item-body small muted">建议动作：${esc(a.action_label)}</div>
      <div class="item-body small">后果：${esc(a.side_effects || "（未填写）")}</div>
      ${missing}
      <div class="item-foot">
        <button class="btn btn-sm" type="button" data-dismiss="${esc(a.alert_id)}">忽略此告警</button>
        <span class="small muted">社区版不下发任何阻断</span>
      </div>
    </div>`;
}

function renderAlerts() {
  const items = state.data.alerts?.items || [];
  if (!items.length) {
    return '<div class="card empty">暂无活跃告警。行为识别看的是「一段时间内的若干次观测」，不是单条流量。</div>';
  }
  return `<div class="section">
    <div class="sec-head">
      <h2>告警 <span class="count">（${items.length} 条，按严重度排序）</span></h2>
      <button class="btn btn-sm btn-warn" type="button" data-action="clear-observations"
        title="清空设备/域名/告警等全部观测记录，重新开始分析（不删除许可）">清除全部观测记录</button>
    </div>
    <div class="list">${items.map(alertCard).join("")}</div>
  </div>`;
}

// —— P1-4 趋势面板 ——
async function _refetchTrend(days) {
  try {
    state.data.trend = await api(`/api/trends?days=${days}`);
  } catch {
    state.data.trend = { days, points: [] };
  }
  render();
}

function renderTrends() {
  const d = state.data.trend || { points: [] };
  const points = d.points || [];
  const currentDays = d.days || 7;

  // 无数据时的引导：首次启动后每小时自动采样，7 天后自然有
  if (!points.length) {
    return `
      <div class="card empty">
        <div style="font-size:18px;font-weight:600;margin-bottom:8px">⏳ 趋势数据还在累积</div>
        <p>家卫每小时整点自动采样一次。启动后约 <b>7 天</b> 可看到完整一周的活跃趋势，<b>30 天</b> 可看到月度规律。</p>
        <p>采样不消耗额外流量、不影响设备性能，数据只存在本地 SQLite（<code>data/trends.db</code>），超过 30 天自动滚动清理。</p>
      </div>`;
  }

  // 简易 div-bar 图：三条曲线叠加（设备数柱状 + 告警点 + 隐私分线）
  const maxDevices = Math.max(...points.map(p => p.devices_total), 1);
  const maxAlerts = Math.max(...points.map(p => p.alerts_active), 1);
  const widthPct = 100 / Math.max(points.length, 1);

  const bars = points.map((p, i) => {
    const devH = (p.devices_total / maxDevices) * 100;
    const alertTop = 100 - (p.alerts_active / maxAlerts) * 100;
    const scoreTop = 100 - p.privacy_score;  // score 0-100 直接当 %
    const hr = new Date(p.hour_epoch * 1000);
    const label = hr.getHours().toString().padStart(2, "0") + ":00";
    // 每 6 小时显示一次标签，避免拥挤
    const showLabel = (i % 6 === 0) || i === points.length - 1;
    return `
      <div class="trend-col" style="width:${widthPct}%">
        <div class="trend-canvas">
          <div class="trend-bar" style="height:${devH}%" title="设备 ${p.devices_total}"></div>
          ${p.alerts_active > 0 ? `<div class="trend-dot trend-alert" style="bottom:${alertTop}%" title="告警 ${p.alerts_active}"></div>` : ""}
          <div class="trend-dot trend-score" style="bottom:${scoreTop}%" title="隐私分 ${p.privacy_score}"></div>
        </div>
        ${showLabel ? `<div class="trend-label">${label}</div>` : ""}
      </div>`;
  }).join("");

  // 汇总卡：第一天 vs 最后一天的对比
  const first = points[0], last = points[points.length - 1];
  const summary = `
    <div class="card" style="display:flex;gap:24px;flex-wrap:wrap">
      <div><div class="muted small">窗口</div><div><b>${points.length}</b> 小时（${currentDays} 天）</div></div>
      <div><div class="muted small">设备峰值</div><div><b>${maxDevices}</b> 台</div></div>
      <div><div class="muted small">告警峰值</div><div><b>${maxAlerts}</b> 条</div></div>
      <div><div class="muted small">起始隐私分</div><div><b>${first.privacy_score}</b></div></div>
      <div><div class="muted small">当前隐私分</div><div><b>${last.privacy_score}</b></div></div>
    </div>`;

  const rangeBtn = (days, label) => `
    <button class="btn btn-sm ${currentDays === days ? "" : "is-muted"}"
            type="button" data-trend-days="${days}">${label}</button>`;

  return `
    <div class="section">
      <div class="section-head">
        <h2>活跃趋势</h2>
        <div style="display:flex;gap:6px">
          ${rangeBtn(7, "7 天")}
          ${rangeBtn(14, "14 天")}
          ${rangeBtn(30, "30 天")}
        </div>
      </div>
      ${summary}
      <div class="card">
        <div class="trend-legend">
          <span class="trend-legend-item"><span class="trend-legend-swatch" style="background:var(--accent)"></span>设备数</span>
          <span class="trend-legend-item"><span class="trend-legend-swatch trend-alert"></span>告警</span>
          <span class="trend-legend-item"><span class="trend-legend-swatch trend-score"></span>隐私分（0-100）</span>
        </div>
        <div class="trend-chart">${bars}</div>
      </div>
      <div class="muted small" style="margin-top:8px">提示：设备数（绿柱）= 同一小时内出现过 DNS 查询的设备数；告警点（红点）= 该小时末的活跃告警数；隐私分（蓝点）= 当前体检分数。数据只存在本地 SQLite，不联网。</div>
    </div>`;
}

// trend 范围切换：拦截 click → refetch → render
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-trend-days]");
  if (btn) {
    e.preventDefault();
    const days = parseInt(btn.dataset.trendDays, 10);
    if (!isNaN(days)) _refetchTrend(days);
  }
});

function renderUnknown() {
  const d = state.data.unknown || {};
  const items = d.items || [];
  const own = d.own || [];
  const benign = d.benign || [];
  const marks = d.marks || {};

  if (!items.length && !own.length && !benign.length) {
    return '<div class="card empty">所有观测到的域名都能在知识库里查到归属。</div>';
  }

  // 「真正未知」：可让用户自己归类为自有 / 良性（家卫不替用户猜，用户说了算且可撤销）
  const rowUnknown = (x) => `
    <div class="item is-unknown">
      <div class="item-head">
        <span class="item-title mono">${esc(x)}</span>
        <button class="btn btn-sm" type="button" disabled
          title="需在配置中启用 AI 后端，且必须由你手动触发">帮我分析</button>
      </div>
      <div class="item-sub small muted">分析需你手动触发，且只在启用 AI 后端后可用；结果须经你确认才写入知识库。</div>
      <div class="item-actions" style="margin-top:6px;display:flex;gap:6px">
        <button class="btn btn-sm" type="button" data-mark="own" data-domain="${esc(x)}">标记为自有</button>
        <button class="btn btn-sm" type="button" data-mark="benign" data-domain="${esc(x)}">标记为良性</button>
      </div>
    </div>`;

  // 已归类项：只有**用户手动标记**的才可取消；结构性自动判定的自有（.lan/.local/.arpa）不可取消
  const rowMarked = (x, label, kind, cancellable) => `
    <div class="item">
      <div class="item-head">
        <span class="item-title mono">${esc(x)}</span>
        <span class="badge">${esc(label)}</span>
      </div>
      <div class="item-sub small muted">${cancellable
        ? `你标记为${esc(label)}，不计入未知域名；可随时撤销。`
        : `自动判定为${esc(label)}（本地网络命名），不是外部外联，不计入未知域名。`}</div>
      ${cancellable
        ? `<div class="item-actions" style="margin-top:6px">
             <button class="btn btn-sm" type="button" data-mark="" data-domain="${esc(x)}">取消标记</button>
           </div>`
        : ""}
    </div>`;

  let html = '<div class="section">';
  html += `<h2>未知域名 <span class="count">（${items.length} 个）</span></h2>`;
  html += '<div class="note">AI 分析默认关闭（需自备后端与 API Key）。未启用时这里只做列举 —— 家卫不会替你猜这些域名是谁的。</div>';
  html += items.length
    ? `<div class="list" style="margin-top:10px">${items.map(rowUnknown).join("")}</div>`
    : '<div class="card empty" style="margin-top:10px">没有真正未知的域名了。</div>';

  if (own.length) {
    html += `<h3 style="margin-top:16px">自有 / 局域网 <span class="count">（${own.length} 个）</span></h3>
      <div class="note">这些是你自己家里的名字（如路由 istoreos.lan、mDNS 的 .local、内网反向解析），
      <strong>不是外部外联</strong>，已不计入未知域名。</div>
      <div class="list" style="margin-top:8px">${
        own.map((x) => rowMarked(x, "自有", "own", !!marks[x])).join("")}</div>`;
  }
  if (benign.length) {
    html += `<h3 style="margin-top:16px">已标记为良性 <span class="count">（${benign.length} 个）</span></h3>
      <div class="note">你手动标记为良性（如更新源、开发工具）的域名，不计入未知域名。</div>
      <div class="list" style="margin-top:8px">${
        benign.map((x) => rowMarked(x, "良性", "benign", true)).join("")}</div>`;
  }
  html += "</div>";
  return html;
}

function renderSuggestions() {
  const d = state.data.suggestions || {};
  const items = d.items || [];
  const note = d.note || "";
  if (!items.length) {
    return `<div class="section"><h2>建议阻断</h2>
      <div class="card empty">当前没有待确认的建议。</div>
      <div class="note" style="margin-top:10px">${esc(note)}</div></div>`;
  }
  return `<div class="section">
    <h2>建议阻断 <span class="count">（${items.length} 条，均为「建议」，未生效）</span></h2>
    <div class="note">${esc(note)}</div>
    <div class="list" style="margin-top:10px">
      ${items.map((r) => `
        <div class="item sev-high">
          <div class="item-head">
            <div>
              <span class="item-title mono">${esc(r.domain || "—")}</span>
              <div class="item-sub">${esc(r.device || "")} · ${esc(r.level || "")} · 来源 ${esc(r.source || "")}</div>
            </div>
            <span class="tag">${esc(r.status || "suggested")}</span>
          </div>
          <div class="item-body">${esc(r.reason || "")}</div>
          <div class="item-body small">后果预览：${esc(r.side_effects || "（未填写）")}</div>
          <div class="item-foot">
            <button class="btn btn-sm" type="button" disabled>执行拦截（标准版）</button>
            <span class="small muted">社区版到此为止：告诉你会怎样，不替你动手</span>
          </div>
        </div>`).join("")}
    </div>
  </div>`;
}

function renderBlind() {
  const items = state.data.blind?.items || [];
  const cov = state.data.overview?.coverage || {};
  const vis = state.data.overview?.visibility || {};
  const visRate = Math.round((vis.rate || 0) * 100);
  const collection = state.data.overview?.stats?.collection || [];
  // 「疑似不可见」的四种可能成因 —— 现有数据无法区分，必须照实列出，
  // 不能让用户以为「疑似不可见 Y 台」等于「Y 台设备都是盲区」
  const causes = [
    "当期闲置，没发任何查询——不是盲区",
    "DNS 单播直连光猫、不经旁路",
    "加密 DNS（DoH/DoT）",
    "只直连 IP、无域名查询",
  ];
  return `<div class="section">
    <h2>可见性 <span class="count">（设备观测覆盖）</span></h2>
    <div class="card">
      <div class="kv"><span class="k">比例</span><span>可见 ${esc(vis.visible ?? 0)} / 疑似不可见 ${esc(vis.suspected_invisible ?? 0)}（在册 ${esc(vis.total ?? 0)} 台，${visRate}%）</span></div>
      <div class="bar" style="margin-top:8px"><i style="width:${visRate}%"></i></div>
      <div class="small muted" style="margin-top:8px">${esc(vis.denominator_note || "")}</div>
      <div class="item-body" style="margin-top:14px">疑似不可见的四种可能成因（现有数据无法区分）：</div>
      <div class="list" style="margin-top:8px">
        ${causes.map((x, i) => `<div class="item"><div class="item-body">${"①②③④"[i]} ${esc(x)}</div></div>`).join("")}
      </div>
      <div class="item-body" style="margin-top:14px">为什么旁路天然有上限：家卫以旁路方式工作：只被动接收广播与发给自己的流量。其他设备的 DNS 查询走单播、不经过这里——这是部署形态的结构性上限，不是故障。当前能力 = L1 被动发现（谁在家）+ L3 自愿设备（它的外联）；L2 端口镜像验证中、未启用。已知盲区：加密 DNS（DoH/DoT）、设备硬编码的公网 DNS、只直连 IP 的连接、直连光猫 LAN 口的有线设备。</div>
      <div class="item-body" style="margin-top:14px">采集通道状态：</div>
      ${collection.length
        ? `<table style="margin-top:8px">
          <thead><tr><th>采集通道</th><th>状态</th><th>原因</th></tr></thead>
          <tbody>${collection.map((c) => `<tr>
            <td>${esc(c.collector || "")}</td>
            <td>${c.active ? "可用" : "不可用"}</td>
            <td>${esc(c.reason || "")}</td>
          </tr>`).join("")}</tbody>
        </table>`
        : '<div class="small muted" style="margin-top:8px">暂无采集通道信息</div>'}
    </div>
  </div>
  <div class="section">
    <h2>盲区 <span class="count">（${items.length} 项）</span></h2>
    <div class="note">家卫的承诺是「看不到的地方要写出来」。下面这些是当前部署形态下确实做不到 / 没做到的事，不是故障。</div>
    <div class="list" style="margin-top:10px">
      ${items.length
        ? items.map((x) => `<div class="item"><div class="item-body">${esc(x)}</div></div>`).join("")
        : '<div class="card empty">当前没有已识别到的盲区。</div>'}
    </div>
  </div>
  <div class="section">
    <h2>域名归属命中率（知识库）</h2>
    <div class="card">
      <div class="kv"><span class="k">域名</span><span>${esc(cov.hit || 0)} / ${esc(cov.total || 0)} 认得出来</span></div>
      <div class="bar" style="margin-top:8px"><i style="width:${Math.round((cov.hit_rate || 0) * 100)}%"></i></div>
      <div class="small muted" style="margin-top:8px">
        覆盖率低不代表有问题，只说明知识库还不够厚。域名归属数据（CC BY 4.0）欢迎共建，
        贡献规范见仓库的 .github/CONTRIBUTING.md。
      </div>
    </div>
  </div>`;
}

function renderImport() {
  return `
    <div class="section">
      <h2>离线日志导入</h2>
      <div class="note">把一段 dnsmasq 查询日志或 conntrack 快照（或两者混合）粘贴 / 上传进来，
        家卫会离线回放成观测，走与实时采集完全相同的分析链路。无需把家卫串进网络、也无需给读日志权限，
        就能先体验「看见」能力。日志只在你本机分析，不会上传。</div>
      <div class="card" style="margin-top:12px">
        <div class="row" style="margin-bottom:10px">
          <input class="field" id="import-file" type="file"
            accept=".log,.txt,text/plain" style="flex:1;min-width:240px">
        </div>
        <textarea class="field" id="import-log" rows="8"
          placeholder="在此粘贴 dnsmasq 查询日志（如：Jun 1 12:00:01 dnsmasq[123]: query[A] example.com from 192.168.1.50）或 conntrack 快照行，或两者混合"></textarea>
        <div class="item-foot" style="margin-top:10px">
          <button class="btn" type="button" data-import-run>开始分析</button>
          <span class="small muted" id="import-result"></span>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>导出观测报告</h2>
      <div class="note">导出的报告只含你自己的观测遥测（设备、去向、未知域名、告警、盲区）。
        知识库在服务器端，客户端不会导出或抓取，也不提供「浏览全部已知域名」功能。</div>
      <div class="card" style="margin-top:12px">
        <div class="row">
          <button class="btn" type="button" data-report="markdown">导出观测报告（Markdown）</button>
          <button class="btn" type="button" data-report="json">导出观测报告（JSON）</button>
        </div>
        <div class="small muted" style="margin-top:8px">下载的文件保存在你本地，可离线查看或转发。</div>
      </div>
    </div>

    <div class="section">
      <h2>重置观测数据</h2>
      <div class="note">清空全部观测记录（设备台账、域名归属缓存、未知域名、所有告警，含已忽略），
        让家卫从零开始重新采集。常用于：区分「修复前的旧证据」与「重新抓到的新数据」。
        不会删除你的许可 / 标准版动作记录。</div>
      <div class="card" style="margin-top:12px">
        <div class="item-foot">
          <button class="btn btn-warn" type="button" data-action="clear-observations"
            title="清空设备/域名/告警等全部观测记录，重新开始分析（不删除许可）">清除全部观测记录</button>
          <span class="small muted">操作不可撤销，但只影响本机观测态。</span>
        </div>
      </div>
    </div>`;
}

function renderUpgrade() {
  const lic = state.data.license || {};
  const status = lic.license || {};
  // 订单 URL 由服务端下发（HOMEWARD_ORDER_URL），前端不硬编码任何外部链接。
  // 此处不给外部链接字面量兜底，避免破坏「界面零外部资源」约束；若缺失则输入框留空由用户填写。
  const orderUrl = lic.order_url || "";
  const valid = !!status.valid;
  const reason = status.reason || "none";

  const planRows = [
    ["单月", "30 天", "入门 / 体验"],
    ["3 个月", "90 天", ""],
    ["6 个月", "180 天", ""],
    ["1 年", "365 天", "通常单价最低 · 主推"],
  ];
  const tiers = planRows.map(([name, dur, note]) =>
    `<div class="tier">
      <div class="tier-name">${esc(name)}</div>
      <div class="tier-dur">${esc(dur)}</div>
      <div class="tier-note small muted">${esc(note)}</div>
    </div>`).join("");

  let statusCard;
  if (valid) {
    const until = fmtTime(status.valid_until);
    const days = status.days_remaining;
    const isTrial = !!status.is_trial;
    const warn = days <= 7
      ? `<div class="note">${isTrial ? "试用" : "订阅"}将在 ${days} 天后到期${isTrial ? "，到期后拦截停用、观测不受影响" : ""}，记得续费。</div>` : "";
    statusCard = `<div class="card">
      <div class="item-head">
        <span class="sev" style="background:var(--ok)">已激活</span>
        <span class="item-title">${esc(status.edition === "pro" ? "专业版" : "标准版")}${isTrial ? " · 30 天试用中" : ""}</span>
        <span class="small muted">订单 ${esc(status.order_id || "—")}</span>
      </div>
      <div class="kv" style="margin-top:8px"><span class="k">有效期至</span>
        <span>${esc(until)}（剩余 ${esc(days)} 天）</span></div>
      <div class="kv"><span class="k">功能</span>
        <span>${(status.features || []).map(esc).join("、") || "—"}</span></div>
      ${warn}
      <div class="item-foot">
        <button class="btn btn-sm" type="button" data-deactivate>清除本地许可（回到社区版）</button>
        <button class="btn btn-sm" type="button" disabled
          title="标准版许可服务上线后启用；本期仅预埋占位与接口契约（见防伪设计 §4.7）">备份许可</button>
      </div>
    </div>`;
  } else {
    const isTrial = !!status.is_trial;
    const reasonText = {
      none: "当前为社区版：只做「看见」，实际拦截属标准版能力。",
      expired: isTrial
        ? "试用已到期：拦截已停用，观测与解释不受影响。续费后导入新令牌即可恢复。"
        : "订阅已过期，请续费后重新导入新令牌。",
      invalid: "本地许可无效（可能被篡改或签发密钥不匹配）。",
      revoked: "该许可已被吊销（如已退款）。如有疑问请联系支持。",
    }[reason] || "当前为社区版。";
    statusCard = `<div class="card">
      <div class="item-head">
        <span class="sev sev-low">社区版</span>
        <span class="item-title">未激活付费版本</span>
      </div>
      <div class="item-body small muted">${esc(reasonText)}</div>
      <div class="kv" style="margin-top:8px"><span class="k">设备指纹</span>
        <span><code>${esc(lic.device_fp || "—")}</code></span></div>
      <div class="small muted" style="margin-top:4px">手动签发许可时，需把此指纹发给作者用于令牌绑定（仅 sha256 哈希，不含任何原始硬件信息）。</div>
      <div class="item-foot">
        ${reason === "expired"
          ? '<button class="btn btn-sm" type="button" data-goto-pay>续费解锁</button>' : ""}
        <button class="btn btn-sm" type="button" disabled
          title="标准版许可服务上线后启用；本期仅预埋占位与接口契约（见防伪设计 §4.7）">备份许可</button>
      </div>
    </div>`;
  }

  const flash = state.flash
    ? `<div class="note" style="border-color:var(--ok);background:#eafaf1">${esc(state.flash)}</div>` : "";

  return `
    ${flash}
    <div class="section">
      <h2>当前状态</h2>
      ${statusCard}
    </div>

    <div class="section">
      <h2>升级到标准版 / 专业版</h2>
      <div class="note">家卫本体 100% 客户端、可离线使用；仅「激活」需联网一次。扫码付款后，把服务端返回的许可令牌粘贴到下方即可解锁。</div>
      <div class="grid" style="margin-top:12px">${tiers}</div>
    </div>

    <div class="section">
      <h2>第一步 · 扫码付款</h2>
      <div class="card">
        <div class="row" style="margin-bottom:10px">
          <input class="field" id="order-url" type="text" value="${esc(orderUrl)}" style="flex:1;min-width:240px">
          <button class="btn" type="button" data-qr-gen>生成付款二维码</button>
        </div>
        <div id="qr-box" class="qr-box"></div>
        <div class="small muted" style="margin-top:8px">用手机扫描上方二维码打开付款页，完成支付。订单 URL 由服务端下发，私有化部署可自行改写。</div>
      </div>
    </div>

    <div class="section">
      <h2>第二步 · 导入许可令牌</h2>
      <div class="card">
        <textarea class="field" id="token-input" rows="3"
          placeholder="粘贴服务端返回的许可令牌（形如 base64payload.base64signature）"></textarea>
        <div class="item-foot">
          <button class="btn" type="button" data-activate>导入许可</button>
          <span class="small muted">令牌仅保存在本机，不会上传任何家庭数据。</span>
        </div>
        <div id="activate-result" class="small" style="margin-top:8px"></div>
      </div>
    </div>`;
}

const RENDERERS = {
  overview: renderOverview,
  devices: renderDevices,
  destinations: renderDestinations,
  alerts: renderAlerts,
  trend: renderTrends,
  unknown: renderUnknown,
  suggestions: renderSuggestions,
  blind: renderBlind,
  import: renderImport,
  upgrade: renderUpgrade,
};

// ------------------------------------------------------------------ 渲染

function render() {
  const view = document.getElementById("view");
  const pill = document.getElementById("alert-pill");

  const active = state.data.alerts?.items || [];
  pill.textContent = String(active.length);
  pill.classList.toggle("is-hot", active.some((a) => a.severity === "high" || a.severity === "critical"));

  const err = state.error
    ? `<div class="section"><div class="note">读取接口失败：${esc(state.error)}。服务可能刚启动，或端口不是 9595。</div></div>`
    : "";

  const body = state.error ? "" : (RENDERERS[state.view] || renderOverview)();
  view.innerHTML = err + body;
  state.flash = null;   // 一次性提示已渲染，清掉避免下次重复

  document.getElementById("updated-at").textContent = "更新于 " + fmtTime(Date.now() / 1000);

  const ov = state.data.overview;
  if (ov) {
    document.getElementById("foot-meta").textContent =
      `v${esc(ov.version)} · 运行 ${esc(ov.uptime_seconds)}s · 知识库 ${esc(ov.stats?.flows_processed ?? 0)} 条观测`;
    document.getElementById("edition-badge").textContent = ov.edition?.label || "社区版";
  }
}

// ------------------------------------------------------------------ 交互

document.getElementById("tabs").addEventListener("click", (e) => {
  const btn = e.target.closest(".tab");
  if (!btn) return;
  state.view = btn.dataset.view;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === btn));
  render();
});

document.getElementById("view").addEventListener("click", async (e) => {
  const dismiss = e.target.closest("[data-dismiss]");
  if (dismiss) {
    const id = dismiss.dataset.dismiss;
    dismiss.disabled = true;
    try {
      await fetch(`/api/alerts/${encodeURIComponent(id)}/dismiss`, { method: "POST" });
      await loadAll();
    } catch (err) {
      dismiss.disabled = false;
      alert("忽略失败：" + (err.message || err));
    }
    return;
  }

  // —— F7：把域名标记为「自有 / 良性」，或取消标记 ——
  // 家卫不替用户猜域名是谁的；但用户说了算，且必须能随时撤销（kind 传空串即取消）。
  const markBtn = e.target.closest("[data-mark]");
  if (markBtn) {
    const domain = markBtn.dataset.domain || "";
    const kind = markBtn.dataset.mark || "";
    if (!domain) return;
    markBtn.disabled = true;
    try {
      const r = await fetch("/api/domain-marks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, kind }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await loadAll();
    } catch (err) {
      markBtn.disabled = false;
      alert("标记失败：" + (err.message || err));
    }
    return;
  }

  // —— 一键清除全部观测记录 ——
  const clearBtn = e.target.closest("[data-action='clear-observations']");
  if (clearBtn) {
    if (!confirm("确定要清空全部观测记录吗？\n\n会删除：设备台账、域名归属缓存、未知域名、所有告警（含已忽略）。\n不会删除：你的许可 / 标准版动作记录。\n\n清完后家卫会重新开始采集——之后看到的都是全新数据，方便区分哪些是旧的、哪些是刚抓到的。")) {
      return;
    }
    clearBtn.disabled = true;
    try {
      const r = await fetch("/api/observations/clear", { method: "POST" });
      const j = await r.json().catch(() => ({}));
      await loadAll();
      if (j.ok && j.cleared) {
        const c = j.cleared;
        alert(`已清除 ${c.devices} 台设备、${c.attribution_cache} 条归属缓存、${c.alerts} 条告警。\n现在重新采集，之后看到的全是新的。`);
      }
    } catch (err) {
      alert("清除失败：" + (err.message || err));
    } finally {
      clearBtn.disabled = false;
    }
    return;
  }

  // —— 升级面板 ——
  const gotoPayBtn = e.target.closest("[data-goto-pay]");
  if (gotoPayBtn) {
    // 到期回落的「续费解锁」（EDITIONS 试用条款 3）：滚到付款码区，不跳外部链接
    const box = document.getElementById("qr-box");
    if (box) box.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }

  const qrBtn = e.target.closest("[data-qr-gen]");
  if (qrBtn) {
    const url = (document.getElementById("order-url").value || "").trim();
    const box = document.getElementById("qr-box");
    box.innerHTML = "";
    if (!url) return;
    // 用 <img> 而非 innerHTML 注入 SVG：qr_svg 由服务端生成，走同源 img-src，杜绝 SVG 携带脚本的风险。
    const img = document.createElement("img");
    img.className = "qr-img";
    img.alt = "付款二维码";
    img.src = "/api/qr?text=" + encodeURIComponent(url);
    box.appendChild(img);
    return;
  }

  const actBtn = e.target.closest("[data-activate]");
  if (actBtn) {
    const token = (document.getElementById("token-input").value || "").trim();
    const result = document.getElementById("activate-result");
    if (!token) { result.textContent = "请先粘贴许可令牌"; return; }
    actBtn.disabled = true;
    try {
      const res = await fetch("/api/activate", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "token=" + encodeURIComponent(token),
      });
      const d = await res.json();
      if (!res.ok || !d.saved) throw new Error(d.error || "导入失败");
      const s = d.status || {};
      state.flash = s.valid
        ? `许可已导入：${s.edition === "pro" ? "专业版" : "标准版"}${s.is_trial ? " · 30 天试用" : ""}（剩余 ${s.days_remaining} 天）`
        : "令牌已保存但校验未通过，请确认是否过期或被吊销。";
      await loadAll();
    } catch (err) {
      result.textContent = "导入失败：" + (err.message || err);
    } finally {
      actBtn.disabled = false;
    }
    return;
  }

  const deactBtn = e.target.closest("[data-deactivate]");
  if (deactBtn) {
    if (!confirm("确定清除本地许可、回到社区版？")) return;
    try {
      await fetch("/api/license/deactivate", { method: "POST" });
      state.flash = "已清除本地许可，回到社区版。";
      await loadAll();
    } catch (err) {
      alert("清除失败：" + (err.message || err));
    }
    return;
  }

  // —— 导入 / 导出 ——
  const importRun = e.target.closest("[data-import-run]");
  if (importRun) {
    const ta = document.getElementById("import-log");
    const log = (ta && ta.value || "").trim();
    const result = document.getElementById("import-result");
    if (!log) { result.textContent = "请先粘贴或上传日志"; return; }
    importRun.disabled = true;
    result.textContent = "分析中…";
    try {
      const res = await fetch("/api/import", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: log,
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "导入失败");
      const s = d.stats || {};
      result.textContent =
        `完成：解析 ${esc(s.parsed)} 行 → 观测 ${esc(s.flows)} 条，`
        + `新增设备 ${esc(s.new_devices)} 台、新增告警 ${esc(s.new_alerts)} 条`
        + (s.truncated ? `（已截断 ${esc(s.truncated)} 行）` : "");
      await loadAll();
    } catch (err) {
      result.textContent = "导入失败：" + (err.message || err);
    } finally {
      importRun.disabled = false;
    }
    return;
  }

  const reportBtn = e.target.closest("[data-report]");
  if (reportBtn) {
    const fmt = reportBtn.dataset.report;
    try {
      const res = await fetch("/api/report?format=" + encodeURIComponent(fmt));
      if (!res.ok) throw new Error("HTTP " + res.status);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fmt === "json" ? "homeward-report.json" : "homeward-report.md";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("导出失败：" + (err.message || err));
    }
    return;
  }
});

// 文件选择：把上传的日志读进文本框（不自动上传）
document.getElementById("view").addEventListener("change", (e) => {
  const fileInput = e.target.closest("#import-file");
  if (fileInput && fileInput.files && fileInput.files[0]) {
    const file = fileInput.files[0];
    const reader = new FileReader();
    reader.onload = () => {
      const ta = document.getElementById("import-log");
      if (ta) ta.value = reader.result;
    };
    reader.readAsText(file);
  }
});

document.getElementById("btn-refresh").addEventListener("click", () => loadAll());

document.getElementById("auto-refresh").addEventListener("change", (e) => {
  if (e.target.checked) {
    state.timer = setInterval(loadAll, REFRESH_MS);
  } else {
    clearInterval(state.timer);
    state.timer = null;
  }
});

loadAll();
state.timer = setInterval(loadAll, REFRESH_MS);
