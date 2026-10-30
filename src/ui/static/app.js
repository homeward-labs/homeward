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
  loaded: false,  // 首屏加载态：首次 render 时为 false，loadAll() 结束后置 true
  // P1-5 设备视图打磨：前端筛选/搜索/分组，不碰后端
  deviceSearch: "",              // 搜索框值（name/vendor/mac/ips 子串）
  deviceRiskFilter: "all",      // risk_level 筛选：all/high/medium/low
  deviceGroupBy: "vendor",      // 分组：vendor（厂商）/none（平铺）
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

// P1-6 部署网络模式自检：根据不可用的采集器给出修复建议
// 家卫社区版最常见的坑就是 bridge 容器里 conntrack 不可用——用户看到"不可用"但不知道为什么
function renderCollectorHints(collectors) {
  const hints = [];

  const ct = collectors.find((c) => c.collector === "ConntrackCollector");
  if (ct && !ct.active) {
    // bridge 容器里必然读不到 /proc/net/nf_conntrack，也没 conntrack 命令
    hints.push(`
      <div class="note" style="margin-top:10px;background:var(--accent-soft);border-left:3px solid var(--accent)">
        <strong>Tier 2 · 连接元数据 不可用</strong> — 这通常意味着你用的是 Docker 默认的 <code>bridge</code> 网络模式。
        容器独立的 netns 里读不到宿主机的 <code>/proc/net/nf_conntrack</code>，也没有 <code>conntrack</code> 命令。
        <div style="margin-top:4px">
          <strong>修复方式</strong>（二选一）：
          <ul style="margin:4px 0 4px 20px;padding:0">
            <li>把容器改成 <code>--network host</code>（最简单，容器直接用宿主机网络栈）</li>
            <li>或者把宿主机的 <code>/proc/net/nf_conntrack</code> 挂进容器：<code>-v /proc/net/nf_conntrack:/proc/net/nf_conntrack:ro</code>，并确保容器里装了 <code>conntrack-tools</code></li>
          </ul>
          Tier 2 不可用时家卫仍能跑（只有 Tier 1 DNS 观测），但会看不见直连 IP 流量、设备字节数、连接时长等元数据。
        </div>
      </div>`);
  }

  const dnsmasq = collectors.find((c) => c.collector === "DnsLogCollector");
  if (dnsmasq && !dnsmasq.active) {
    hints.push(`
      <div class="note" style="margin-top:10px;background:var(--danger-soft);border-left:3px solid var(--danger)">
        <strong>Tier 1 · DNS（dnsmasq）不可用</strong> — 家卫需要 dnsmasq 的查询日志来发现「设备 ↔ 域名」关联。
        <div style="margin-top:4px">
          检查 dnsmasq 是否已开启查询日志（<code>log-queries</code> 配置项），以及运行家卫的进程是否有读权限。
          如果你的路由器用的是 OpenWrt，通常只需要 <code>opkg update && opkg install dnsmasq</code>（默认已装）。
        </div>
      </div>`);
  }

  return hints.join("");
}

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
  state.loaded = false;   // 加载中，render() 显示骨架
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
  // P1-2 用户配置（AI 后端状态等）：容错拉取
  try {
    state.data.config = await api("/api/config");
  } catch {
    state.data.config = {};
  }
  state.loaded = true;    // 全部拉完（无论中间哪些报错）
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
          <span style="font-size:26px;font-weight:700">${esc(c.score)}<span style="font-size:14px;color:var(--text-muted)"> /100</span></span>
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
  const chk = d.checkup || {};
  const rate = Math.round((cov.hit_rate || 0) * 100);
  const visRate = Math.round((vis.rate || 0) * 100);
  const score = chk.score ?? 0;
  const unknownCount = chk.unknown_count ?? 0;

  const counts = as.by_severity || {};
  const sevLine = ["critical", "high", "medium", "low"]
    .filter((k) => counts[k])
    .map((k) => `<span class="sev sev-${k}">${esc(counts[k])}</span>`)
    .join(" ") || '<span class="muted">无</span>';

  const topDest = (state.data.destinations?.items || []).slice(0, 6);
  const recentAlerts = (state.data.alerts?.items || []).slice(0, 3);

  // —— 前端聚合：设备厂商 / 去向分类 / 告警严重度（零后端改动） ——
  const vendors = {};
  (state.data.devices?.items || []).forEach((x) => {
    const v = x.vendor || "未知厂商";
    vendors[v] = (vendors[v] || 0) + 1;
  });
  const vendorItems = Object.entries(vendors).sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([k, v]) => ({ label: k, value: v }));

  const catColors = {
own: "var(--ok)", benign: "var(--text-muted)", tracker: "var(--warn)", ads: "var(--sev-high)",
    cdn: "var(--accent)", social: "var(--cat-social)", ai: "var(--cat-ai)", productivity: "var(--cat-productivity)",
    cloud: "var(--cat-cloud)", unknown: "var(--cat-unknown)", iot_core: "var(--warn)", iot: "var(--warn)",
    advertising_sdk: "var(--sev-high)", cloud_storage: "var(--cat-cloud)", analytics: "var(--cat-social)",
    telemetry: "var(--cat-productivity)", tracking: "var(--warn)", malware: "var(--danger)", phishing: "var(--danger)",
  };
  const cats = {};
  (state.data.destinations?.items || []).forEach((x) => {
    const c = (x.category || "unknown").toLowerCase();
    cats[c] = (cats[c] || 0) + 1;
  });
  const catItems = Object.entries(cats).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ label: k, value: v, color: catColors[k] || "var(--cat-unknown)" }));

  const sevColors = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };
  const sevItems = ["critical", "high", "medium", "low"].filter((k) => counts[k])
    .map((k) => ({ label: k, value: counts[k], color: sevColors[k] }));

  // 采集器状态条：如实展示「我能看多少」（保留原逻辑）
  const collectors = d.collection_status || [];
  const collectorBar = collectors.length ? `
    <div class="section">
      <h2>采集器状态 <span class="count">（${collectors.filter((c) => c.active).length}/${collectors.length} 个活跃）</span></h2>
      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:8px">
        ${collectors.map((c) => {
          const name = c.collector === "DnsLogCollector" ? "Tier 1 · DNS（dnsmasq）"
            : c.collector === "SyslogDnsCollector" ? "Tier 1 · DNS（syslog）"
            : c.collector === "ConntrackCollector" ? "Tier 2 · 连接元数据（conntrack）"
            : c.collector;
          const color = c.active ? "var(--ok)" : "var(--danger)";
          const icon = c.active ? "●" : "○";
          return `<div style="display:flex;align-items:center;gap:6px;padding:6px 10px;border-radius:6px;background:${c.active ? "var(--ok-soft)" : "var(--danger-soft)"}">
            <span style="color:${color};font-size:12px">${icon}</span>
            <span style="font-weight:500">${esc(name)}</span>
            <span class="small muted" title="${esc(c.reason || "")}">${c.active ? "活跃" : "不可用"}</span>
          </div>`;
        }).join("")}
      </div>
      ${renderCollectorHints(collectors)}
      <div class="small muted" style="margin-top:6px">
        Tier 1 看不见直连 IP 流量（设备硬编码 IP / 加密 DNS 绕过）；Tier 2 补连接元数据（字节数 / 连接时长），但也看不见加密域名（Tier 3 标准版）。<strong>两个 Tier 都不生效时，家卫等同于一块「只知道有多少设备」的空板。</strong>
      </div>
    </div>` : "";

  return `
    <div class="hero">
      <div class="ring-wrap">
        ${HWCharts.donut({
          size: 168, stroke: 15,
          segments: [
            { value: score, color: score >= 80 ? "var(--ok)" : (score >= 60 ? "var(--accent)" : "var(--warn)") },
            { value: Math.max(100 - score, 0), color: "var(--chart-track)" },
          ],
          ariaLabel: "防护健康分 " + score + " 分（满分 100）",
        })}
        <div class="ring-center">
          <div class="ring-pct">${esc(score)}</div>
          <div class="ring-cap">健康分 / 100</div>
        </div>
        <div class="ring-pulse" title="实时守护中"></div>
      </div>
      <div class="hero-body">
        <div class="hero-title">${esc(chk.verdict || "家庭网络态势")}</div>
        <div class="hero-sub">家卫正在守护 ${esc(s.devices_total ?? 0)} 台设备 · 域名归属覆盖 ${rate}%</div>
        <div class="hero-kpis">
          <div class="hk"><div class="n">${esc(as.active ?? 0)}</div><div class="l">活跃告警</div></div>
          <div class="hk"><div class="n">${esc(vis.visible ?? 0)}</div><div class="l">可见设备</div></div>
          <div class="hk"><div class="n">${rate}%</div><div class="l">域名覆盖率</div></div>
        </div>
      </div>
    </div>

    ${collectorBar}

    <div class="section">
      <div class="grid">
        <div class="stat"><div class="k">设备</div><div class="v">${esc(s.devices_total ?? 0)}</div>
          <div class="sub">${esc(s.vendors_resolved ?? 0)} 台识别出厂商</div></div>
        <div class="stat"><div class="k">观测记录</div><div class="v">${esc(s.flows_processed ?? 0)}</div>
          <div class="sub">决策 ${esc(s.decisions_made ?? 0)} 条</div></div>
        <div class="stat"><div class="k">活跃告警</div><div class="v">${esc(as.active ?? 0)}</div>
          <div class="sub">${sevLine}</div></div>
        <div class="stat"><div class="k">域名归属覆盖率</div><div class="v">${rate}%</div>
          <div class="sub">${esc(cov.hit ?? 0)} / ${esc(cov.total ?? 0)} 认得出来</div>
          <div class="bar" style="margin-top:6px"><i style="width:${rate}%"></i></div></div>
        <div class="stat"><div class="k">设备观测覆盖</div><div class="v">${esc(vis.visible ?? 0)} / ${esc(vis.suspected_invisible ?? 0)}</div>
          <div class="sub">可见 / 疑似不可见</div>
          <div class="bar" style="margin-top:6px"><i style="width:${visRate}%"></i></div></div>
        <div class="stat"><div class="k">未知域名</div><div class="v">${esc(unknownCount)}</div>
          <div class="sub">盲区 ${esc(spots.length)} 项</div></div>
      </div>
    </div>

    <div class="section">
      <div class="chart-grid">
        <div class="chart-card">
          <h3>设备厂商分布</h3>
          <div class="chart-hint">按识别出的厂商统计设备数</div>
          ${vendorItems.length ? HWCharts.hbar({ items: vendorItems, ariaLabel: "设备厂商分布" })
            : '<div class="empty">暂无设备数据</div>'}
        </div>
        <div class="chart-card">
          <h3>外联去向分类</h3>
          <div class="chart-hint">观测到的域名按归属类别分布</div>
          ${catItems.length ? HWCharts.donut({ size: 168, stroke: 20, segments: catItems.map((i) => ({ value: i.value, color: i.color })), ariaLabel: "外联去向分类" }) : '<div class="empty">暂无去向</div>'}
          <div class="legend">${catItems.map((i) => `<span class="legend-item"><span class="legend-swatch round" style="background:${esc(i.color)}"></span>${esc(i.label)} ${esc(i.value)}</span>`).join("")}</div>
        </div>
        <div class="chart-card">
          <h3>告警严重度</h3>
          <div class="chart-hint">按严重度分布活跃告警</div>
          ${sevItems.length ? HWCharts.donut({ size: 168, stroke: 20, segments: sevItems.map((i) => ({ value: i.value, color: i.color })), ariaLabel: "告警严重度分布" }) : '<div class="empty">暂无告警，网络很清净</div>'}
          <div class="legend">${sevItems.map((i) => `<span class="legend-item"><span class="legend-swatch round" style="background:${esc(i.color)}"></span>${esc(i.label)} ${esc(i.value)}</span>`).join("")}</div>
        </div>
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
  const all = state.data.devices?.items || [];

  // 厂商分布柱状图（前端聚合，零后端改动）
  const _vendors = {};
  all.forEach((x) => { const v = x.vendor || "未知厂商"; _vendors[v] = (_vendors[v] || 0) + 1; });
  const _vendorItems = Object.entries(_vendors).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([k, v]) => ({ label: k, value: v }));
  const vendorChart = _vendorItems.length ? `
    <div class="section">
      <div class="chart-grid">
        <div class="chart-card">
          <h3>设备厂商分布</h3>
          <div class="chart-hint">按识别出的厂商统计设备数（前 10）</div>
          ${HWCharts.hbar({ items: _vendorItems, ariaLabel: "设备厂商分布" })}
        </div>
      </div>
    </div>` : "";

  // —— 搜索（子串模糊匹配 name/vendor/mac/ips） ——
  const q = state.deviceSearch.trim().toLowerCase();
  let items = all;
  if (q) {
    items = items.filter((d) => {
      const hay = [
        d.name || "", d.vendor || "", d.mac || "",
        ...(d.ips || []),
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }

  // —— 风险筛选 ——
  if (state.deviceRiskFilter !== "all") {
    items = items.filter((d) => d.risk_level === state.deviceRiskFilter);
  }

  if (!items.length) {
    // 有设备但全被筛掉了 → 友好提示
    if (all.length) {
      return `<div class="section"><div class="card empty">筛选后无匹配设备。<a href="#" data-device-reset>清除筛选</a>。</div></div>`;
    }
    return '<div class="card empty">设备台账为空。家卫通过 DHCP 租约与 ARP 表发现设备 —— 若以单网口 Docker 形态运行，可能读不到这些数据，详见「盲区」页。</div>';
  }

  // —— 分组 / 平铺 ——
  const groupByVendor = state.deviceGroupBy === "vendor";
  const groups = {};
  if (groupByVendor) {
    for (const d of items) {
      const g = d.vendor || "未知厂商";
      (groups[g] ||= []).push(d);
    }
  } else {
    groups[""] = items; // 平铺
  }

  // 每组按风险排序（组内保留原排序逻辑）
  const groupOrder = groupByVendor
    ? Object.keys(groups).sort((a, b) => {
        // 未知厂商放最后
        if (a === "未知厂商") return 1;
        if (b === "未知厂商") return -1;
        return a.localeCompare(b, "zh");
      })
    : [""];

  const high = items.filter((d) => d.risk_level === "high").length;
  const mid = items.filter((d) => d.risk_level === "medium").length;

  const riskOpts = [
    { v: "all", label: `全部（${all.length} 台）` },
    { v: "high", label: `高风险（${all.filter((d) => d.risk_level === "high").length}）` },
    { v: "medium", label: `需关注（${all.filter((d) => d.risk_level === "medium").length}）` },
    { v: "low", label: `低风险（${all.filter((d) => d.risk_level === "low").length}）` },
  ].map((o) =>
    `<option value="${o.v}" ${state.deviceRiskFilter === o.v ? "selected" : ""}>${o.label}</option>`
  ).join("");

  const groupOpts = [
    { v: "vendor", label: "按厂商分组" },
    { v: "none", label: "平铺（不分组）" },
  ].map((o) =>
    `<option value="${o.v}" ${state.deviceGroupBy === o.v ? "selected" : ""}>${o.label}</option>`
  ).join("");

  const renderTable = (rows) => `
    <div class="card scroll-x">
      <table>
        <thead><tr>
          <th>名称 / 品类</th><th>IP</th><th>MAC</th><th>厂商</th><th>风险</th><th>最近活跃</th><th>主要去向</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  const renderRow = (d) => `
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
    </tr>`;

  // 组装各分组
  const groupSections = groupOrder.map((g) => {
    const list = groups[g];
    if (!groupByVendor) return renderTable(list.map(renderRow).join(""));
    const highG = list.filter((d) => d.risk_level === "high").length;
    return `
      <div style="margin-top:16px">
        <h3 style="font-size:14px;color:var(--text-2);margin-bottom:8px">
          ${esc(g)} <span class="count">（${list.length} 台${highG ? ` · 高风险 ${highG}` : ""}）</span>
        </h3>
        ${renderTable(list.map(renderRow).join(""))}
      </div>`;
  }).join("");

  return `
    ${vendorChart}
    <div class="section">
      <h2>设备画像 <span class="count">（${items.length}/${all.length} 台；高风险 ${high} 台、需关注 ${mid} 台）</span></h2>

      <!-- 搜索 + 筛选 + 分组 工具栏 -->
      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px;align-items:center">
        <input
          type="search"
          placeholder="搜索：名称 / 厂商 / MAC / IP"
          value="${esc(state.deviceSearch)}"
          data-device-search
          style="flex:1;min-width:180px;padding:6px 10px;border:1px solid var(--border-strong);border-radius:6px;font-size:13px"
        >
        <select data-device-risk style="padding:6px 10px;border:1px solid var(--border-strong);border-radius:6px;font-size:13px">
          ${riskOpts}
        </select>
        <select data-device-group style="padding:6px 10px;border:1px solid var(--border-strong);border-radius:6px;font-size:13px">
          ${groupOpts}
        </select>
        ${(state.deviceSearch || state.deviceRiskFilter !== "all")
          ? `<a href="#" data-device-reset style="font-size:13px;color:var(--accent)">清除筛选</a>` : ""}
      </div>

      ${groupSections}
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
  const rate = Math.round((d.hit_rate || 0) * 100);
  if (!items.length) return '<div class="card empty">还没有观测到任何外联去向。</div>';

  // 前端聚合：分类饼图 + Top 域名横向柱状（零后端改动）
  const catColors = {
own: "var(--ok)", benign: "var(--text-muted)", tracker: "var(--warn)", ads: "var(--sev-high)",
    cdn: "var(--accent)", social: "var(--cat-social)", ai: "var(--cat-ai)", productivity: "var(--cat-productivity)",
    cloud: "var(--cat-cloud)", unknown: "var(--cat-unknown)", iot_core: "var(--warn)", iot: "var(--warn)",
    advertising_sdk: "var(--sev-high)", cloud_storage: "var(--cat-cloud)", analytics: "var(--cat-social)",
    telemetry: "var(--cat-productivity)", tracking: "var(--warn)", malware: "var(--danger)", phishing: "var(--danger)",
  };
  const cats = {};
  items.forEach((x) => { const c = (x.category || "unknown").toLowerCase(); cats[c] = (cats[c] || 0) + 1; });
  const catItems = Object.entries(cats).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ label: k, value: v, color: catColors[k] || "var(--cat-unknown)" }));
  const byDevices = items.map((x) => ({
    label: x.domain,
    value: (x.devices || []).reduce((a, dd) => a + (dd.count || 1), 0) || 1,
  })).sort((a, b) => b.value - a.value).slice(0, 8);
  const maxDev = Math.max.apply(null, byDevices.map((x) => x.value).concat([1]));

  return `
    <div class="section">
      <div class="chart-grid">
        <div class="chart-card">
          <h3>去向分类占比</h3>
          <div class="chart-hint">所有观测到的域名按归属类别分布</div>
          ${catItems.length ? HWCharts.donut({ size: 180, stroke: 22, segments: catItems.map((i) => ({ value: i.value, color: i.color })), ariaLabel: "去向分类占比" }) : '<div class="empty">暂无数据</div>'}
          <div class="legend">${catItems.map((i) => `<span class="legend-item"><span class="legend-swatch round" style="background:${esc(i.color)}"></span>${esc(i.label)} ${esc(i.value)}</span>`).join("")}</div>
        </div>
        <div class="chart-card">
          <h3>Top 域名（按请求热度）</h3>
          <div class="chart-hint">涉及请求量最高的 8 个域名</div>
          ${byDevices.length ? HWCharts.hbar({ items: byDevices, max: maxDev, ariaLabel: "Top 域名请求热度" }) : '<div class="empty">暂无数据</div>'}
        </div>
      </div>
    </div>

    <div class="section">
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
  // 前端聚合：严重度柱状 + 饼图（零后端改动）
  const sevColors = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };
  const counts = {};
  items.forEach((a) => { counts[a.severity] = (counts[a.severity] || 0) + 1; });
  const sevItems = ["critical", "high", "medium", "low"].filter((k) => counts[k])
    .map((k) => ({ label: k, value: counts[k], color: sevColors[k] }));

  return `
    <div class="section">
      <div class="chart-grid">
        <div class="chart-card">
          <h3>告警严重度分布</h3>
          <div class="chart-hint">按严重度统计活跃告警数量</div>
          ${sevItems.length ? HWCharts.donut({ size: 180, stroke: 22, segments: sevItems.map((i) => ({ value: i.value, color: i.color })), ariaLabel: "告警严重度分布" }) : '<div class="empty">暂无告警</div>'}
          <div class="legend">${sevItems.map((i) => `<span class="legend-item"><span class="legend-swatch round" style="background:${esc(i.color)}"></span>${esc(i.label)} ${esc(i.value)}</span>`).join("")}</div>
        </div>
        <div class="chart-card">
          <h3>严重度柱状</h3>
          <div class="chart-hint">各严重度告警数对比</div>
          ${sevItems.length ? HWCharts.vbar({ items: sevItems.map((i) => ({ label: i.label, value: i.value, color: i.color })), ariaLabel: "告警严重度柱状" }) : '<div class="empty">暂无告警</div>'}
        </div>
      </div>
    </div>

    <div class="section">
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

  const maxDevices = Math.max.apply(null, points.map((p) => p.devices_total).concat([1]));
  const maxAlerts = Math.max.apply(null, points.map((p) => p.alerts_active).concat([1]));
  const first = points[0], last = points[points.length - 1];

  const devPts = points.map((p) => ({ y: p.devices_total }));
  const alertPts = points.map((p) => ({ y: p.alerts_active }));
  const scorePts = points.map((p) => ({ y: p.privacy_score }));

  const summary = `
    <div class="card" style="display:flex;gap:24px;flex-wrap:wrap">
      <div><div class="muted small">窗口</div><div><b>${points.length}</b> 小时（${currentDays} 天）</div></div>
      <div><div class="muted small">设备峰值</div><div><b>${maxDevices}</b> 台</div></div>
      <div><div class="muted small">告警峰值</div><div><b>${maxAlerts}</b> 条</div></div>
      <div><div class="muted small">起始隐私分</div><div><b>${first.privacy_score}</b></div></div>
      <div><div class="muted small">当前隐私分</div><div><b>${last.privacy_score}</b></div></div>
    </div>`;

  const rangeBtn = (days, label) => `
    <button class="btn btn-sm ${currentDays === days ? "is-active" : "is-muted"}"
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
        ${HWCharts.areaMulti({
          height: 170, max: Math.max(maxDevices, maxAlerts),
          series: [
            { points: devPts, color: "var(--accent)", fill: true },
            { points: alertPts, color: "var(--danger)", fill: false },
          ],
          ariaLabel: "设备数与告警趋势",
        })}
        ${HWCharts.areaMulti({
          height: 120, max: 100,
          series: [{ points: scorePts, color: "var(--cat-productivity)", fill: true }],
          ariaLabel: "隐私分趋势（0-100）",
        })}
      </div>
      <div class="muted small" style="margin-top:8px">提示：设备数（蓝）与告警（红）共享左轴；隐私分（青，0-100）单独成图。数据只存在本地 SQLite，不联网。</div>
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
  // P1-5 清除设备筛选
  const reset = e.target.closest("[data-device-reset]");
  if (reset) {
    e.preventDefault();
    state.deviceSearch = "";
    state.deviceRiskFilter = "all";
    render();
  }
});

// P1-5 设备搜索（input 实时触发）
document.addEventListener("input", (e) => {
  const el = e.target.closest("[data-device-search]");
  if (el) {
    state.deviceSearch = el.value;
    render();
  }
});

// P1-5 设备筛选 / 分组（change 触发）
document.addEventListener("change", (e) => {
  const risk = e.target.closest("[data-device-risk]");
  if (risk) {
    state.deviceRiskFilter = risk.value;
    render();
  }
  const group = e.target.closest("[data-device-group]");
  if (group) {
    state.deviceGroupBy = group.value;
    render();
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
  const rowUnknown = (x, aiOn) => `
    <div class="item is-unknown">
      <div class="item-head">
        <span class="item-title mono">${esc(x)}</span>
        ${aiOn
          ? `<button class="btn btn-sm" type="button" data-ai-analyze data-domain="${esc(x)}">AI 帮我分析</button>`
          : `<button class="btn btn-sm" type="button" disabled
             title="需在设置里启用 AI 后端（本地 Ollama 或 OpenAI 兼容 Key）">AI 分析未启用</button>`}
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
  const aiOn = !!(state.data.config && state.data.config.ai_backend
                  && state.data.config.ai_backend !== "none");
  html += items.length
    ? `<div class="list" style="margin-top:10px">${items.map(x => rowUnknown(x, aiOn)).join("")}</div>`
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

function renderSettings() {
  const cfg = state.data.config || {};
  const backend = cfg.ai_backend || "none";
  const keySet = !!cfg.ai_api_key_set;
  const baseUrl = cfg.ai_base_url || "";
  const model = cfg.ai_model || "";

  return `
    <div class="section">
      <h2>设置</h2>
      <div class="note">
        AI 分析默认关闭，启用需自备后端：本地 Ollama（<code>ollama run qwen2.5:7b</code>）
        或任意 OpenAI 兼容接口。<strong>结果只在你手动触发时才调用，不会自动联网。</strong>
      </div>

      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 12px">AI 辅助分析（P1-2）</h3>
        <div style="display:flex;flex-direction:column;gap:10px">
          <div style="display:flex;gap:8px;align-items:center">
            <label style="width:100px">后端类型</label>
            <select id="cfg-ai-backend" style="flex:1;max-width:220px">
              <option value="none" ${backend === "none" ? "selected" : ""}>关闭</option>
              <option value="ollama" ${backend === "ollama" ? "selected" : ""}>本地 Ollama</option>
              <option value="openai" ${backend === "openai" ? "selected" : ""}>OpenAI 兼容</option>
            </select>
            <span class="small muted">${backend !== "none" ? "(已启用)" : "(未启用)"}</span>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <label style="width:100px">API Key</label>
            <input id="cfg-ai-key" type="password" placeholder="${keySet ? '*** 已配置（留空保持不变）' : 'sk-... 或其他兼容 Key'}" style="flex:1;max-width:320px">
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <label style="width:100px">Base URL</label>
            <input id="cfg-ai-url" type="text" placeholder="${backend === 'ollama' ? '默认本地 11434 端口' : '默认官方兼容端点'}" value="${esc(baseUrl)}" style="flex:1;max-width:320px">
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <label style="width:100px">模型名</label>
            <input id="cfg-ai-model" type="text" placeholder="${backend === 'ollama' ? 'qwen2.5:7b' : 'gpt-4o-mini'}" value="${esc(model)}" style="flex:1;max-width:220px">
          </div>
        </div>
        <div class="item-foot" style="margin-top:14px">
          <button class="btn" type="button" data-save-ai-cfg>保存设置</button>
          <span class="small muted">保存后立即生效，无需重启。API Key 只写本地 <code>data/config.json</code>，不发送到任何其他地方。</span>
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
  // 早鸟假门 URL 同由服务端下发（HOMEWARD_EARLYBIRD_URL），未配置时前端展示「待上线」降级态。
  const earlybirdUrl = lic.earlybird_url || "";
  const ebClicks = (() => {
    try { return parseInt(localStorage.getItem("homeward_earlybird_cta") || "0", 10) || 0; }
    catch (e) { return 0; }
  })();
  const valid = !!status.valid;
  const reason = status.reason || "none";

const planRows = [
    ["月付", "¥19.9 / 月", "灵活尝鲜"],
    ["3 个月", "¥49", "季度体验"],
    ["6 个月", "¥79", "半年用户"],
    ["年付", "¥99 / 年", "主推 · 单价最低"],
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
    ? `<div class="note" style="border-color:var(--ok);background:var(--ok-surface)">${esc(state.flash)}</div>` : "";

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
      <h2>早鸟抢先 · 标准版首年 ¥69</h2>
      <div class="card">
        <div class="item-head">
          <span class="item-title">早鸟名额占位</span>
          <span class="sev sev-medium">限 100 名</span>
        </div>
        <div class="item-body small muted">原价 ¥99/年 → 早鸟 ¥69/年；先占位、不收款，开售前按占位顺序邮件通知，名额满自动转候补。</div>
        <div class="item-foot">
          ${earlybirdUrl
            ? `<a class="btn btn-primary" href="${esc(earlybirdUrl)}" target="_blank" rel="noopener" data-earlybird>抢早鸟名额</a>`
            : `<button class="btn" type="button" disabled title="早鸟假门尚未上线（服务端未配置 HOMEWARD_EARLYBIRD_URL）">抢早鸟（待上线）</button>`}
          <span class="small muted">本机点击 ${ebClicks} 次（仅本地统计，不外发）</span>
        </div>
      </div>
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
  settings: renderSettings,
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

  // 首屏加载态：服务刚起来时 fetch 还没回来，显示骨架而非全零值
  const loading = (!state.loaded && !state.error)
    ? `<div class="section"><div class="card empty">加载中… 正在拉取设备清单、观测记录与告警。服务首次启动约 5–15 秒完成采集器协商。</div></div>`
    : "";

  const body = state.error ? "" : (RENDERERS[state.view] || renderOverview)();
  view.innerHTML = err + loading + body;
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

  // —— P1-2：AI 手动分析未知域名 ——
  const aiBtn = e.target.closest("[data-ai-analyze]");
  if (aiBtn) {
    const domain = aiBtn.dataset.domain || "";
    if (!domain) return;
    aiBtn.disabled = true;
    aiBtn.textContent = "分析中…";
    try {
      const r = await fetch("/api/ai/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const j = await r.json().catch(() => ({}));
      if (j.ok) {
        const msg = [
          `域名 ${j.domain}`,
          `归属：${j.organization || "未知"}`,
          `类型：${j.category || "unknown"}（置信度 ${j.confidence || "low"}）`,
          `建议：${j.suggested_action || "warn"}`,
          "",
          j.explanation || "",
        ].join("\n");
        alert(msg);
        await loadAll();
      } else if (j.reason === "ai_not_enabled") {
        alert("AI 后端未启用。请在「升级」Tab 的 AI 配置区设置本地 Ollama 或 OpenAI 兼容 Key。");
      } else {
        alert("AI 分析失败：" + (j.reason || "未知错误"));
      }
    } catch (err) {
      alert("AI 分析网络错误：" + (err.message || err));
    } finally {
      aiBtn.disabled = false;
      aiBtn.textContent = "AI 帮我分析";
    }
    return;
  }

  // —— P1-2：保存 AI 配置 ——
  const saveCfgBtn = e.target.closest("[data-save-ai-cfg]");
  if (saveCfgBtn) {
    const backend = document.getElementById("cfg-ai-backend")?.value || "none";
    const apiKey = document.getElementById("cfg-ai-key")?.value || "";
    const baseUrl = document.getElementById("cfg-ai-url")?.value || "";
    const model = document.getElementById("cfg-ai-model")?.value || "";
    saveCfgBtn.disabled = true;
    try {
      const body = { ai_backend: backend };
      if (apiKey) body.ai_api_key = apiKey;
      if (baseUrl) body.ai_base_url = baseUrl;
      if (model) body.ai_model = model;
      const r = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (j.ok) {
        alert(`已保存：${(j.saved || []).join(", ") || "（无变更）"}\nAI 后端已${backend !== "none" ? "启用" : "关闭"}，立即生效。`);
        await loadAll();
      } else {
        alert("保存失败：" + (j.reason || "未知错误"));
      }
    } catch (err) {
      alert("保存网络错误：" + (err.message || err));
    } finally {
      saveCfgBtn.disabled = false;
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

  const earlybirdBtn = e.target.closest("[data-earlybird]");
  if (earlybirdBtn) {
    // 本地埋点：仅统计本机 CTA 点击次数，不发送任何数据（零遥测红线）
    try {
      const n = parseInt(localStorage.getItem("homeward_earlybird_cta") || "0", 10) || 0;
      localStorage.setItem("homeward_earlybird_cta", String(n + 1));
    } catch (er) { /* 隐私模式等场景忽略，不影响跳转 */ }
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
