/* 家卫 Homeward · 图表库（零依赖手写 SVG）
   —— 不引任何第三方库；所有动态文本经 esc() 转义；纯 SVG，随容器宽度缩放。
   暴露全局 HWCharts：{ donut, hbar, vbar, area }。 */

(function () {
  "use strict";

  // 转义：与 app.js 的 esc 同语义，防 XSS
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // 角度（度，12 点方向起、顺时针）→ SVG 圆弧 path
  function arcPath(cx, cy, r, startDeg, endDeg) {
    var s = (startDeg - 90) * Math.PI / 180;
    var e = (endDeg - 90) * Math.PI / 180;
    var x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s);
    var x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e);
    var large = (endDeg - startDeg) % 360 > 180 ? 1 : 0;
    return "M" + x1.toFixed(2) + " " + y1.toFixed(2) +
      " A" + r.toFixed(2) + " " + r.toFixed(2) + " 0 " + large + " 1 " +
      x2.toFixed(2) + " " + y2.toFixed(2);
  }

  // 环形 / 饼图：segments = [{value, color, label}]
  // opts: { size=180, stroke=16, track="var(--chart-track)", gap=2, ariaLabel }
  // 仅返回纯 SVG；中心文字由调用方用 .ring-center 绝对定位叠加。
  function donut(opts) {
    opts = opts || {};
    var size = opts.size || 180;
    var stroke = opts.stroke || 16;
    var track = opts.track || "var(--chart-track)";
    var gap = typeof opts.gap === "number" ? opts.gap : 2;
    var cx = size / 2, cy = size / 2;
    var r = (size - stroke) / 2;
    var segs = (opts.segments || []).filter(function (x) { return x.value > 0; });
    var total = segs.reduce(function (a, x) { return a + x.value; }, 0);

    var parts = ['<circle cx="' + cx + '" cy="' + cy + '" r="' + r.toFixed(2) +
      '" fill="none" stroke="' + esc(track) + '" stroke-width="' + stroke + '"/>'];

    if (total > 0) {
      var acc = 0;
      segs.forEach(function (sg) {
        var ang = sg.value / total * 360;
        var start = acc + gap / 2;
        var end = acc + ang - gap / 2;
        acc += ang;
        if (end <= start) { start = acc - ang; end = acc - 0.01; }
        parts.push('<path d="' + arcPath(cx, cy, r, start, end) +
          '" fill="none" stroke="' + esc(sg.color) + '" stroke-width="' + stroke +
          '" stroke-linecap="round"/>');
      });
    }

    return '<svg viewBox="0 0 ' + size + ' ' + size + '" role="img" aria-label="' +
      esc(opts.ariaLabel || "环形图") + '" style="max-width:' + size + 'px;margin:0 auto;display:block">' +
      parts.join("") + '</svg>';
  }

  // 横向柱状图：items = [{label, value, color?}]
  // opts: { max, rowH=30, labelW=130, barColor="var(--accent)", unit="" }
  function hbar(opts) {
    opts = opts || {};
    var items = opts.items || [];
    var rowH = opts.rowH || 30;
    var labelW = opts.labelW || 130;
    var barColor = opts.barColor || "var(--accent)";
    var unit = opts.unit || "";
    var max = opts.max || Math.max.apply(null, items.map(function (x) { return x.value; }).concat([1]));
    var gap = 6;
    var w = 100, barArea = w - labelW; // 0..100 坐标系
    var h = Math.max(items.length * (rowH + gap) - gap, rowH);

    var body = items.map(function (it, i) {
      var pct = max > 0 ? (it.value / max * 100) : 0;
      var c = it.color || barColor;
      var ty = i * (rowH + gap);
      return '<g transform="translate(0,' + ty + ')">' +
        '<text x="0" y="' + (rowH / 2) + '" dominant-baseline="middle" font-size="12.5" fill="var(--text-2)">' + esc(it.label) + '</text>' +
        '<rect x="' + labelW + '" y="0" width="' + barArea + '" height="' + rowH + '" rx="7" fill="var(--overlay-track)"/>' +
        '<rect x="' + labelW + '" y="0" width="' + (barArea * pct / 100).toFixed(2) + '" height="' + rowH + '" rx="7" fill="' + esc(c) + '"/>' +
        '<text x="' + (labelW + barArea + 6) + '" y="' + (rowH / 2) + '" dominant-baseline="middle" font-size="12" fill="var(--text-muted)">' +
          esc(it.value) + esc(unit) + '</text>' +
        '</g>';
    }).join("");

    return '<svg viewBox="0 0 ' + w + ' ' + h + '" role="img" aria-label="' + esc(opts.ariaLabel || "横向柱状图") +
      '" preserveAspectRatio="xMinYMid meet" style="width:100%;height:auto">' + body + '</svg>';
  }

  // 纵向柱状图：items = [{label, value, color?}]
  // opts: { max, height=180, barColor="var(--accent)", labelEvery=1 }
  function vbar(opts) {
    opts = opts || {};
    var items = opts.items || [];
    var height = opts.height || 180;
    var padTop = 10, padBottom = 22, padLeft = 6, padRight = 6;
    var barColor = opts.barColor || "var(--accent)";
    var max = opts.max || Math.max.apply(null, items.map(function (x) { return x.value; }).concat([1]));
    var n = items.length || 1;
    var areaW = 100 - padLeft - padRight;
    var bw = areaW / n * 0.62;
    var step = areaW / n;
    var plotH = height - padTop - padBottom;

    var body = items.map(function (it, i) {
      var pct = max > 0 ? (it.value / max) : 0;
      var bh = Math.max(pct * plotH, 1);
      var cx = padLeft + step * i + step / 2;
      var x = cx - bw / 2;
      var y = padTop + plotH - bh;
      var c = it.color || barColor;
      var showLabel = (opts.labelEvery || 1) > 1 ? (i % opts.labelEvery === 0 || i === items.length - 1) : true;
      var label = showLabel
        ? '<text x="' + cx + '" y="' + (height - 6) + '" text-anchor="middle" font-size="9" fill="var(--text-muted)">' + esc(it.label) + '</text>'
        : "";
      return '<g>' +
        '<rect x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + bw.toFixed(2) + '" height="' + bh.toFixed(2) +
          '" rx="3" fill="' + esc(c) + '" opacity="0.85"/>' +
        (it.value ? '<text x="' + cx + '" y="' + (y - 4).toFixed(2) + '" text-anchor="middle" font-size="9.5" fill="var(--text-2)">' + esc(it.value) + '</text>' : "") +
        label +
        '</g>';
    }).join("");

    body = '<line x1="' + padLeft + '" y1="' + (padTop + plotH) + '" x2="' + (100 - padRight) + '" y2="' + (padTop + plotH) +
      '" stroke="var(--border)" stroke-width="1"/>' + body;

    return '<svg viewBox="0 0 ' + 100 + ' ' + height + '" role="img" aria-label="' + esc(opts.ariaLabel || "纵向柱状图") +
      '" preserveAspectRatio="none" style="width:100%;height:auto">' + body + '</svg>';
  }

  // 面积 / 折线：points = [{x, y}]（y 为原始值，用 max 归一）
  // opts: { max, height=120, color="var(--accent)", fill=true, dots=false }
  function area(opts) {
    opts = opts || {};
    var pts = opts.points || [];
    var height = opts.height || 120;
    var pad = 6;
    var color = opts.color || "var(--accent)";
    var plotH = height - pad * 2;
    var n = pts.length;
    if (n === 0) return '<svg viewBox="0 0 100 ' + height + '"></svg>';
    var max = opts.max || Math.max.apply(null, pts.map(function (p) { return p.y; }).concat([1]));
    var step = n > 1 ? 100 / (n - 1) : 100;

    var coords = pts.map(function (p, i) {
      var x = n > 1 ? i * step : 50;
      var y = pad + plotH - (max > 0 ? (p.y / max) : 0) * plotH;
      return [x, y];
    });
    var line = coords.map(function (c, i) { return (i ? "L" : "M") + c[0].toFixed(2) + " " + c[1].toFixed(2); }).join(" ");
    var areaPath = line + " L100 " + (pad + plotH) + " L0 " + (pad + plotH) + " Z";

    var dots = opts.dots
      ? coords.map(function (c) { return '<circle cx="' + c[0].toFixed(2) + '" cy="' + c[1].toFixed(2) + '" r="2.4" fill="' + esc(color) + '"/>'; }).join("")
      : "";
    var gid = "g" + Math.random().toString(36).slice(2, 8);
    var fillSvg = opts.fill === false ? "" :
      '<defs><linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + esc(color) + '" stop-opacity="0.22"/>' +
      '<stop offset="100%" stop-color="' + esc(color) + '" stop-opacity="0"/></linearGradient></defs>' +
      '<path d="' + areaPath + '" fill="url(#' + gid + ')" stroke="none"/>';

    return '<svg viewBox="0 0 100 ' + height + '" role="img" aria-label="' + esc(opts.ariaLabel || "趋势图") +
      '" preserveAspectRatio="none" style="width:100%;height:auto">' +
      fillSvg + '<path d="' + line + '" fill="none" stroke="' + esc(color) + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
      dots + '</svg>';
  }

  // 多序列叠加面积图（趋势专用）：series = [{points:[{x,y}], color, fill?}]
  // 共享同一 max / 坐标系，便于对比
  function areaMulti(opts) {
    opts = opts || {};
    var series = opts.series || [];
    var height = opts.height || 140;
    var pad = 6;
    var plotH = height - pad * 2;
    var n = 0;
    series.forEach(function (s) { n = Math.max(n, s.points.length); });
    if (n === 0) return '<svg viewBox="0 0 100 ' + height + '"></svg>';
    var allMax = opts.max || 1;
    var step = n > 1 ? 100 / (n - 1) : 100;
    var defs = [], bodies = [];

    series.forEach(function (s, si) {
      var pts = s.points || [];
      var coords = pts.map(function (p, i) {
        var x = n > 1 ? i * step : 50;
        var y = pad + plotH - (allMax > 0 ? (p.y / allMax) : 0) * plotH;
        return [x, y];
      });
      var line = coords.map(function (c, i) { return (i ? "L" : "M") + c[0].toFixed(2) + " " + c[1].toFixed(2); }).join(" ");
      var color = s.color || "var(--accent)";
      if (s.fill !== false) {
        var gid = "gm" + si + Math.random().toString(36).slice(2, 6);
        defs.push('<linearGradient id="' + gid + '" x1="0" y1="0" x2="0" y2="1">' +
          '<stop offset="0%" stop-color="' + esc(color) + '" stop-opacity="0.20"/>' +
          '<stop offset="100%" stop-color="' + esc(color) + '" stop-opacity="0"/></linearGradient>');
        bodies.push('<path d="' + line + ' L100 ' + (pad + plotH) + ' L0 ' + (pad + plotH) + ' Z" fill="url(#' + gid + ')" stroke="none"/>');
      }
      bodies.push('<path d="' + line + '" fill="none" stroke="' + esc(color) + '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>');
      // 末点圆点
      if (coords.length) {
        var last = coords[coords.length - 1];
        bodies.push('<circle cx="' + last[0].toFixed(2) + '" cy="' + last[1].toFixed(2) + '" r="2.6" fill="' + esc(color) + '"/>');
      }
    });

    return '<svg viewBox="0 0 100 ' + height + '" role="img" aria-label="' + esc(opts.ariaLabel || "趋势对比图") +
      '" preserveAspectRatio="none" style="width:100%;height:auto"><defs>' + defs.join("") + '</defs>' +
      bodies.join("") + '</svg>';
  }

  window.HWCharts = { donut: donut, hbar: hbar, vbar: vbar, area: area, areaMulti: areaMulti };
})();
