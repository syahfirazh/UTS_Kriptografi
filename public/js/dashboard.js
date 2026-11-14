/* Grafik aktivitas (canvas vanilla, tanpa library). */
(function () {
  'use strict';
  var canvas = document.getElementById('activityChart');
  if (!canvas) return;
  var data = (window.getPageData() || {}).chart || { labels: [], values: [] };

  function draw() {
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.parentElement.clientWidth;
    var h = Math.max(220, Math.round(w * 0.32));
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    var ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    var pad = { l: 36, r: 12, t: 16, b: 30 };
    var max = Math.max(4, Math.max.apply(null, data.values));
    max = Math.ceil(max / 4) * 4;
    var cw = w - pad.l - pad.r, ch = h - pad.t - pad.b;

    ctx.font = '11px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillStyle = '#64748b';
    ctx.strokeStyle = '#e3e9f2';
    for (var i = 0; i <= 4; i++) {
      var y = pad.t + ch - (ch * i / 4);
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
      ctx.fillText(String(Math.round(max * i / 4)), pad.l - 6, y + 4);
    }
    var n = data.values.length;
    var slot = cw / Math.max(1, n);
    var bw = Math.min(36, slot * 0.55);
    ctx.textAlign = 'center';
    data.values.forEach(function (v, idx) {
      var x = pad.l + slot * idx + (slot - bw) / 2;
      var bh = ch * v / max;
      var grad = ctx.createLinearGradient(0, pad.t + ch - bh, 0, pad.t + ch);
      grad.addColorStop(0, '#22d3ee'); grad.addColorStop(1, '#0e7490');
      ctx.fillStyle = grad;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(x, pad.t + ch - bh, bw, bh, 5); else ctx.rect(x, pad.t + ch - bh, bw, bh);
      ctx.fill();
      ctx.fillStyle = '#64748b';
      ctx.fillText(data.labels[idx], x + bw / 2, h - 10);
      if (v > 0) { ctx.fillStyle = '#0f1f38'; ctx.fillText(String(v), x + bw / 2, pad.t + ch - bh - 5); }
    });
  }
  draw();
  var t;
  window.addEventListener('resize', function () { clearTimeout(t); t = setTimeout(draw, 120); });
})();
