/**
 * packetlens-ui.js
 * ---------------------------------------------------------------
 * DOM/view layer for the pcap dashboard. Consumes the pure
 * PacketLensEngine module (packetlens-engine.js) for all parsing/analysis and
 * is responsible only for rendering, charts, and user interaction.
 * Requires: Chart.js (global `Chart`), packetlens-engine.js loaded first.
 * ---------------------------------------------------------------
 */
(function () {
  const { parsePcap, analyze, tcpFlagsToStr } = window.PacketLensEngine;

  const fileInput = document.getElementById('fileInput');
  const fileName = document.getElementById('fileName');
  const content = document.getElementById('content');
  const summaryChips = document.getElementById('summaryChips');
  const traceCanvas = document.getElementById('traceCanvas');
  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');
  const themeLabel = document.getElementById('themeLabel');
  let charts = [];
  let lastAnalysis = null;

  // ---------- Theming ----------
  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function getThemeColors() {
    const styles = getComputedStyle(document.documentElement);
    const read = (name) => styles.getPropertyValue(name).trim();
    return {
      signal: read('--signal') || '#57e5c9',
      warn: read('--warn') || '#f5a623',
      crit: read('--crit') || '#f0553f',
      grid: read('--grid') || '#1d2629',
      muted: read('--muted') || '#7d8e93',
      text: read('--text') || '#e7edef',
      panel: read('--panel') || '#151d20'
    };
  }

  function hexToRgba(hex, alpha) {
    const h = hex.replace('#', '');
    if (h.length !== 6) return `rgba(87,229,201,${alpha})`;
    const r = parseInt(h.substring(0, 2), 16);
    const g = parseInt(h.substring(2, 4), 16);
    const b = parseInt(h.substring(4, 6), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  function updateThemeButton() {
    const isLight = currentTheme() === 'light';
    themeIcon.textContent = isLight ? '🌙' : '☀️';
    themeLabel.textContent = isLight ? 'Dark' : 'Light';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('packetlens-theme', theme); } catch (e) { /* ignore */ }
    updateThemeButton();
    if (lastAnalysis) {
      render(lastAnalysis);
    } else {
      drawIdleTrace();
    }
  }

  updateThemeButton();
  themeToggle.addEventListener('click', () => {
    applyTheme(currentTheme() === 'light' ? 'dark' : 'light');
  });

  // ---------- Header trace visual ----------
  let idleRAF;
  function drawIdleTrace() {
    cancelAnimationFrame(idleRAF);
    const ctx = traceCanvas.getContext('2d');
    const w = traceCanvas.width = traceCanvas.clientWidth * devicePixelRatio;
    const h = traceCanvas.height = traceCanvas.clientHeight * devicePixelRatio;
    let t = 0;
    function frame() {
      const theme = getThemeColors();
      t += 0.02;
      ctx.clearRect(0, 0, w, h);
      ctx.beginPath();
      ctx.strokeStyle = hexToRgba(theme.signal, 0.35);
      ctx.lineWidth = 1.5 * devicePixelRatio;
      for (let x = 0; x <= w; x += 4) {
        const y = h / 2 + Math.sin(x * 0.02 + t) * (h * 0.12) * Math.sin(t * 0.3);
        x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      }
      ctx.stroke();
      idleRAF = requestAnimationFrame(frame);
    }
    frame();
  }
  drawIdleTrace();

  function drawStaticTrace(buckets) {
    cancelAnimationFrame(idleRAF);
    const theme = getThemeColors();
    const ctx = traceCanvas.getContext('2d');
    const w = traceCanvas.width = traceCanvas.clientWidth * devicePixelRatio;
    const h = traceCanvas.height = traceCanvas.clientHeight * devicePixelRatio;
    ctx.clearRect(0, 0, w, h);
    if (!buckets.length) return;
    const max = Math.max(...buckets, 1);
    ctx.beginPath();
    ctx.strokeStyle = theme.signal;
    ctx.lineWidth = 1.75 * devicePixelRatio;
    buckets.forEach((v, i) => {
      const x = (i / (buckets.length - 1 || 1)) * w;
      const y = h - (v / max) * (h * 0.85) - 4;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = hexToRgba(theme.signal, 0.08);
    ctx.fill();
  }

  // ---------- Small view helpers ----------
  function destroyCharts() { charts.forEach(c => c.destroy()); charts = []; }

  function fmtBytes(n) {
    if (n > 1e6) return (n / 1e6).toFixed(2) + ' MB';
    if (n > 1e3) return (n / 1e3).toFixed(1) + ' KB';
    return n + ' B';
  }

  function chartDefaults() {
    const theme = getThemeColors();
    Chart.defaults.color = theme.muted;
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
  }

  function portLabel(p) {
    const known = { 80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 3389: 'RDP', 3306: 'MySQL', 5432: 'Postgres' };
    return known[p] || '—';
  }

  // ---------- Main render ----------
  function render(a) {
    destroyCharts();
    chartDefaults();
    lastAnalysis = a;
    const theme = getThemeColors();

    summaryChips.innerHTML = `
      <span class="chip">packets: <b>${a.total.toLocaleString()}</b></span>
      <span class="chip">bytes: <b>${fmtBytes(a.totalBytes)}</b></span>
      <span class="chip">duration: <b>${a.duration.toFixed(2)}s</b></span>
      <span class="chip">unique hosts: <b>${a.hosts.size}</b></span>
      <span class="chip">alerts: <b style="color:${a.alerts.length ? theme.warn : theme.signal}">${a.alerts.length}</b></span>
    `;

    drawStaticTrace(a.buckets);

    const talkerRows = a.topTalkers.map(([k, v]) => `
      <tr><td>${k}</td><td class="bar-cell">
        <div class="bar-fill" style="width:${(v / a.topTalkers[0][1] * 100).toFixed(0)}%"></div>
        <span>${fmtBytes(v)}</span></td></tr>`).join('');

    const portRows = a.topPorts.map(([p, c]) => `
      <tr><td>${p}</td><td>${portLabel(p)}</td><td class="bar-cell">
        <div class="bar-fill" style="width:${(c / a.topPorts[0][1] * 100).toFixed(0)}%"></div>
        <span>${c}</span></td></tr>`).join('');

    const alertRows = a.alerts.length ? a.alerts.map(al => `
      <div class="alert-row">
        <div class="dot ${al.level}"></div>
        <div><div class="alert-title">${al.title}</div><div class="alert-detail">${al.detail}</div></div>
      </div>`).join('') : `<div class="no-alerts">No anomalies flagged — traffic looks unremarkable.</div>`;

    content.innerHTML = `
      <div class="main-tabs">
        <button class="main-tab active" id="tabBtnDetails" type="button">Packet Details</button>
        <button class="main-tab" id="tabBtnOverview" type="button">Traffic Overview</button>
      </div>

      <div class="tab-panel active" id="tabDetails">
        <div class="grid">
          <div class="panel span-12">
            <h2>Packet details</h2>
            <div class="pkt-toolbar">
              <input class="pkt-search" id="pktSearch" type="text" placeholder="Filter by IP or port…" />
              <select class="pkt-select" id="pktProtoFilter">
                <option value="">All protocols</option>
              </select>
              <span class="pkt-count" id="pktCount"></span>
            </div>
            <div style="overflow-x:auto;">
              <table class="pkt-table" id="pktTable">
                <thead>
                  <tr><th>#</th><th>Time</th><th>Src</th><th>Sport</th><th>Dst</th><th>Dport</th><th>Proto</th><th>Len</th></tr>
                </thead>
                <tbody id="pktTableBody"></tbody>
              </table>
            </div>
            <div class="pkt-pagination">
              <button class="pkt-page-btn" id="pktPrev">← Prev</button>
              <span class="pkt-page-info" id="pktPageInfo"></span>
              <button class="pkt-page-btn" id="pktNext">Next →</button>
            </div>
          </div>
        </div>
      </div>

      <div class="tab-panel" id="tabOverview">
        <div class="grid">
          <div class="panel span-12">
            <h2>Bandwidth over time</h2>
            <div class="chart-box"><canvas id="bwChart"></canvas></div>
          </div>
          <div class="panel span-4">
            <h2>Protocol distribution</h2>
            <div class="chart-box"><canvas id="protoChart"></canvas></div>
          </div>
          <div class="panel span-4">
            <h2>Packet size distribution</h2>
            <div class="chart-box"><canvas id="sizeChart"></canvas></div>
          </div>
          <div class="panel span-4">
            <h2>Anomalies</h2>
            <div style="max-height:260px; overflow-y:auto;">${alertRows}</div>
          </div>
          <div class="panel span-6">
            <h2>Top talkers (by bytes)</h2>
            <table class="data-table"><thead><tr><th>Src → Dst</th><th>Bytes</th></tr></thead><tbody>${talkerRows}</tbody></table>
          </div>
          <div class="panel span-6">
            <h2>Top destination ports</h2>
            <table class="data-table"><thead><tr><th>Port</th><th>Service</th><th>Packets</th></tr></thead><tbody>${portRows}</tbody></table>
          </div>
        </div>
      </div>
    `;

    setupMainTabs();

    const gridColor = theme.grid;

    charts.push(new Chart(document.getElementById('bwChart'), {
      type: 'line',
      data: {
        labels: a.buckets.map((_, i) => (i * a.bucketDur).toFixed(1) + 's'),
        datasets: [{
          data: a.buckets, borderColor: theme.signal, backgroundColor: hexToRgba(theme.signal, 0.08),
          fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor }, ticks: { maxTicksLimit: 10 } },
          y: { grid: { color: gridColor }, ticks: { callback: v => fmtBytes(v) } }
        }
      }
    }));

    const protoLabels = Object.keys(a.protoCounts);
    const protoColors = currentTheme() === 'light'
      ? ['#0d9488', '#b45309', '#b91c1c', '#2563eb', '#7c3aed', '#5b6a6f']
      : ['#57e5c9', '#f5a623', '#f0553f', '#4d8fdb', '#a78bfa', '#7d8e93'];
    charts.push(new Chart(document.getElementById('protoChart'), {
      type: 'doughnut',
      data: {
        labels: protoLabels,
        datasets: [{ data: protoLabels.map(l => a.protoCounts[l]), backgroundColor: protoColors, borderColor: theme.panel, borderWidth: 2 }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12 } } }
      }
    }));

    charts.push(new Chart(document.getElementById('sizeChart'), {
      type: 'bar',
      data: {
        labels: a.sizeLabels,
        datasets: [{ data: a.sizeHist, backgroundColor: theme.signal, borderRadius: 3 }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: gridColor } }
        }
      }
    }));

    setupPacketTable(a);
  }

  // ---------- Packet details table ----------
  // ---------- Main tab switching ----------
  function setupMainTabs() {
    const btnDetails = document.getElementById('tabBtnDetails');
    const btnOverview = document.getElementById('tabBtnOverview');
    const tabDetails = document.getElementById('tabDetails');
    const tabOverview = document.getElementById('tabOverview');

    function activate(tab) {
      const showDetails = tab === 'details';
      btnDetails.classList.toggle('active', showDetails);
      btnOverview.classList.toggle('active', !showDetails);
      tabDetails.classList.toggle('active', showDetails);
      tabOverview.classList.toggle('active', !showDetails);
      if (!showDetails) {
        // Charts were created while this tab was display:none, so Chart.js
        // measured a zero-size canvas. Resize on the next frame, once the
        // browser has actually laid out the now-visible panel.
        requestAnimationFrame(() => charts.forEach(c => c.resize()));
      }
    }

    btnDetails.addEventListener('click', () => activate('details'));
    btnOverview.addEventListener('click', () => activate('overview'));
  }

  function setupPacketTable(a) {
    const searchEl = document.getElementById('pktSearch');
    const protoEl = document.getElementById('pktProtoFilter');
    const countEl = document.getElementById('pktCount');
    const bodyEl = document.getElementById('pktTableBody');
    const prevBtn = document.getElementById('pktPrev');
    const nextBtn = document.getElementById('pktNext');
    const pageInfoEl = document.getElementById('pktPageInfo');
    const pageSize = 50;

    let page = 0;
    let expandedIdx = null;
    let filtered = a.packets;

    Object.keys(a.protoCounts).forEach(proto => {
      const opt = document.createElement('option');
      opt.value = proto; opt.textContent = `${proto} (${a.protoCounts[proto]})`;
      protoEl.appendChild(opt);
    });

    function applyFilter() {
      const text = searchEl.value.trim().toLowerCase();
      const protoVal = protoEl.value;
      filtered = a.packets.filter(p => {
        if (protoVal && p.proto !== protoVal) return false;
        if (!text) return true;
        return (p.src && p.src.includes(text)) ||
               (p.dst && p.dst.includes(text)) ||
               (p.sport != null && String(p.sport).includes(text)) ||
               (p.dport != null && String(p.dport).includes(text));
      });
      page = 0;
      expandedIdx = null;
      draw();
    }

    function protoClass(proto) {
      return ['TCP', 'UDP', 'ICMP'].includes(proto) ? proto : 'other';
    }

    function hexDumpHtml(p) {
      const dv = p.dv;
      const rows = [];
      for (let i = 0; i < p.rawLen; i += 16) {
        const chunkLen = Math.min(16, p.rawLen - i);
        let hexPart = '', asciiPart = '';
        for (let j = 0; j < chunkLen; j++) {
          const b = dv.getUint8(p.rawOff + i + j);
          hexPart += b.toString(16).padStart(2, '0') + ' ';
          asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
        }
        rows.push(`<div class="hrow"><span class="hoff">${i.toString(16).padStart(4, '0')}</span>  <span class="hbytes">${hexPart.padEnd(48, ' ')}</span> <span class="hascii">${asciiPart}</span></div>`);
      }
      return rows.join('');
    }

    function detailHtml(p) {
      let l4 = '';
      if (p.proto === 'TCP') {
        l4 = `
          <div class="layer-title">Transport — TCP</div>
          <div class="field-row"><b>Src port</b>${p.sport}</div>
          <div class="field-row"><b>Dst port</b>${p.dport}</div>
          <div class="field-row"><b>Flags</b>${tcpFlagsToStr(p.tcpFlags)}</div>`;
      } else if (p.proto === 'UDP') {
        l4 = `
          <div class="layer-title">Transport — UDP</div>
          <div class="field-row"><b>Src port</b>${p.sport}</div>
          <div class="field-row"><b>Dst port</b>${p.dport}</div>`;
      } else if (p.proto === 'ICMP') {
        l4 = `
          <div class="layer-title">ICMP</div>
          <div class="field-row"><b>Type</b>${p.icmpType}</div>
          <div class="field-row"><b>Code</b>${p.icmpCode}</div>`;
      }
      const ipBlock = p.src ? `
          <div class="layer-title">Internet Protocol v${p.ipVersion || 4}</div>
          <div class="field-row"><b>Source</b>${p.src}</div>
          <div class="field-row"><b>Destination</b>${p.dst}</div>
          <div class="field-row"><b>TTL</b>${p.ttl}</div>
          <div class="field-row"><b>Header length</b>${p.ihl} bytes</div>
          <div class="field-row"><b>Protocol</b>${p.proto}</div>` : '';

      return `
        <div class="pkt-detail">
          <div class="pkt-detail-fields">
            <div class="layer-title">Ethernet II</div>
            <div class="field-row"><b>Src MAC</b>${p.srcMac || '—'}</div>
            <div class="field-row"><b>Dst MAC</b>${p.dstMac || '—'}</div>
            ${ipBlock}
            ${l4}
          </div>
          <div class="hex-dump">${hexDumpHtml(p)}</div>
        </div>`;
    }

    function draw() {
      const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      if (page >= totalPages) page = totalPages - 1;
      const start = page * pageSize;
      const pageItems = filtered.slice(start, start + pageSize);

      countEl.textContent = `${filtered.length.toLocaleString()} packet${filtered.length === 1 ? '' : 's'} matched`;
      pageInfoEl.textContent = `page ${page + 1} / ${totalPages}`;
      prevBtn.disabled = page <= 0;
      nextBtn.disabled = page >= totalPages - 1;

      bodyEl.innerHTML = pageItems.map(p => {
        const isExpanded = p.idx === expandedIdx;
        const rowHtml = `
          <tr data-idx="${p.idx}" class="${isExpanded ? 'expanded' : ''}">
            <td>${p.idx}</td>
            <td>${(p.ts - a.minT).toFixed(6)}s</td>
            <td>${p.src || '—'}</td>
            <td>${p.sport ?? '—'}</td>
            <td>${p.dst || '—'}</td>
            <td>${p.dport ?? '—'}</td>
            <td><span class="proto-tag ${protoClass(p.proto)}">${p.proto}</span></td>
            <td>${p.len} B</td>
          </tr>`;
        const detailRow = isExpanded ? `<tr class="pkt-detail-row"><td colspan="8">${detailHtml(p)}</td></tr>` : '';
        return rowHtml + detailRow;
      }).join('');

      bodyEl.querySelectorAll('tr[data-idx]').forEach(row => {
        row.addEventListener('click', () => {
          const idx = Number(row.getAttribute('data-idx'));
          expandedIdx = expandedIdx === idx ? null : idx;
          draw();
        });
      });
    }

    searchEl.addEventListener('input', applyFilter);
    protoEl.addEventListener('change', applyFilter);
    prevBtn.addEventListener('click', () => { if (page > 0) { page--; expandedIdx = null; draw(); } });
    nextBtn.addEventListener('click', () => {
      const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      if (page < totalPages - 1) { page++; expandedIdx = null; draw(); }
    });

    draw();
  }

  // ---------- File handling ----------
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    fileName.textContent = file.name;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof Chart === 'undefined') {
        content.innerHTML = `<div class="empty-state"><div class="big" style="color:#f0553f">Chart.js failed to load</div><div>The charting library couldn't be fetched from the CDN — check your network/firewall access to cdnjs.cloudflare.com, then reload the page.</div></div>`;
        return;
      }

      let packets;
      try {
        packets = parsePcap(reader.result);
        if (!packets.length) throw new Error('No packets found in file.');
      } catch (err) {
        content.innerHTML = `<div class="empty-state"><div class="big" style="color:#f0553f">Couldn't parse this file</div><div>${err.message}</div></div>`;
        return;
      }

      try {
        const analysis = analyze(packets);
        render(analysis);
      } catch (err) {
        console.error(err);
        content.innerHTML = `<div class="empty-state"><div class="big" style="color:#f0553f">Parsed the file, but rendering failed</div><div>${err.message} — check the browser console for details.</div></div>`;
      }
    };
    reader.onerror = () => {
      content.innerHTML = `<div class="empty-state"><div class="big" style="color:#f0553f">Read error</div><div>Could not read the selected file.</div></div>`;
    };
    reader.readAsArrayBuffer(file);
  });
})();
