/* =========================================================
 *  CekTautan :: URL Threat Scanner — UI layer
 *  Uses window.ENGINE (engine.js) for detection logic.
 * ========================================================= */
(function () {
  'use strict';

  var ENGINE = window.ENGINE;
  var VERSION = 'v' + (ENGINE && ENGINE.VERSION || '1.7.1');

  var $ = function (id) { return document.getElementById(id); };
  var form = $('scanForm');
  var input = $('urlInput');
  var resultArea = $('resultArea');
  var historyList = $('historyList');
  var footerVersion = $('footerVersion');
  var channelEl = $('channelStatus');
  var sourceEl = $('sourceInfo');
  var clearBtn = $('clearHistory');
  var exportBtn = $('exportHistory');
  var vtKeyInput = $('vtKey');
  var dnsToggle = $('dnsToggle');
  var saveSettingsBtn = $('saveSettings');
  var clearKeyBtn = $('clearKey');
  var demoWrap = $('demoWrap');
  var newScanBtn = $('newScanBtn');
  var sidebar = $('sidebar');
  var sidebarOverlay = $('sidebarOverlay');
  var sidebarToggle = $('sidebarToggle');
  var sidebarClose = $('sidebarClose');
  var visitorEl = $('visitorCount');
  var visitorSideEl = $('visitorCountSide');
  var activeEl = $('activeCount');
  var activeSideEl = $('activeCountSide');

  /* ---------------- settings (localStorage) ---------------- */

  var SETTINGS_KEY = 'ghost_settings_v2';
  var HISTORY_KEY = 'ghost_history_v2';

  function loadSettings() {
    try {
      var s = JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {};
      return { vtKey: s.vtKey || '', dns: s.dns !== false };
    } catch (e) { return { vtKey: '', dns: true }; }
  }

  var settings = loadSettings();

  function saveSettings() {
    if (!vtKeyInput || !dnsToggle) return;
    settings.vtKey = vtKeyInput.value.trim();
    settings.dns = dnsToggle.checked;
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (e) {}
    updateMode();
    flashSettingsMsg('Pengaturan disimpan');
  }

  function updateMode() {
    if (!sourceEl) return;
    var parts = ['analisis pola'];
    if (settings.dns) parts.push('cek DNS');
    if (settings.vtKey) parts.push('VirusTotal');
    sourceEl.innerHTML = 'Sumber data: <b id="channelStatus">' + parts.join(' + ') + '</b>';
  }

  function flashSettingsMsg(text) {
    var msg = $('settingsMsg');
    if (!msg) return;
    msg.textContent = text;
    clearTimeout(msg._t);
    msg._t = setTimeout(function () { msg.textContent = ''; }, 2500);
  }

  /* ---------------- history (localStorage) ---------------- */

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
    catch (e) { return []; }
  }

  function persistHistory() {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); } catch (e) {}
  }

  var history = loadHistory();

  var VERDICT_WORD = { DANGER: 'Berbahaya', WARN: 'Diwaspadai', CLEAN: 'Aman' };

  function renderHistory() {
    if (!historyList) return;
    historyList.innerHTML = '';
    if (!history.length) {
      var empty = document.createElement('li');
      empty.className = 'empty';
      empty.textContent = 'Belum ada riwayat.';
      historyList.appendChild(empty);
      return;
    }
    history.forEach(function (h) {
      var li = document.createElement('li');
      li.className = h.verdict.toLowerCase();
      var time = new Date(h.ts).toLocaleTimeString();
      var dot = document.createElement('span');
      dot.className = 'h-dot';
      var t = document.createElement('span');
      t.className = 'h-time';
      t.textContent = time;
      var u = document.createElement('span');
      u.className = 'h-url';
      u.textContent = h.input;
      var v = document.createElement('span');
      v.className = 'h-verdict';
      v.textContent = (VERDICT_WORD[h.verdict] || h.verdict) + ' (' + h.score + ')';
      li.appendChild(dot);
      li.appendChild(t);
      li.appendChild(u);
      li.appendChild(v);
      historyList.appendChild(li);
    });
  }

  function addHistory(h) {
    history.unshift(h);
    if (history.length > 20) history = history.slice(0, 20);
    persistHistory();
    renderHistory();
  }

  function exportReport() {
    var lines = [];
    lines.push('CekTautan — Laporan Pemeriksaan Tautan');
    lines.push('Versi ' + VERSION + ' | ' + new Date().toLocaleString());
    lines.push('='.repeat(56));
    history.forEach(function (h, i) {
      lines.push('#' + (i + 1) + ' [' + new Date(h.ts).toLocaleString() + ']');
      lines.push('  Tautan  : ' + h.input);
      lines.push('  HASIL   : ' + (VERDICT_WORD[h.verdict] || h.verdict) + ' | skor ' + h.score + '/100');
      if (h.notes) lines.push('  CATATAN : ' + h.notes);
      lines.push('');
    });
    if (!history.length) lines.push('(belum ada riwayat pemeriksaan)');
    var blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'cektautan-report-' + new Date().toISOString().slice(0, 10) + '.txt';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 100);
  }

  /* ---------------- helpers ---------------- */

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
    });
  }

  /* Terjemahkan pesan teknis dari engine menjadi bahasa sederhana. */
  var PLAIN_RULES = [
    [/URL tidak valid/, 'Alamat ini tidak bisa dibaca dengan benar.'],
    [/Host berupa IP mentah/, 'Alamatnya berupa angka IP, bukan nama situs. Cara ini sering dipakai penipu.'],
    [/URL shortener "([^"]+)"/, function (m) { return 'Tautan memakai layanan pemendek (' + m[1] + '). Tujuan aslinya tidak terlihat.'; }],
    [/TLD berisiko tinggi "([^"]+)"/, function (m) { return 'Akhiran situs (' + m[1] + ') sering dipakai situs penipuan.'; }],
    [/level subdomain/, 'Terlalu banyak bagian subdomain di alamat — bisa untuk menipu.'],
    [/Karakter "@"/, 'Ada simbol "@" yang bisa menyembunyikan tujuan sebenarnya dari tautan.'],
    [/HTTP eksplisit/, 'Situs tidak memakai koneksi aman (HTTP, bukan HTTPS).'],
    [/Port tidak standar/, 'Situs memakai nomor port yang tidak biasa.'],
    [/URL sangat panjang/, 'Tautan terlalu panjang, tidak seperti biasanya.'],
    [/Hostname terlalu panjang/, 'Nama situs terlalu panjang.'],
    [/titik di hostname/, 'Terlalu banyak titik di nama situs.'],
    [/Kata "([^"]+)" pada path/, function (m) { return 'Ada kata mencurigakan ("' + m[1] + '") di alamat.'; }],
    [/angka menempel/, 'Banyak angka di nama situs — sering dipakai situs penipuan.'],
    [/tanda strip/, 'Banyak tanda "-" di nama situs — ciri khas situs palsu.'],
    [/typosquat, jarak/, 'Nama situs sangat mirip dengan nama resmi — bisa jadi situs palsu.'],
    [/hampir sama dengan brand "([^"]+)"/, function (m) { return 'Nama situs mirip sekali dengan brand asli "' + m[1] + '" — bisa jadi situs palsu.'; }],
    [/karakter mirip brand "([^"]+)"/, function (m) { return 'Nama situs memakai huruf/angka yang meniru brand asli "' + m[1] + '".'; }],
    [/Nama brand "([^"]+)" \+ kata mencurigakan/, function (m) { return 'Menggabungkan nama "' + m[1] + '" dengan kata mencurigakan (mis. login, secure).'; }],
    [/Brand "([^"]+)" disembunyikan di subdomain/, function (m) { return 'Nama "' + m[1] + '" disembunyikan di subdomain situs lain — pola login palsu.'; }],
    [/punycode/, 'Nama situs memakai huruf khusus yang bisa menipu mata.'],
    [/Karakter aneh/, 'Ada karakter aneh di nama situs.'],
    [/domain tidak resolve/, 'Situs ini tidak aktif / tidak ditemukan di DNS.'],
    [/MALICIOUS/, 'Antivirus menandai situs ini berbahaya.'],
    [/SUSPICIOUS/, 'Antivirus menilai situs ini mencurigakan.'],
    [/DNS: domain ter-resolve/, 'Situs aktif dan terhubung.'],
    [/DNS: pemeriksaan gagal/, 'Pemeriksaan DNS tidak bisa dilakukan saat ini.'],
    [/VirusTotal: gagal/, 'Pemeriksaan VirusTotal gagal dilakukan.']
  ];

  function plainReason(msg) {
    for (var i = 0; i < PLAIN_RULES.length; i++) {
      var m = String(msg).match(PLAIN_RULES[i][0]);
      if (m) {
        var r = PLAIN_RULES[i][1];
        return typeof r === 'function' ? r(m) : r;
      }
    }
    return msg;
  }

  function recommendation(verdict) {
    if (verdict === 'DANGER') {
      return 'Jangan buka tautan ini. Jangan isi kata sandi, kode OTP, atau data kartu apa pun. Jika sudah pernah mengisinya, segera ganti kata sandi akun terkait.';
    }
    if (verdict === 'WARN') {
      return 'Hati-hati. Pastikan dulu apakah situs ini benar-benar resmi. Kalau ragu, lebih baik jangan dibuka.';
    }
    return 'Tidak ditemukan tanda bahaya yang jelas. Tetap jangan berikan kata sandi atau OTP ke situs yang tidak Anda kenal.';
  }

  var VERDICT_UI = {
    DANGER: { title: 'Berbahaya', sub: 'Jangan buka tautan ini.' },
    WARN: { title: 'Perlu Diwaspadai', sub: 'Tautan ini mencurigakan. Pastikan dulu sebelum membuka.' },
    CLEAN: { title: 'Aman', sub: 'Tidak ditemukan tanda bahaya yang jelas.' }
  };

  /* ---------------- scan flow ---------------- */

  var currentResult = null;
  var scanInProgress = false;

  function runScan(raw) {
    var r = ENGINE.scanUrl(raw);
    r.heurScore = r.score;
    currentResult = r;

    var btn = $('scanBtn');
    input.disabled = true;
    btn.disabled = true;
    btn.textContent = 'Memeriksa...';
    form.hidden = true;
    demoWrap.hidden = true;
    newScanBtn.hidden = false;
    resultArea.hidden = true;
    resultArea.innerHTML = '';
    scanInProgress = true;

    renderResult(r);
    runLive(r);

    setTimeout(function () {
      resultArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 60);
  }

  function backToInput() {
    if (scanInProgress) return;
    form.hidden = false;
    demoWrap.hidden = false;
    newScanBtn.hidden = true;
    resultArea.hidden = true;
    resultArea.className = 'result-area';
    resultArea.innerHTML = '';
    input.value = '';
    input.disabled = false;
    input.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* ---------------- sidebar & header buttons ---------------- */

  function setSidebar(open) {
    if (sidebar) sidebar.classList.toggle('open', open);
    if (sidebarOverlay) sidebarOverlay.classList.toggle('open', open);
    if (sidebar) sidebar.setAttribute('aria-hidden', String(!open));
    if (sidebarToggle) sidebarToggle.setAttribute('aria-expanded', String(open));
  }

  /* ---------------- visitor counter (server) ---------------- */

  var VISITOR_KEY = 'ghost_visitors_v1';
  var VISITED_KEY = 'ghost_visited_v1';
  var VISITOR_ID_KEY = 'ghost_visitor_id_v1';

  function setVisitorUI(total, active) {
    if (visitorEl) visitorEl.textContent = String(total);
    if (visitorSideEl) visitorSideEl.textContent = String(total);
    if (activeEl) activeEl.textContent = String(active);
    if (activeSideEl) activeSideEl.textContent = String(active);
  }

  function visitorId() {
    var id = null;
    try { id = localStorage.getItem(VISITOR_ID_KEY); } catch (e) {}
    if (!id) {
      id = (window.crypto && window.crypto.randomUUID)
        ? window.crypto.randomUUID()
        : ('v' + Date.now().toString(36) + Math.random().toString(36).slice(2));
      try { localStorage.setItem(VISITOR_ID_KEY, id); } catch (e) {}
    }
    return id;
  }

  /* Fallback bila server tanpa backend (hanya file statis): hitung unik per perangkat. */
  function fallbackVisitor() {
    var count = 0;
    try {
      count = parseInt(localStorage.getItem(VISITOR_KEY), 10) || 0;
      if (!localStorage.getItem(VISITED_KEY)) {
        count += 1;
        localStorage.setItem(VISITOR_KEY, String(count));
        localStorage.setItem(VISITED_KEY, '1');
      }
    } catch (e) {}
    setVisitorUI(count, 1);
  }

  function countVisitor() {
    var id = visitorId();
    fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id })
    }).then(function (res) { return res.json(); }).then(function (j) {
      setVisitorUI(j.total, j.active);
    }).catch(fallbackVisitor);
  }

  window.addEventListener('pagehide', function () {
    var id = null;
    try { id = localStorage.getItem(VISITOR_ID_KEY); } catch (e) {}
    if (id && navigator.sendBeacon) {
      navigator.sendBeacon('/api/leave', JSON.stringify({ id: id }));
    }
  });

  function runLive(r) {
    var p = r.parsed;

    if (settings.dns && !p.isIp) {
      ENGINE.dnsResolve(p.host).then(function (res) {
        r.live.dns = res;
        applyLive(r);
      });
    }

    if (settings.vtKey) {
      ENGINE.vtAnalyze(r.input, settings.vtKey)
        .then(function (j) {
          r.live.vt = ENGINE.vtSummarize(j);
          applyLive(r);
        })
        .catch(function (err) {
          r.live.vtError = (err && err.message) || 'gagal terhubung';
          applyLive(r);
        });
    } else if (!settings.dns || p.isIp) {
      finishScan(r);
    }
  }

  function applyLive(r) {
    var lv = ENGINE.liveScore(r);
    r.live.flags = lv.flags;
    r.score = Math.min(r.heurScore + lv.pts, 100);
    r.grade = ENGINE.gradeScore(r.score);
    renderResult(r);

    var liveDone =
      (settings.dns && !r.parsed.isIp ? !!r.live.dns : true) &&
      (settings.vtKey ? (r.live.vt || r.live.vtError) : true);

    if (liveDone) finishScan(r);
  }

  function finishScan(r) {
    scanInProgress = false;
    input.disabled = false;
    var btn = $('scanBtn');
    btn.disabled = false;
    btn.textContent = 'Periksa Keamanan';
    input.value = '';
    input.focus();

    var notes = [];
    if (r.live.vt && r.live.vt.stats) {
      notes.push('VirusTotal: ' + r.live.vt.stats.malicious + ' berbahaya / ' + r.live.vt.stats.suspicious + ' mencurigakan.');
    }
    if (r.live.dns && r.live.dns.ok && !r.live.dns.resolved) notes.push('Situs tidak aktif di DNS.');

    addHistory({
      input: r.input,
      score: r.score,
      verdict: r.grade.verdict,
      ts: r.ts,
      notes: notes.length ? notes.join(' ') : ''
    });
  }

  /* ---------------- rendering ---------------- */

  function renderResult(r) {
    var verdictWord = r.grade.verdict.toLowerCase();
    resultArea.hidden = false;
    resultArea.className = 'result-area verdict-' + verdictWord;
    resultArea.innerHTML = '';

    var ui = VERDICT_UI[r.grade.verdict];

    var head = document.createElement('div');
    head.className = 'result-head';
    var banner = document.createElement('div');
    banner.className = 'verdict-banner';
    var dot = document.createElement('span');
    dot.className = 'verdict-dot';
    var txt = document.createElement('span');
    var title = document.createElement('div');
    title.className = 'verdict-title';
    title.textContent = ui.title;
    var sub = document.createElement('div');
    sub.className = 'verdict-sub';
    sub.textContent = ui.sub;
    txt.appendChild(title);
    txt.appendChild(sub);
    banner.appendChild(dot);
    banner.appendChild(txt);
    head.appendChild(banner);
    resultArea.appendChild(head);

    var body = document.createElement('div');
    body.className = 'result-body';

    /* skor risiko */
    var scoreLine = document.createElement('div');
    scoreLine.className = 'score-line';
    var slLabel = document.createElement('div');
    slLabel.className = 'label';
    slLabel.textContent = 'Tingkat risiko: ' + r.score + '/100 (' + (r.score >= 50 ? 'tinggi' : r.score >= 20 ? 'sedang' : 'rendah') + ')';
    var barWrap = document.createElement('div');
    barWrap.className = 'score-bar-wrap';
    var bar = document.createElement('div');
    bar.className = 'score-bar ' + verdictWord;
    bar.style.width = '0%';
    barWrap.appendChild(bar);
    scoreLine.appendChild(slLabel);
    scoreLine.appendChild(barWrap);
    body.appendChild(scoreLine);

    /* rekomendasi */
    var rec = document.createElement('div');
    rec.className = 'recommend ' + verdictWord;
    rec.textContent = recommendation(r.grade.verdict);
    body.appendChild(rec);

    /* alasan (plain language) */
    var reasons = [];
    (r.flags || []).forEach(function (f) { reasons.push(f); });
    (r.live.flags || []).forEach(function (f) { reasons.push(f); });

    var bTitle = document.createElement('div');
    bTitle.className = 'block-title';
    bTitle.textContent = reasons.length ? 'Mengapa:' : 'Hasil Pemeriksaan';
    body.appendChild(bTitle);

    if (!reasons.length) {
      var okRow = document.createElement('ul');
      okRow.className = 'plain-list';
      var okLi = document.createElement('li');
      okLi.className = 'clean';
      var okDot = document.createElement('span');
      okDot.className = 'dot';
      var okTxt = document.createElement('span');
      okTxt.textContent = 'Tidak ada indikator mencurigakan yang ditemukan.';
      okLi.appendChild(okDot);
      okLi.appendChild(okTxt);
      okRow.appendChild(okLi);
      body.appendChild(okRow);
    } else {
      var ul = document.createElement('ul');
      ul.className = 'plain-list';
      reasons.forEach(function (f) {
        var li = document.createElement('li');
        if (f.danger) li.className = 'danger';
        var d = document.createElement('span');
        d.className = 'dot';
        var s = document.createElement('span');
        s.textContent = plainReason(f.msg);
        if (f.source === 'DNS' || f.source === 'VT') {
          var sub2 = document.createElement('div');
          sub2.className = 'pl-sub';
          sub2.textContent = f.source === 'DNS' ? '(dari pemeriksaan jaringan)' : '(dari VirusTotal)';
          s.appendChild(sub2);
        }
        li.appendChild(d);
        li.appendChild(s);
        ul.appendChild(li);
      });
      body.appendChild(ul);
    }

    /* detail alamat (sederhana) */
    var p = r.parsed;
    var dTitle = document.createElement('div');
    dTitle.className = 'block-title';
    dTitle.textContent = 'Detail Alamat';
    body.appendChild(dTitle);

    var grid = document.createElement('div');
    grid.className = 'info-grid';
    var rows = [
      ['Tautan yang dicek', r.input],
      ['Nama situs', p.host || 'N/A'],
      ['Domain utama', p.regDomain || 'N/A'],
      ['Akhiran situs', p.tld || 'N/A'],
      ['Subdomain', p.subdomains.length + ' level' + (p.subdomains.length ? ' (' + p.subdomains.join('.') + ')' : '')],
      ['Koneksi', p.hasProtocol ? (p.protocol || 'N/A') : 'tidak ditentukan']
    ];
    rows.forEach(function (row) {
      var k = document.createElement('span');
      k.className = 'k';
      k.textContent = row[0];
      var v = document.createElement('span');
      v.className = 'v';
      v.textContent = row[1];
      grid.appendChild(k);
      grid.appendChild(v);
    });
    body.appendChild(grid);

    /* hasil live */
    if (r.live.dns || r.live.vt || r.live.vtError || settings.vtKey) {
      var liveBlock = document.createElement('div');
      liveBlock.className = 'live-block';
      var liveTitle = document.createElement('div');
      liveTitle.className = 'block-title';
      liveTitle.textContent = 'Pemeriksaan Jaringan';
      liveBlock.appendChild(liveTitle);

      if (r.live.dns) {
        var dnsRow = document.createElement('div');
        dnsRow.className = 'flag-row' + (r.live.dns.ok && !r.live.dns.resolved ? ' danger' : '');
        dnsRow.textContent = r.live.dns.ok
          ? (r.live.dns.resolved
            ? 'DNS: situs aktif (' + (r.live.dns.ips || []).join(', ') + ').'
            : 'DNS: situs tidak ditemukan (tidak aktif).')
          : 'DNS: pemeriksaan gagal (' + (r.live.dns.error || '?') + ').';
        liveBlock.appendChild(dnsRow);
      } else if (settings.dns && !p.isIp) {
        var dnsWait = document.createElement('div');
        dnsWait.className = 'flag-row dim';
        dnsWait.textContent = 'DNS: memeriksa...';
        liveBlock.appendChild(dnsWait);
      }

      if (r.live.vt) {
        var st = r.live.vt.stats;
        var vtRow = document.createElement('div');
        vtRow.className = 'flag-row' + (st && st.malicious > 0 ? ' danger' : '');
        vtRow.textContent = st
          ? 'VirusTotal: ' + st.malicious + ' berbahaya, ' + st.suspicious + ' mencurigakan, ' + st.harmless + ' aman.'
          : 'VirusTotal: hasil tidak tersedia.';
        liveBlock.appendChild(vtRow);
        if (r.live.vt.reportUrl) {
          var vtLink = document.createElement('div');
          vtLink.className = 'flag-row';
          vtLink.innerHTML = '<a class="vt-link" href="' + escapeHtml(r.live.vt.reportUrl) + '" target="_blank" rel="noopener noreferrer">Lihat laporan lengkap VirusTotal</a>';
          liveBlock.appendChild(vtLink);
        }
      } else if (r.live.vtError) {
        var vtErr = document.createElement('div');
        vtErr.className = 'flag-row';
        vtErr.textContent = 'VirusTotal: gagal (' + r.live.vtError + ').';
        liveBlock.appendChild(vtErr);
      } else if (settings.vtKey) {
        var vtWait = document.createElement('div');
        vtWait.className = 'flag-row dim';
        vtWait.textContent = 'VirusTotal: menganalisis...';
        liveBlock.appendChild(vtWait);
      }

      body.appendChild(liveBlock);
    }

    resultArea.appendChild(body);

    setTimeout(function () { bar.style.width = r.score + '%'; }, 40);
  }

  /* ---------------- events ---------------- */

  if (form && input) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (scanInProgress) return;
      var value = input.value.trim();
      if (!value) {
        input.focus();
        input.style.borderColor = '#dc2626';
        setTimeout(function () { input.style.borderColor = ''; }, 800);
        return;
      }
      runScan(value);
    });
  }

  if (newScanBtn) newScanBtn.addEventListener('click', backToInput);

  if (sidebarToggle) sidebarToggle.addEventListener('click', function () { setSidebar(true); });
  if (sidebarClose) sidebarClose.addEventListener('click', function () { setSidebar(false); });
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', function () { setSidebar(false); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') setSidebar(false);
  });
  if (sidebar) sidebar.addEventListener('click', function (e) {
    if (e.target.closest('.side-link')) setSidebar(false);
  });

  if (demoWrap) demoWrap.addEventListener('click', function (e) {
    if (e.target.classList.contains('demo-chip')) {
      if (scanInProgress) return;
      input.value = e.target.textContent;
      runScan(e.target.textContent);
    }
  });

  if (clearBtn) clearBtn.addEventListener('click', function () {
    history = [];
    persistHistory();
    renderHistory();
  });

  if (exportBtn) exportBtn.addEventListener('click', exportReport);

  if (saveSettingsBtn && vtKeyInput && dnsToggle) {
    saveSettingsBtn.addEventListener('click', saveSettings);
    clearKeyBtn.addEventListener('click', function () {
      vtKeyInput.value = '';
      settings.vtKey = '';
      settings.dns = dnsToggle.checked;
      try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (e) {}
      updateMode();
      flashSettingsMsg('API key dihapus');
    });
  }

  /* ---------------- init ---------------- */

  if (vtKeyInput) vtKeyInput.value = settings.vtKey;
  if (dnsToggle) dnsToggle.checked = settings.dns;
  if (footerVersion) footerVersion.textContent = VERSION;
  updateMode();
  if (historyList) renderHistory();
  countVisitor();
  setInterval(countVisitor, 30000);
  if (input) input.focus();

  window.CEKTAUTAN = { version: VERSION, engine: ENGINE, runScan: runScan };
})();