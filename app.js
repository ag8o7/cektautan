/* =========================================================
 *  GHOSTSHELL :: URL Threat Scanner — UI layer
 *  Uses window.ENGINE (engine.js) for detection logic.
 * ========================================================= */
(function () {
  'use strict';

  var ENGINE = window.ENGINE;
  var VERSION = 'v' + (ENGINE && ENGINE.VERSION || '1.1.0');

  var $ = function (id) { return document.getElementById(id); };
  var bootLogEl = $('bootLog');
  var typedEl = $('typedCmd');
  var form = $('scanForm');
  var input = $('urlInput');
  var resultArea = $('resultArea');
  var historyList = $('historyList');
  var chip = $('status-chip');
  var footerVersion = $('footerVersion');
  var channelEl = $('channelStatus');
  var clearBtn = $('clearHistory');
  var exportBtn = $('exportHistory');
  var settingsPanel = $('settingsPanel');
  var vtKeyInput = $('vtKey');
  var dnsToggle = $('dnsToggle');
  var saveSettingsBtn = $('saveSettings');
  var clearKeyBtn = $('clearKey');
  var demoWrap = $('demoWrap');

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
    settings.vtKey = vtKeyInput.value.trim();
    settings.dns = dnsToggle.checked;
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (e) {}
    updateMode();
    flashSettingsMsg('PENGATURAN DISIMPAN');
  }

  function updateMode() {
    if (settings.vtKey) {
      channelEl.textContent = 'LIVE + HEUR';
      channelEl.style.color = '';
    } else {
      channelEl.textContent = 'HEUR (offline)';
      channelEl.style.color = '#ffe033';
    }
  }

  function flashSettingsMsg(text) {
    var msg = $('settingsMsg');
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

  function renderHistory() {
    historyList.innerHTML = '';
    history.forEach(function (h) {
      var li = document.createElement('li');
      li.className = h.verdict.toLowerCase();
      var time = new Date(h.ts).toLocaleTimeString();
      li.innerHTML = '<span class="h-time">' + time + '</span>' +
        '<span class="h-url">' + escapeHtml(h.input) + '</span>' +
        '<span class="h-verdict">[' + h.verdict + ':' + h.score + ']</span>';
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
    lines.push('GHOSTSHELL URL THREAT SCANNER — LAPORAN');
    lines.push('Versi ' + VERSION + ' | ' + new Date().toLocaleString());
    lines.push('='.repeat(56));
    history.forEach(function (h, i) {
      lines.push('#' + (i + 1) + ' [' + new Date(h.ts).toLocaleString() + ']');
      lines.push('  URL     : ' + h.input);
      lines.push('  VERDICT : ' + h.verdict + ' | skor ' + h.score + '/100');
      if (h.notes) lines.push('  CATATAN : ' + h.notes);
      lines.push('');
    });
    if (!history.length) lines.push('(belum ada riwayat scan)');
    var blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'ghostshell-report-' + new Date().toISOString().slice(0, 10) + '.txt';
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

  function sevOf(pts) {
    if (pts >= 50) return { tag: 'KRITIS', cls: 'sev-critical' };
    if (pts >= 25) return { tag: 'TINGGI', cls: 'sev-high' };
    if (pts >= 10) return { tag: 'SEDANG', cls: 'sev-med' };
    return { tag: 'RENDAH', cls: 'sev-low' };
  }

  function recommendation(verdict) {
    if (verdict === 'DANGER') {
      return 'JANGAN buka tautan ini. Kemungkinan besar phishing/pencurian data. Jangan isi username, password, OTP, atau data kartu. Jika sudah terlanjur mengisi, segera ganti kredensial akun terkait.';
    }
    if (verdict === 'WARN') {
      return 'Tautan mencurigakan. Verifikasi manual: cek ejaan domain utama, jumlah subdomain, dan TLD. Jika tidak yakin dengan keasliannya, jangan dibuka.';
    }
    return 'Tidak ada indikator mencurigakan yang kuat. Tetap waspada: jangan berikan OTP/kredensial ke situs yang tidak kamu yakini.';
  }

  function setChip(state) {
    chip.textContent = state.text;
    chip.className = 'chip ' + state.cls;
  }

  /* ---------------- scan flow ---------------- */

  var currentResult = null;
  var scanInProgress = false;

  function runScan(raw) {
    var r = ENGINE.scanUrl(raw);
    r.heurScore = r.score;
    currentResult = r;

    setChip({ text: 'SCANNING', cls: 'scanning' });
    input.disabled = true;
    $('scanBtn').disabled = true;
    resultArea.hidden = true;
    resultArea.innerHTML = '';
    scanInProgress = true;

    var promptText = 'ghost_scan --target "' + raw + '"';
    typePrompt(promptText).then(function () {
      renderResult(r);
      runLive(r);
    });
  }

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
    }
  }

  function applyLive(r) {
    var lv = ENGINE.liveScore(r);
    r.live.flags = lv.flags;
    r.score = Math.min(r.heurScore + lv.pts, 100);
    r.grade = ENGINE.gradeScore(r.score);
    renderResult(r);

    var liveDone =
      (settings.dns && r.live.dns) &&
      (settings.vtKey ? (r.live.vt || r.live.vtError) : true);

    if (liveDone) finishScan(r);
  }

  function finishScan(r) {
    scanInProgress = false;
    input.disabled = false;
    $('scanBtn').disabled = false;
    input.value = '';
    input.focus();

    setChip({
      text: r.grade.verdict === 'DANGER' ? 'DANGER' : (r.grade.verdict === 'WARN' ? 'CAUTION' : 'CLEAN'),
      cls: r.grade.verdict === 'DANGER' ? 'done-danger' : (r.grade.verdict === 'WARN' ? 'scanning' : 'done-clean')
    });

    var notes = [];
    if (r.live.vt && r.live.vt.stats) {
      notes.push('VirusTotal: ' + r.live.vt.stats.malicious + ' malicious / ' + r.live.vt.stats.suspicious + ' suspicious dari total engine.');
    }
    if (r.live.dns && r.live.dns.ok && !r.live.dns.resolved) notes.push('Domain tidak resolve di DNS.');

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

    var head = document.createElement('div');
    head.className = 'result-head';
    head.innerHTML = '<b>' + r.grade.label + '</b> <span class="score-inline">skor ' + r.score + '/100</span>';
    resultArea.appendChild(head);

    var body = document.createElement('div');
    body.className = 'result-body';

    var rec = document.createElement('div');
    rec.className = 'recommend ' + verdictWord;
    rec.textContent = '>> REKOMENDASI: ' + recommendation(r.grade.verdict);
    body.appendChild(rec);

    var p = r.parsed;
    var protoNote = p.hasProtocol ? '' : ' (tidak ditulis — hanya hostname yang dianalisis)';
    var sum = document.createElement('div');
    sum.className = 'summary';
    sum.innerHTML =
      '<div class="sum-row"><span class="sum-k">TARGET</span><span class="sum-v">' + escapeHtml(r.input) + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">HOST</span><span class="sum-v">' + escapeHtml(p.host || 'N/A') + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">DOMAIN UTAMA</span><span class="sum-v">' + escapeHtml(p.regDomain || 'N/A') + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">TLD</span><span class="sum-v">' + escapeHtml(p.tld || 'N/A') + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">SUBDOMAIN</span><span class="sum-v">' + p.subdomains.length + ' level' +
        (p.subdomains.length ? ' (' + escapeHtml(p.subdomains.join('.')) + ')' : '') + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">PROTOKOL</span><span class="sum-v">' + escapeHtml(p.protocol || 'tidak ditentukan') + protoNote + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">IP LANGSUNG</span><span class="sum-v">' + (p.isIp ? 'YA — berisiko tinggi' : 'tidak') + '</span></div>' +
      '<div class="sum-row"><span class="sum-k">SUMBER</span><span class="sum-v">' + (settings.vtKey ? 'heuristik + VirusTotal + DNS' : 'heuristik + DNS (VirusTotal nonaktif)') + '</span></div>';
    body.appendChild(sum);

    appendFindings(body, 'HEURISTIK (POLA STATIS)', r.flags);

    if (r.live.dns || r.live.vt || r.live.vtError) {
      var liveFlags = (r.live.flags || []).slice();
      var liveBlock = document.createElement('div');
      liveBlock.className = 'live-block';
      var liveHead = document.createElement('div');
      liveHead.className = 'findings-head';
      liveHead.textContent = '-- SINYAL LIVE (JARINGAN) --';
      liveBlock.appendChild(liveHead);

      if (r.live.dns) {
        var dnsRow = document.createElement('div');
        dnsRow.className = 'flag-row' + (r.live.dns.ok && !r.live.dns.resolved ? ' danger' : '');
        var dnsTxt = r.live.dns.ok
          ? (r.live.dns.resolved
            ? 'DNS: domain ter-resolve (' + (r.live.dns.ips || []).join(', ') + ').'
            : 'DNS: domain TIDAK resolve — tidak ditemukan record.')
          : 'DNS: pemeriksaan gagal (' + (r.live.dns.error || '?') + ').';
        dnsRow.textContent = dnsTxt;
        liveBlock.appendChild(dnsRow);
      } else {
        var dnsWait = document.createElement('div');
        dnsWait.className = 'flag-row dim';
        dnsWait.textContent = 'DNS: memeriksa...';
        liveBlock.appendChild(dnsWait);
      }

      if (r.live.vt) {
        var st = r.live.vt.stats;
        var vtRow = document.createElement('div');
        vtRow.className = 'flag-row' + (st && st.malicious > 0 ? ' danger' : '');
        if (st) {
          vtRow.textContent = 'VirusTotal: ' + st.malicious + ' malicious · ' + st.suspicious + ' suspicious · ' + st.harmless + ' harmless.';
        } else {
          vtRow.textContent = 'VirusTotal: hasil tidak tersedia.';
        }
        liveBlock.appendChild(vtRow);
        if (r.live.vt.reportUrl) {
          var vtLink = document.createElement('div');
          vtLink.className = 'metric';
          vtLink.innerHTML = '<a class="vt-link" href="' + escapeHtml(r.live.vt.reportUrl) + '" target="_blank" rel="noopener noreferrer">BUKA_LAPORAN_VIRUSTOTAL &gt;&gt;</a>';
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

      liveFlags.forEach(function (f) {
        var row = document.createElement('div');
        row.className = 'flag-row' + (f.danger ? ' danger' : '');
        var sev = sevOf(f.pts);
        row.innerHTML = '<span class="sev ' + sev.cls + '">' + sev.tag + '</span> <span class="pts">[+' + f.pts + ']</span> ' + escapeHtml(f.msg);
        liveBlock.appendChild(row);
      });

      body.appendChild(liveBlock);
    } else if (settings.dns || settings.vtKey) {
      var wait = document.createElement('div');
      wait.className = 'flag-row dim';
      wait.textContent = '>> sinyal live sedang dikumpulkan...';
      body.appendChild(wait);
    }

    var scoreWrap = document.createElement('div');
    scoreWrap.className = 'score-line';
    scoreWrap.innerHTML = '<span class="metric">SKOR ANCAMAN: <span class="val">' + r.score + '/100</span> ' +
      '(' + (r.score >= 50 ? 'tinggi' : r.score >= 20 ? 'sedang' : 'rendah') + ')</span>';
    var barWrap = document.createElement('div');
    barWrap.className = 'score-bar-wrap';
    var bar = document.createElement('div');
    bar.className = 'score-bar ' + verdictWord;
    bar.style.width = '0%';
    barWrap.appendChild(bar);
    scoreWrap.appendChild(barWrap);
    body.appendChild(scoreWrap);

    resultArea.appendChild(body);

    setTimeout(function () { bar.style.width = r.score + '%'; }, 40);
  }

  function appendFindings(parent, label, flags) {
    var fHead = document.createElement('div');
    fHead.className = 'findings-head';
    fHead.textContent = '-- ' + label + ' (' + flags.length + ') --';
    parent.appendChild(fHead);

    if (!flags.length) {
      var none = document.createElement('div');
      none.className = 'metric';
      none.textContent = 'Tidak ada indikator mencurigakan pada lapisan ini.';
      parent.appendChild(none);
      return;
    }

    flags.forEach(function (f) {
      var row = document.createElement('div');
      row.className = 'flag-row' + (f.danger ? ' danger' : '');
      var sev = sevOf(f.pts);
      row.innerHTML = '<span class="sev ' + sev.cls + '">' + sev.tag + '</span> ' +
        '<span class="pts">[+' + f.pts + ']</span> ' + escapeHtml(f.msg);
      parent.appendChild(row);
    });
  }

  /* ---------------- boot / typing ---------------- */

  var bootLines = [
    { cls: 'system', txt: '> GHOSTSHELL v' + VERSION.slice(1) + ' initializing...' },
    { cls: 'ok', txt: '[OK] signature DB: ' + (ENGINE.SUSPICIOUS_TLDS.length + ENGINE.SHORTENERS.length + ENGINE.SUSPICIOUS_KEYWORDS.length + ENGINE.BRANDS.length) + ' pattern' },
    { cls: 'ok', txt: '[OK] heuristik 15 lapis + brand-similarity (edit-distance) aktif' },
    { cls: 'dim', txt: '> DNS live-check via cloudflare-dns.com (DoH)' + (settings.vtKey ? '' : ' | VirusTotal: NONAKTIF — isi API key di SETTINGS') },
    { cls: 'warn', txt: '> jangan pernah membuka tautan berstatus DANGER' }
  ];

  function typeBoot(step) {
    if (step >= bootLines.length) {
      updateMode();
      chip.textContent = 'READY';
      chip.className = 'chip idle';
      input.focus();
      return;
    }
    var line = bootLines[step];
    var div = document.createElement('div');
    div.className = 'row ' + line.cls;
    bootLogEl.appendChild(div);
    var chars = line.txt;
    var i = 0;
    var typeInt = setInterval(function () {
      div.textContent = line.txt.slice(0, ++i);
      if (i >= chars.length) {
        clearInterval(typeInt);
        setTimeout(function () { typeBoot(step + 1); }, 80);
      }
    }, 9);
  }

  function typePrompt(text) {
    var i = 0;
    typedEl.textContent = '';
    return new Promise(function (resolve) {
      var int = setInterval(function () {
        typedEl.textContent = text.slice(0, ++i);
        if (i >= text.length) { clearInterval(int); resolve(); }
      }, 22);
    });
  }

  function updateClock() {
    var d = new Date();
    $('clock').textContent =
      String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0') + ':' +
      String(d.getSeconds()).padStart(2, '0');
  }

  /* ---------------- events ---------------- */

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (scanInProgress) return;
    var value = input.value.trim();
    if (!value) {
      input.focus();
      input.style.borderColor = '#ff3344';
      setTimeout(function () { input.style.borderColor = ''; }, 800);
      return;
    }
    runScan(value);
  });

  demoWrap.addEventListener('click', function (e) {
    if (e.target.classList.contains('demo-chip')) {
      input.value = e.target.textContent;
      runScan(e.target.textContent);
    }
  });

  clearBtn.addEventListener('click', function () {
    history = [];
    persistHistory();
    renderHistory();
  });

  exportBtn.addEventListener('click', exportReport);

  saveSettingsBtn.addEventListener('click', saveSettings);
  clearKeyBtn.addEventListener('click', function () {
    vtKeyInput.value = '';
    settings.vtKey = '';
    settings.dns = dnsToggle.checked;
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch (e) {}
    updateMode();
    flashSettingsMsg('API KEY DIHAPUS');
  });

  /* ---------------- init ---------------- */

  vtKeyInput.value = settings.vtKey;
  dnsToggle.checked = settings.dns;
  footerVersion.textContent = 'Version ' + VERSION;
  setInterval(updateClock, 1000);
  updateClock();
  renderHistory();
  typeBoot(0);

  window.GHOSTSHELL = { version: VERSION, engine: ENGINE, runScan: runScan };
})();
