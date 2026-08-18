/* =========================================================
 *  GHOSTSHELL :: URL Threat Scanner — detection engine
 *  Pure logic, no DOM. Works in browser AND node (for tests).
 *  Exposed as window.ENGINE in browser, module.exports in node.
 * ========================================================= */
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ENGINE = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.loan',
    '.click', '.link', '.gdn', '.bid', '.vip', '.icu', '.cyou', '.bar',
    '.rest', '.bond', '.country', '.stream', '.zip', '.mov'
  ];

  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rb.gy', 'cutt.ly', 'tiny.cc', 'shorturl.at', 'rebrand.ly',
    's.id', 'u.to', 'lnkd.in', 'tny.im', 'qr.ae', 'vgd.me', 'adf.ly'
  ];

  var SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'confirm', 'wallet', 'unlock', 'suspend',
    'limited', 'prize', 'winner', 'reward', 'bonus', 'refund', 'invoice',
    'password', 'credential', '2fa', 'otp', 'token', 'recover',
    'alert', 'urgent', 'support', 'billing', 'claim', 'crypto',
    'bitcoin', 'coupon', 'signup', 'activity'
  ];

  /* Nama brand resmi. Baris ini sengaja dipisah (tanpa regex) agar
     pemeriksaan memakai logika kesamaan (edit-distance), bukan substring mentah. */
  var BRANDS = [
    'paypal', 'facebook', 'instagram', 'google', 'gmail', 'amazon',
    'microsoft', 'netflix', 'apple', 'whatsapp', 'telegram', 'binance',
    'coinbase', 'metamask', 'shopee', 'tokopedia', 'dana', 'gojek',
    'grab', 'bca', 'mandiri', 'bri', 'bni', 'ocbc', 'mastercard', 'visa'
  ];

  /* Kata umum di belakang/depan nama brand pada domain phishing
     (mis. paypal-secure, verify-paypal, paypallogin). */
  var BRAND_TRAIL = /^\d+$|-(login|signin|secure|security|verify|verification|support|help|account|update|confirm|id|info|online|service|token|pay|check|alert|unlock|prime|rewards|gift|cash|win|shop|store)$|^(login|secure|verify|support|help|account|update|confirm|id|info|online|service|token|pay)-/;

  /* ccTLD dua tingkat (co.id, co.uk, ...) agar BNI dkk. tidak salah hitung. */
  var SECOND_LEVEL_TLDS = [
    'co.id', 'or.id', 'web.id', 'ac.id', 'go.id', 'co.uk', 'org.uk',
    'ac.uk', 'gov.uk', 'co.nz', 'com.au', 'net.au', 'co.in', 'com.br',
    'co.jp', 'co.kr', 'com.sg', 'com.my', 'com.hk', 'com.cn', 'org.cn',
    'com.tr', 'com.tw', 'com.vn', 'co.th', 'com.ph', 'com.mx', 'co.za'
  ];

  var LOOKALIKE_MAP = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b' };

  /* ---------------- helpers ---------------- */

  function stripProtocol(raw) {
    var s = raw.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(s)) {
      s = 'http://' + s;
    }
    return s;
  }

  function parseUrl(raw) {
    var userProtocol = /^https?:\/\//i.test(raw.trim());
    var url = stripProtocol(raw);
    var res = {
      raw: raw, url: url, host: '', subdomains: [], tld: '',
      regDomain: '', sld: '', path: '', protocol: '', port: '',
      isIp: false, hasProtocol: userProtocol, parseError: false
    };

    try {
      var u = new URL(url);
      res.host = u.hostname.toLowerCase().replace(/\.$/, '');
      res.path = (u.pathname || '') + (u.search || '');
      res.port = u.port;
      res.protocol = u.protocol;

      var host = res.host;
      res.isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(host);

      var parts = host.split('.');
      res.tld = parts.length >= 2 ? '.' + parts[parts.length - 1] : '';
      res.subdomains = parts.slice(0, Math.max(1, parts.length - 2));

      var n = parts.length;
      if (n >= 3 && SECOND_LEVEL_TLDS.indexOf(parts[n - 2] + '.' + parts[n - 1]) !== -1) {
        res.regDomain = parts[n - 3] + '.' + parts[n - 2] + '.' + parts[n - 1];
        res.sld = parts[n - 3];
      } else if (n >= 2) {
        res.regDomain = parts[n - 2] + '.' + parts[n - 1];
        res.sld = parts[n - 2];
      } else {
        res.regDomain = host;
        res.sld = host;
      }
    } catch (e) {
      res.parseError = true;
      res.host = url.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].toLowerCase();
    }
    return res;
  }

  function normalizeForBrand(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      out += LOOKALIKE_MAP[c] || c;
    }
    return out;
  }

  function levenshtein(a, b) {
    var m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    var dp = [];
    for (var i = 0; i <= m; i++) dp[i] = [i];
    for (var j = 0; j <= n; j++) dp[0][j] = j;
    for (var r = 1; r <= m; r++) {
      for (var c = 1; c <= n; c++) {
        var cost = a[r - 1] === b[c - 1] ? 0 : 1;
        dp[r][c] = Math.min(dp[r - 1][c] + 1, dp[r][c - 1] + 1, dp[r - 1][c - 1] + cost);
      }
    }
    return dp[m][n];
  }

  function countOccurrences(str, ch) {
    return (str.match(new RegExp('\\' + ch, 'g')) || []).length;
  }

  /* ---------------- rule engine ---------------- */

  var FLAGS = [];

  function flag(pts, msg, danger, source) {
    FLAGS.push({ pts: pts, msg: msg, danger: !!danger, source: source || 'HEUR' });
  }

  function buildRuleSet(parsed) {
    FLAGS = [];
    var host = parsed.host || '';
    var path = parsed.path || '';
    var full = (host + path).toLowerCase();

    if (parsed.parseError) {
      flag(60, 'URL tidak valid / tidak bisa diurai.', true);
      return;
    }

    if (parsed.isIp) {
      flag(50, 'Host berupa IP mentah (bukan domain) — khas situs phishing.', true);
    }

    for (var s = 0; s < SHORTENERS.length; s++) {
      if (host === SHORTENERS[s] || host.indexOf(SHORTENERS[s]) === 0) {
        flag(25, 'URL shortener "' + SHORTENERS[s] + '" — menyembunyikan tujuan sebenarnya.', false);
        break;
      }
    }

    for (var t = 0; t < SUSPICIOUS_TLDS.length; t++) {
      if (parsed.tld === SUSPICIOUS_TLDS[t]) {
        flag(30, 'TLD berisiko tinggi "' + parsed.tld + '".', false);
        break;
      }
    }

    if (parsed.subdomains.length >= 4) {
      flag(20, parsed.subdomains.length + ' level subdomain (obfuskasi alamat).', false);
    }

    if (full.indexOf('@') !== -1) {
      flag(35, 'Karakter "@" dipakai untuk menutupi host tujuan sebenarnya.', true);
    }

    if (parsed.hasProtocol && parsed.protocol !== 'https:') {
      flag(20, 'Protokol HTTP eksplisit tanpa enkripsi TLS.', false);
    }

    if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
      flag(15, 'Port tidak standar "' + parsed.port + '".', false);
    }

    if ((host + path).length > 100) {
      flag(10, 'URL sangat panjang (' + (host + path).length + ' karakter).', false);
    }
    if (host.length > 45) {
      flag(15, 'Hostname terlalu panjang (' + host.length + ' karakter).', false);
    }

    var dots = countOccurrences(host, '.');
    if (dots >= 4) {
      flag(15, dots + ' titik di hostname.', false);
    }

    var keywordFlags = 0;
    for (var k = 0; k < SUSPICIOUS_KEYWORDS.length; k++) {
      if (path.toLowerCase().indexOf(SUSPICIOUS_KEYWORDS[k]) !== -1) {
        keywordFlags++;
        if (keywordFlags <= 2) {
          flag(6, 'Kata "' + SUSPICIOUS_KEYWORDS[k] + '" pada path URL.');
        }
      }
    }

    var digitCount = (host.replace(/\./g, '').match(/\d/g) || []).length;
    if (digitCount >= 3) {
      flag(12, digitCount + ' angka menempel di hostname.', false);
    }

    var hyphens = countOccurrences(host, '-');
    if (hyphens >= 3) {
      flag(18, hyphens + ' tanda strip di hostname (penanda typosquat).', false);
    }

    /* Brand impersonation — berbasis kesamaan domain utama (SLD), bukan substring bebas */
    var regD = parsed.regDomain || host;
    var sld = (parsed.sld || sldOf(regD)).toLowerCase();
    var hostBody = '';
    var idx = host.indexOf(regD);
    if (idx > 0) hostBody = host.slice(0, idx).replace(/\.$/, '');

    for (var b = 0; b < BRANDS.length; b++) {
      var name = BRANDS[b];

      if (sld === name) continue; // domain brand yang asli → aman

      var cleanSld = normalizeForBrand(sld);
      var dist = levenshtein(cleanSld, name);

      /* Brand pendek (<=4 huruf) rentan bentrok dengan SLD generik pendek
         (mis. "bni" vs "bit") → hanya pakai sinyal homoglyph/trail/subdomain. */
      if (name.length > 4 && dist <= 2 && Math.abs(cleanSld.length - name.length) <= 2) {
        flag(55, 'Domain utama hampir sama dengan brand "' + name + '" (typosquat, jarak ' + dist + ').', true);
      } else if (dist === 0 && sld !== name) {
        flag(55, 'Domain memakai karakter mirip brand "' + name + '" (homoglyph).', true);
      } else if (cleanSld.indexOf(name) !== -1) {
        var rest = cleanSld.replace(name, '');
        if (BRAND_TRAIL.test(rest)) {
          flag(50, 'Nama brand "' + name + '" + kata mencurigakan di domain utama.', true);
        }
      }

      if (hostBody.indexOf(name) !== -1) {
        flag(50, 'Brand "' + name + '" disembunyikan di subdomain domain lain — pola phishing login palsu.', true);
      }
    }

    if (host.indexOf('xn--') !== -1) {
      flag(45, 'Hostname internationalized (punycode) — risiko homograph.', true);
    }

    if (/[_~!$%^&=+?]/.test(host)) {
      flag(15, 'Karakter aneh di hostname.', false);
    }
  }

  function sldOf(regDomain) {
    var p = (regDomain || '').split('.');
    return p.length >= 2 ? p[p.length - 2] : (regDomain || '');
  }

  function gradeScore(score) {
    if (score >= 50) return { verdict: 'DANGER', cls: 'danger', label: 'RISIKO TINGGI — JANGAN DIBUKA' };
    if (score >= 20) return { verdict: 'WARN', cls: 'warn', label: 'MENCURIGAKAN — PERLU VERIFIKASI' };
    return { verdict: 'CLEAN', cls: 'clean', label: 'LOW RISK — TIDAK TERINDIKASI' };
  }

  function scanUrl(raw) {
    var parsed = parseUrl(raw);
    buildRuleSet(parsed);
    var score = FLAGS.reduce(function (a, f) { return a + f.pts; }, 0);
    var grade = gradeScore(score);
    return {
      input: raw,
      parsed: parsed,
      flags: FLAGS.slice(),
      score: Math.min(score, 100),
      grade: grade,
      live: { dns: null, vt: null },
      ts: Date.now()
    };
  }

  /* ---------------- live checks (async) ---------------- */

  function dnsResolve(host) {
    var cleanHost = (host || '').split(':')[0].replace(/\.$/, '');
    if (!cleanHost || /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost)) {
      return Promise.resolve({ ok: true, resolved: true, ips: [], note: 'IP langsung — DNS tidak diperiksa' });
    }
    return fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(cleanHost) + '&type=A', {
      headers: { accept: 'application/dns-json' }
    })
      .then(function (r) { if (!r.ok) throw new Error('dns http ' + r.status); return r.json(); })
      .then(function (j) {
        var answers = j.Answer || [];
        var ips = answers.filter(function (a) { return a.type === 1; }).map(function (a) { return a.data; });
        return { ok: true, resolved: ips.length > 0, ips: ips, note: 'resolved via cloudflare-dns.com' };
      })
      .catch(function (e) {
        return { ok: false, resolved: false, ips: [], error: e.message };
      });
  }

  function vtAnalyze(url, apiKey) {
    var body = new URLSearchParams();
    body.set('url', url);
    return fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: body
    })
      .then(function (r) {
        if (!r.ok) throw new Error('VirusTotal submit HTTP ' + r.status);
        return r.json();
      })
      .then(function (j) {
        var id = j.data && j.data.id;
        if (!id) throw new Error('VirusTotal: tidak ada analysis id');
        return vtPoll(id, apiKey);
      });
  }

  function vtPoll(id, apiKey) {
    return fetch('https://www.virustotal.com/api/v3/analyses/' + id, {
      headers: { 'x-apikey': apiKey }
    })
      .then(function (r) {
        if (!r.ok) throw new Error('VirusTotal poll HTTP ' + r.status);
        return r.json();
      })
      .then(function (j) {
        var attrs = j.data && j.data.attributes;
        if (attrs && attrs.status === 'completed') return j;
        return new Promise(function (resolve, reject) {
          setTimeout(function () {
            vtPoll(id, apiKey).then(resolve).catch(reject);
          }, 4000);
        });
      });
  }

  function vtSummarize(resultJson) {
    var attrs = resultJson && resultJson.data && resultJson.data.attributes;
    var meta = resultJson && resultJson.meta || {};
    var hash = meta.url_info && meta.url_info.id;
    return {
      stats: attrs ? {
        malicious: attrs.stats.malicious || 0,
        suspicious: attrs.stats.suspicious || 0,
        harmless: attrs.stats.harmless || 0,
        undetected: attrs.stats.undetected || 0,
        timeout: attrs.stats.timeout || 0
      } : null,
      finalUrl: attrs ? (attrs.url || '') : '',
      hash: hash,
      reportUrl: hash ? 'https://www.virustotal.com/gui/url/' + hash : ''
    };
  }

  function liveScore(parsedResult) {
    var pts = 0;
    var flags = [];
    var live = parsedResult.live || {};

    if (live.dns && live.dns.ok && !live.dns.resolved && !parsedResult.parsed.isIp) {
      pts += 10;
      flags.push({ pts: 10, msg: 'DNS: domain tidak resolve (tidak ada record A) — khas domain phishing yang nonaktif.', danger: false, source: 'DNS' });
    }

    if (live.vt && live.vt.stats) {
      var m = live.vt.stats.malicious;
      var sus = live.vt.stats.suspicious;
      if (m > 0) {
        pts += 50;
        flags.push({ pts: 50, msg: 'VirusTotal: ' + m + ' engine menyatakan MALICIOUS.', danger: true, source: 'VT' });
      } else if (sus > 0) {
        pts += 15;
        flags.push({ pts: 15, msg: 'VirusTotal: ' + sus + ' engine menilai SUSPICIOUS.', danger: false, source: 'VT' });
      }
    }

    return { pts: pts, flags: flags };
  }

  return {
    VERSION: '1.3.0',
    SUSPICIOUS_TLDS: SUSPICIOUS_TLDS,
    SHORTENERS: SHORTENERS,
    SUSPICIOUS_KEYWORDS: SUSPICIOUS_KEYWORDS,
    BRANDS: BRANDS,
    parseUrl: parseUrl,
    scanUrl: scanUrl,
    gradeScore: gradeScore,
    dnsResolve: dnsResolve,
    vtAnalyze: vtAnalyze,
    vtSummarize: vtSummarize,
    liveScore: liveScore,
    levenshtein: levenshtein
  };
});
