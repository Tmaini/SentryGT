/* =========================================================
   Sentry — client-side heuristic link/message risk checker
   Runs entirely in the browser. No network calls, no data leaves
   the device. This is a pattern-based prototype, not a live
   threat-intelligence lookup (see README for how to upgrade it
   to a real API-backed version).
   ========================================================= */

(function () {
  const input = document.getElementById('checker-input');
  const btn = document.getElementById('checker-btn');
  const resultBox = document.getElementById('checker-result');
  const badge = document.getElementById('result-badge');
  const reasonsList = document.getElementById('result-reasons');
  const emptyMsg = document.getElementById('result-empty');

  if (!btn) return; // checker not on this page

  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy'
  ];

  const SUSPICIOUS_TLDS = [
    '.zip', '.mov', '.xyz', '.top', '.click', '.country', '.gq',
    '.tk', '.ml', '.cf', '.work', '.support', '.loan', '.win',
    '.icu', '.rest', '.quest'
  ];

  const WATCHED_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'netflix',
    'bankofamerica', 'wellsfargo', 'chase', 'irs', 'usps',
    'fedex', 'ups', 'dhl', 'google', 'facebook', 'instagram',
    'venmo', 'zelle', 'coinbase'
  ];

  const URGENCY_PHRASES = [
    'verify your account', 'act now', 'suspended', 'confirm your identity',
    'limited time', 'click immediately', 'unusual activity',
    'update your payment', 'claim your reward', 'you have won',
    'confirm your password', "couldn't be delivered", 'failure to respond',
    'final notice', 'account will be closed', 'unauthorized access'
  ];

  function extractUrls(text) {
    // Matches http(s):// links and bare domain-like strings (e.g. bit.ly/xyz)
    const withProtocol = text.match(/https?:\/\/[^\s]+/gi) || [];
    const bareDomains = text.match(/\b[a-z0-9-]+\.[a-z]{2,}(?:\/[^\s]*)?\b/gi) || [];
    const combined = [...withProtocol];
    bareDomains.forEach((d) => {
      if (!combined.some((u) => u.includes(d))) combined.push(d);
    });
    return [...new Set(combined)];
  }

  function toUrlObject(raw) {
    try {
      return new URL(raw.match(/^https?:\/\//) ? raw : 'http://' + raw);
    } catch (e) {
      return null;
    }
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[m][n];
  }

  function analyzeUrl(raw) {
    const flags = [];
    const parsed = toUrlObject(raw);
    if (!parsed) return { raw, flags: ['Could not be parsed as a valid link'], score: 1 };

    const host = parsed.hostname.toLowerCase();
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);

    if (isIp) {
      flags.push({ text: 'Link uses a raw IP address instead of a domain name — a common way to hide the real destination', weight: 3 });
    }

    if (URL_SHORTENERS.some((s) => host === s || host.endsWith('.' + s))) {
      flags.push({ text: 'Uses a link-shortening service, which hides where the link actually goes', weight: 2 });
    }

    if (SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) {
      flags.push({ text: `Domain ending (${host.slice(host.lastIndexOf('.'))}) is commonly abused for scam sites because it's cheap to register`, weight: 2 });
    }

    if (raw.includes('@') && raw.indexOf('@') < raw.indexOf(host)) {
      flags.push({ text: 'Contains an "@" before the domain — a known trick to disguise the real destination', weight: 3 });
    }

    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      flags.push({ text: 'Domain name has an unusually high number of hyphens, often used to mimic a real brand name', weight: 1 });
    }

    const subdomainDepth = host.split('.').length;
    if (subdomainDepth >= 5) {
      flags.push({ text: 'Domain has an unusually deep subdomain structure, sometimes used to bury the real domain', weight: 1 });
    }

    if (parsed.protocol !== 'https:') {
      flags.push({ text: 'Not using a secure (https) connection', weight: 1 });
    }

    // Brand impersonation check: domain contains, or nearly matches, a watched brand
    // without being that brand's actual root domain.
    const cleanHost = host.replace(/^www\./, '');
    const rootDomain = cleanHost.split('.').slice(-2, -1)[0] || '';
    const leet = (s) => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't');
    const tokens = cleanHost.split(/[.\-_]/).filter(Boolean);

    let impersonationFlagged = false;
    WATCHED_BRANDS.forEach((brand) => {
      if (impersonationFlagged) return;

      if (rootDomain === brand) return; // this IS the brand's own domain, e.g. paypal.com

      // Exact brand name appears somewhere in the domain (e.g. amazon-support.xyz)
      if (cleanHost.includes(brand)) {
        flags.push({ text: `Mentions "${brand}" in the domain but doesn't match ${brand}'s actual site — a common impersonation pattern`, weight: 3 });
        impersonationFlagged = true;
        return;
      }

      // Check each hyphen/dot-separated token for a leetspeak or 1-character-off match
      tokens.forEach((token) => {
        if (impersonationFlagged) return;
        const normalized = leet(token);
        if (normalized === brand && token !== brand) {
          flags.push({ text: `Domain uses "${token}" as a lookalike for "${brand}" (character substitution) — a common typosquat trick`, weight: 3 });
          impersonationFlagged = true;
        } else if (Math.abs(token.length - brand.length) <= 1 && levenshtein(normalized, brand) === 1) {
          flags.push({ text: `Domain segment "${token}" is one character off from "${brand}" — possible lookalike/typosquat`, weight: 3 });
          impersonationFlagged = true;
        }
      });
    });

    const score = flags.reduce((sum, f) => sum + f.weight, 0);
    return { raw, flags: flags.map((f) => f.text), score };
  }

  function analyzeText(text) {
    const urgencyHits = URGENCY_PHRASES.filter((p) => text.toLowerCase().includes(p));
    return urgencyHits.map((p) => `Message uses urgency/pressure language: "${p}"`);
  }

  function scoreToRisk(score) {
    if (score === 0) return { level: 'low', label: 'Looks low-risk' };
    if (score <= 2) return { level: 'medium', label: 'Some risk signals' };
    return { level: 'high', label: 'High-risk signals detected' };
  }

  function render(urls, textFlags, overallText) {
    reasonsList.innerHTML = '';
    let totalScore = 0;
    let anyReasons = false;

    if (textFlags.length) {
      anyReasons = true;
      textFlags.forEach((t) => {
        const li = document.createElement('li');
        li.textContent = t;
        reasonsList.appendChild(li);
      });
      totalScore += textFlags.length;
    }

    urls.forEach(({ raw, flags, score }) => {
      totalScore += score;
      if (flags.length) {
        anyReasons = true;
        const header = document.createElement('li');
        header.className = 'reason-url';
        header.textContent = raw;
        reasonsList.appendChild(header);
        flags.forEach((f) => {
          const li = document.createElement('li');
          li.textContent = f;
          reasonsList.appendChild(li);
        });
      }
    });

    const risk = scoreToRisk(totalScore);
    badge.className = 'result-badge risk-' + risk.level;
    badge.textContent = risk.label;

    emptyMsg.hidden = urls.length > 0 || overallText.trim() === '';
    if (!urls.length && !textFlags.length) {
      emptyMsg.hidden = false;
      emptyMsg.textContent = urls.length
        ? 'No specific risk signals found in what was checked.'
        : 'No links found in the pasted text — try including the full URL.';
    } else {
      emptyMsg.hidden = true;
    }

    resultBox.hidden = false;
  }

  btn.addEventListener('click', function () {
    const text = input.value || '';
    const urls = extractUrls(text).map(analyzeUrl);
    const textFlags = analyzeText(text);
    render(urls, textFlags, text);
  });
})();
