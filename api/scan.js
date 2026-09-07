export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { target, authorized } = req.body || {};
  if (!authorized) return res.status(403).json({ error: 'Authorization confirmation required.' });
  if (!target || typeof target !== 'string') return res.status(400).json({ error: 'Target URL is required.' });

  let url;
  try { url = new URL(target); } catch { return res.status(400).json({ error: 'Invalid target URL.' }); }
  if (!['https:', 'http:'].includes(url.protocol)) return res.status(400).json({ error: 'Only HTTP(S) targets are supported.' });

  const allowed = (process.env.ALLOWED_TARGET_HOSTS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
  if (!allowed.length || !allowed.some(host => url.hostname === host || url.hostname.endsWith('.' + host))) {
    return res.status(403).json({ error: 'Target host is not allowlisted. Configure ALLOWED_TARGET_HOSTS in Vercel for your authorized staging environment.' });
  }

  const started = Date.now();
  const findings = [];
  const checked = [];
  const endpoints = new Set(['/']);
  const seen = new Set();

  async function request(path, method = 'GET') {
    const u = new URL(path, url.origin);
    if (u.hostname !== url.hostname) return null;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    try {
      const r = await fetch(u, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'WorldGuard-AI-Authorized-Assessment/1.1', 'Accept': 'text/html,application/json,text/plain,*/*' }
      });
      const text = method === 'GET' && /text|json|javascript|xml/i.test(r.headers.get('content-type') || '') ? (await r.text()).slice(0, 180000) : '';
      return { r, headers: Object.fromEntries(r.headers.entries()), text, path: u.pathname };
    } finally { clearTimeout(timeout); }
  }

  try {
    const root = await request(url.pathname || '/');
    if (!root) return res.status(502).json({ error: 'Target unavailable.' });
    checked.push('HTTP availability');

    const headers = root.headers;
    const securityHeaders = [
      ['content-security-policy', 'Missing Content-Security-Policy', 'MEDIUM', 'A browser policy can reduce the impact of injected script and content-loading attacks.'],
      ['x-content-type-options', 'Missing X-Content-Type-Options', 'LOW', 'Add X-Content-Type-Options: nosniff.'],
      ['referrer-policy', 'Missing Referrer-Policy', 'LOW', 'Set an explicit Referrer-Policy appropriate for the application.'],
      ['permissions-policy', 'Missing Permissions-Policy', 'LOW', 'Restrict browser capabilities that the application does not need.']
    ];
    for (const [key, title, severity, remediation] of securityHeaders) {
      if (!headers[key]) findings.push({ id: key, title, severity, cvss: severity === 'MEDIUM' ? 5.3 : 3.7, evidence: `GET ${root.path || '/'} returned no ${key} header.`, remediation });
    }
    checked.push('security headers');

    const setCookie = headers['set-cookie'] || '';
    if (setCookie) {
      const cookieProblems = [];
      if (url.protocol === 'https:' && !/;\s*secure\b/i.test(setCookie)) cookieProblems.push('Secure');
      if (!/;\s*httponly\b/i.test(setCookie)) cookieProblems.push('HttpOnly');
      if (!/;\s*samesite\s*=/i.test(setCookie)) cookieProblems.push('SameSite');
      if (cookieProblems.length) findings.push({ id: 'cookie-flags', title: 'Session Cookie Security Flags', severity: 'MEDIUM', cvss: 5.4, evidence: `Set-Cookie was observed without: ${cookieProblems.join(', ')}.`, remediation: 'Apply Secure, HttpOnly and an appropriate SameSite policy to session cookies.' });
    }
    checked.push('cookie flags when present');

    if (headers['access-control-allow-origin'] === '*') findings.push({ id: 'cors-wildcard', title: 'Wildcard CORS Policy', severity: 'MEDIUM', cvss: 5.3, evidence: 'The response advertises Access-Control-Allow-Origin: *.', remediation: 'Allow only trusted origins where cross-origin access is required.' });
    checked.push('CORS response policy');

    const versionHeaders = ['server', 'x-powered-by'].filter(k => headers[k]);
    if (versionHeaders.length) findings.push({ id: 'version-disclosure', title: 'Server Technology Disclosure', severity: 'LOW', cvss: 3.1, evidence: `Response exposes: ${versionHeaders.map(k => `${k}: ${headers[k]}`).join('; ')}`, remediation: 'Minimize unnecessary technology and version disclosure in response headers.' });
    checked.push('technology disclosure');

    if (url.protocol === 'https:') {
      if (!headers['strict-transport-security']) findings.push({ id: 'missing-hsts', title: 'Missing Strict-Transport-Security', severity: 'LOW', cvss: 3.7, evidence: 'HTTPS target returned no Strict-Transport-Security header.', remediation: 'Enable HSTS after confirming the entire domain is safely served over HTTPS.' });
      checked.push('HTTPS transport policy');
    } else {
      findings.push({ id: 'plaintext-http', title: 'Target Uses Plain HTTP', severity: 'MEDIUM', cvss: 5.9, evidence: 'The assessment target was supplied over HTTP rather than HTTPS.', remediation: 'Use HTTPS for authenticated or sensitive application traffic.' });
    }

    // Passive same-origin endpoint discovery: parse links/forms/scripts only; no discovered endpoint is actively attacked.
    if (root.text) {
      const patterns = [/(?:href|src|action)\s*=\s*["']([^"'#]+)["']/gi, /fetch\s*\(\s*["']([^"']+)["']/gi];
      for (const re of patterns) {
        let m;
        while ((m = re.exec(root.text)) !== null && endpoints.size < 25) {
          try {
            const u = new URL(m[1], url.origin);
            if (u.origin === url.origin && u.pathname.startsWith('/')) endpoints.add(u.pathname);
          } catch {}
        }
      }
    }
    checked.push('passive same-origin endpoint discovery');

    // Low-impact verification of a small number of discovered GET endpoints.
    const discovered = Array.from(endpoints).slice(0, 12);
    const endpointResults = [];
    for (const path of discovered) {
      if (seen.has(path)) continue;
      seen.add(path);
      const result = await request(path);
      if (result) endpointResults.push({ path, status: result.r.status, contentType: result.headers['content-type'] || '', location: result.headers.location || null });
    }
    checked.push('low-impact discovered endpoint status checks');

    const exposedSensitive = endpointResults.filter(x => /(^|\/)(admin|debug|internal|actuator|\.env|config)(\/|$)/i.test(x.path) && x.status >= 200 && x.status < 400);
    for (const ep of exposedSensitive) findings.push({ id: `sensitive-${ep.path}`, title: 'Potentially Sensitive Endpoint Exposed', severity: 'MEDIUM', cvss: 5.3, evidence: `A same-origin path matching a sensitive naming pattern responded with HTTP ${ep.status}: ${ep.path}. This is a passive observation, not an exploitation attempt.`, remediation: 'Review whether the endpoint is intentionally public and enforce server-side authentication and authorization where required.' });

    const score = Math.max(0, Math.round(100 - findings.reduce((n, f) => n + (f.severity === 'HIGH' ? 20 : f.severity === 'MEDIUM' ? 12 : 5), 0)));
    return res.status(200).json({
      ok: true,
      target: url.origin,
      status: root.r.status,
      durationMs: Date.now() - started,
      score,
      findings,
      endpoints: endpointResults,
      checked,
      methodology: 'Authorized low-impact passive discovery and GET response analysis. No credential attacks, destructive requests, fuzzing, or access-control bypass attempts.'
    });
  } catch (e) {
    return res.status(502).json({ error: `Assessment request failed: ${e.name === 'AbortError' ? 'timeout' : 'target unavailable'}` });
  }
}
