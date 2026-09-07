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
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(url, { method: 'GET', redirect: 'manual', signal: controller.signal, headers: { 'User-Agent': 'WorldGuard-AI-Authorized-Assessment/1.0' } });
    clearTimeout(timeout);

    const headers = Object.fromEntries(response.headers.entries());
    const findings = [];
    const securityHeaders = [
      ['content-security-policy', 'Missing Content-Security-Policy'],
      ['x-content-type-options', 'Missing X-Content-Type-Options'],
      ['referrer-policy', 'Missing Referrer-Policy'],
      ['permissions-policy', 'Missing Permissions-Policy']
    ];
    for (const [key, title] of securityHeaders) {
      if (!headers[key]) findings.push({ id: key, title, severity: key === 'content-security-policy' ? 'MEDIUM' : 'LOW', evidence: `GET ${url.pathname || '/'} returned no ${key} header.` });
    }

    const setCookie = headers['set-cookie'] || '';
    if (setCookie && (!/;\s*secure\b/i.test(setCookie) || !/;\s*httponly\b/i.test(setCookie))) {
      findings.push({ id: 'cookie-flags', title: 'Session Cookie Security Flags', severity: 'MEDIUM', evidence: 'A Set-Cookie response was observed without all expected Secure/HttpOnly protections.' });
    }

    if (headers['access-control-allow-origin'] === '*') {
      findings.push({ id: 'cors-wildcard', title: 'Wildcard CORS Policy', severity: 'MEDIUM', evidence: 'The response advertises Access-Control-Allow-Origin: *.' });
    }

    const versionHeaders = ['server', 'x-powered-by'].filter(k => headers[k]);
    if (versionHeaders.length) findings.push({ id: 'version-disclosure', title: 'Server Technology Disclosure', severity: 'LOW', evidence: `Response exposes: ${versionHeaders.map(k => `${k}: ${headers[k]}`).join('; ')}` });

    const score = Math.max(0, 100 - findings.reduce((n, f) => n + (f.severity === 'MEDIUM' ? 12 : 5), 0));
    return res.status(200).json({ ok: true, target: url.origin, status: response.status, durationMs: Date.now() - started, score, findings, checked: ['HTTP availability', 'security headers', 'cookie flags when present', 'CORS response policy', 'technology disclosure'] });
  } catch (e) {
    return res.status(502).json({ error: `Assessment request failed: ${e.name === 'AbortError' ? 'timeout' : 'target unavailable'}` });
  }
}
