// server.js (updated - supports GET /api/check and POST /check)
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(express.json()); // for parsing application/json
app.use(cors({ origin: '*' })); // okay for local dev; tighten in prod

const PORT = process.env.PORT || 3000;
const VT_API_KEY = process.env.VT_API_KEY || '';
const GSB_API_KEY = process.env.GSB_API_KEY || '';
const EXT_TOKEN = process.env.EXT_TOKEN || 'super-secret-local-token';
const CACHE_TTL = parseInt(process.env.CACHE_TTL || '300', 10);

const cache = new NodeCache({ stdTTL: CACHE_TTL, checkperiod: Math.max(60, Math.floor(CACHE_TTL/2)) });

// Simple auth middleware (expects: Authorization: Bearer <EXT_TOKEN>)
function requireExtAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  if (!token || token !== EXT_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Rate limiter
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
}));

// Root - friendly page
app.get('/', (req, res) => {
  res.send(`<h1>PhishGuard Proxy</h1>
    <p>Endpoints:</p>
    <ul>
      <li><code>GET /health</code></li>
      <li><code>GET /api/check?url=...</code> (Authorization: Bearer &lt;token&gt;)</li>
      <li><code>POST /check</code> JSON: {"url":"..."} (Authorization: Bearer &lt;token&gt;)</li>
    </ul>`);
});

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Helper to normalize and safe-validate URL strings
function normalizeUrl(raw) {
  if (!raw) throw new Error('Missing url');
  try {
    const u = new URL(raw);
    u.hash = '';
    return u.toString();
  } catch (e) {
    // try to add http if missing
    try {
      const u2 = new URL('http://' + raw);
      u2.hash = '';
      return u2.toString();
    } catch (err) {
      throw new Error('Invalid URL');
    }
  }
}

// Core check logic (simplified: queries providers if keys present, caches result)
async function performCheck(url) {
  // If cached, return cached value
  const cached = cache.get(url);
  if (cached) return { url, cached: true, result: cached };

  // Minimal example: do not call external providers if keys absent
  const results = { vt: null, gsb: null, verdict: 'unknown' };

  // Example: if no API keys provided, mark as 'unknown' or 'clean' per your choice.
  if (!VT_API_KEY && !GSB_API_KEY) {
    results.verdict = 'clean';
    cache.set(url, results);
    return { url, cached: false, result: results };
  }

  // --- VirusTotal (simplified pattern, may need adapting for your plan)
  if (VT_API_KEY) {
    try {
      const postResp = await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        `url=${encodeURIComponent(url)}`,
        { headers: { 'x-apikey': VT_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
      );
      const id = postResp?.data?.data?.id;
      if (id) {
        const analysisResp = await axios.get(`https://www.virustotal.com/api/v3/urls/${id}`, {
          headers: { 'x-apikey': VT_API_KEY }, timeout: 10000
        });
        results.vt = analysisResp.data;
        const stats = analysisResp.data?.data?.attributes?.last_analysis_stats || {};
        if ((stats.malicious || 0) > 0) results.verdict = 'malicious';
        else if ((stats.suspicious || 0) > 0) results.verdict = 'suspicious';
      }
    } catch (err) {
      results.vt = { error: 'vt_error' };
      console.warn('VirusTotal error:', err?.response?.status || err.message);
    }
  } else {
    results.vt = { skipped: true };
  }

  // --- Google Safe Browsing
  if (GSB_API_KEY) {
    try {
      const gsbBody = {
        client: { clientId: "phishguard-proxy", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      };
      const gsbResp = await axios.post(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(GSB_API_KEY)}`,
        gsbBody, { timeout: 10000 }
      );
      results.gsb = gsbResp.data;
      if (gsbResp.data && Object.keys(gsbResp.data).length > 0) results.verdict = 'malicious';
    } catch (err) {
      results.gsb = { error: 'gsb_error' };
      console.warn('GSB error:', err?.response?.status || err.message);
    }
  } else {
    results.gsb = { skipped: true };
  }

  // Final fallback: if still 'unknown', set to 'clean'
  if (results.verdict === 'unknown') results.verdict = 'clean';

  cache.set(url, results);
  return { url, cached: false, result: results };
}

// GET route (existing)
app.get('/api/check', requireExtAuth, async (req, res) => {
  const raw = req.query.url;
  try {
    const url = normalizeUrl(raw);
    const out = await performCheck(url);
    return res.json(out);
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Invalid url' });
  }
});

// NEW: accept POST /check with JSON body { "url": "..." }
app.post('/check', requireExtAuth, async (req, res) => {
  const raw = req.body?.url;
  try {
    const url = normalizeUrl(raw);
    const out = await performCheck(url);
    return res.json(out);
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Invalid url' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`PhishGuard proxy listening on port ${PORT}`);
});
