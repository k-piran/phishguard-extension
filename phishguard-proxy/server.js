require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');


const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({ origin: '*' }));


const PORT = process.env.PORT || 3000;
const VT_API_KEY = process.env.VT_API_KEY;
const GSB_API_KEY = process.env.GSB_API_KEY;
const EXT_TOKEN = process.env.EXT_TOKEN;
const CACHE_TTL = parseInt(process.env.CACHE_TTL || '300', 10);
const cache = new NodeCache({ stdTTL: CACHE_TTL });


function requireExtAuth(req, res, next) {
const auth = req.headers.authorization || '';
if (!auth.startsWith('Bearer ') || auth.split(' ')[1] !== EXT_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
next();
}


app.use(rateLimit({ windowMs: 60000, max: 60 }));


function normalizeUrl(raw) { try { return new URL(raw).toString(); } catch { return 'http://' + raw; } }


app.get('/api/check', requireExtAuth, async (req, res) => {
const url = normalizeUrl(req.query.url);
const cached = cache.get(url);
if (cached) return res.json({ url, cached: true, result: cached });


const results = { vt: null, gsb: null, verdict: 'unknown' };
// VirusTotal & GSB API calls (simplified, see previous code for details)
results.verdict = 'clean'; // Placeholder for demo
cache.set(url, results);
res.json({ url, cached: false, result: results });
});


app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));