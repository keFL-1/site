const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const FormData = require('form-data');

const VT_API_KEY =
  process.env.VT_API_KEY ||
  'fa4c4c7029197eee1f40c6fd4a806bb85d80edf9d4d9d473321a77583e856c65';

// VirusTotal public API обычно ограничивает загрузку файла до ~32MB.
const VT_PUBLIC_MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

const app = express();

// Раздаём статический фронт
app.use(express.static('site'));

app.use(express.json({ limit: '1mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 650 * 1024 * 1024,
  },
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeUrlToUiResponse({
  url,
  urlId,
  vtUrlReport,
  vtAnalysis,
}) {
  const urlAttrs = vtUrlReport?.data?.attributes;
  const stats = urlAttrs?.last_analysis_stats || {};
  const results = urlAttrs?.last_analysis_results || {};

  const threats = [];
  for (const [engine, r] of Object.entries(results)) {
    if (!r) continue;
    if (r.category === 'malicious' || r.category === 'suspicious') {
      threats.push({
        engine,
        name: r.result || r.category,
        category: r.category,
        method: r.method,
      });
    }
  }

  const detections = (stats.malicious || 0) + (stats.suspicious || 0);
  const engines =
    (stats.malicious || 0) +
    (stats.suspicious || 0) +
    (stats.undetected || 0) +
    (stats.harmless || 0) +
    (stats.timeout || 0) +
    (stats.type_unsupported || 0);

  const status = detections === 0 ? 'safe' : detections <= 2 ? 'warning' : 'critical';

  return {
    status,
    threats,
    detections,
    engines,
    url,
    urlId,
    stats,
    vt: {
      analysisId: vtAnalysis?.data?.id || null,
      link: vtUrlReport?.data?.links?.self || null,
    },
  };
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function vtFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'x-apikey': VT_API_KEY,
      ...(options.headers || {}),
    },
  });

  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  if (!res.ok) {
    const msg =
      (json && (json.error?.message || json.error)) ||
      `${res.status} ${res.statusText}`;
    const err = new Error(`VirusTotal error: ${msg}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }

  return json;
}

async function vtGetFileReportByHash(fileSha256) {
  // https://docs.virustotal.com/reference/file-info
  return vtFetch(`https://www.virustotal.com/api/v3/files/${fileSha256}`);
}

function vtUrlId(url) {
  return Buffer.from(url)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function vtScanUrl(url) {
  const body = new URLSearchParams({ url });
  return vtFetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  });
}

async function vtGetUrlReport(urlId) {
  return vtFetch(`https://www.virustotal.com/api/v3/urls/${urlId}`);
}

async function vtUploadFile(buffer, filename) {
  const form = new FormData();
  form.append('file', buffer, { filename });

  // https://docs.virustotal.com/reference/file-scan
  return vtFetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    body: form,
    headers: form.getHeaders(),
  });
}

async function vtPollAnalysis(analysisId, {
  maxAttempts = 20,
  delayMs = 3000,
} = {}) {
  // https://docs.virustotal.com/reference/analyses
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const analysis = await vtFetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`
    );

    const status = analysis?.data?.attributes?.status;
    if (status === 'completed') return analysis;

    await sleep(delayMs);
  }

  const err = new Error('VirusTotal analysis timeout');
  err.code = 'VT_TIMEOUT';
  throw err;
}

app.post('/api/scan-url', async (req, res) => {
  try {
    if (!VT_API_KEY) {
      return res.status(500).json({
        error: 'VT_API_KEY is missing on server',
      });
    }

    const url = (req.body?.url || '').toString().trim();
    if (!url) {
      return res.status(400).json({ error: 'No url provided' });
    }

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Only http/https URLs are supported' });
    }

    const urlId = vtUrlId(url);

    const scanResp = await vtScanUrl(url);
    const analysisId = scanResp?.data?.id;

    if (!analysisId) {
      return res.status(502).json({
        error: 'VirusTotal did not return analysis id for URL',
        details: scanResp,
      });
    }

    await vtPollAnalysis(analysisId, { maxAttempts: 20, delayMs: 3000 });

    const vtUrlReport = await vtGetUrlReport(urlId);

    return res.json(
      normalizeUrlToUiResponse({
        url,
        urlId,
        vtUrlReport,
        vtAnalysis: { data: { id: analysisId } },
      })
    );
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: err.message || 'Unknown error',
      code: err.code,
      status: err.status,
    });
  }
});

function normalizeToUiResponse({
  fileSha256,
  vtFileReport,
  vtAnalysis,
}) {
  // VT file report содержит last_analysis_stats + last_analysis_results.
  // Возвращаем то, что нужно фронту.
  const fileAttrs = vtFileReport?.data?.attributes;

  const stats = fileAttrs?.last_analysis_stats || {};
  const results = fileAttrs?.last_analysis_results || {};

  const threats = [];
  for (const [engine, r] of Object.entries(results)) {
    if (!r) continue;
    if (r.category === 'malicious' || r.category === 'suspicious') {
      threats.push({
        engine,
        name: r.result || r.category,
        category: r.category,
        method: r.method,
      });
    }
  }

  const detections = (stats.malicious || 0) + (stats.suspicious || 0);
  const engines =
    (stats.malicious || 0) +
    (stats.suspicious || 0) +
    (stats.undetected || 0) +
    (stats.harmless || 0) +
    (stats.timeout || 0) +
    (stats.type_unsupported || 0);

  const status = detections === 0 ? 'safe' : detections <= 2 ? 'warning' : 'critical';

  return {
    status,
    threats,
    detections,
    engines,
    sha256: fileSha256,
    stats,
    vt: {
      analysisId: vtAnalysis?.data?.id || null,
      fileId: vtFileReport?.data?.id || null,
      link: vtFileReport?.data?.links?.self || null,
    },
  };
}

app.post('/api/scan', upload.single('file'), async (req, res) => {
  try {
    if (!VT_API_KEY) {
      return res.status(500).json({
        error: 'VT_API_KEY is missing on server',
      });
    }

    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    const fileSha256 = sha256(file.buffer);

    // 1) Сначала пытаемся получить отчёт по хэшу (быстро, без загрузки)
    let vtFileReport = null;
    try {
      vtFileReport = await vtGetFileReportByHash(fileSha256);
      // Если есть отчёт — сразу возвращаем
      return res.json(
        normalizeToUiResponse({ fileSha256, vtFileReport, vtAnalysis: null })
      );
    } catch (e) {
      // 404 значит файла нет у VT — это нормально
      if (e.status !== 404) {
        throw e;
      }
    }

    // 2) Если файла нет в VT — загружаем, но только если размер подходит
    if (file.size > VT_PUBLIC_MAX_UPLOAD_BYTES) {
      return res.status(413).json({
        error:
          'File is too large to upload to VirusTotal public API. Only hash lookup is possible, but VT has no report for this file.',
        sha256: fileSha256,
        maxUploadBytes: VT_PUBLIC_MAX_UPLOAD_BYTES,
      });
    }

    const uploadResp = await vtUploadFile(file.buffer, file.originalname);
    const analysisId = uploadResp?.data?.id;
    if (!analysisId) {
      return res.status(502).json({
        error: 'VirusTotal did not return analysis id',
        details: uploadResp,
      });
    }

    // 3) Опрос анализа с ограничением времени
    await vtPollAnalysis(analysisId, { maxAttempts: 20, delayMs: 3000 });

    // 4) После завершения анализа — получаем file report по sha256
    vtFileReport = await vtGetFileReportByHash(fileSha256);

    return res.json(
      normalizeToUiResponse({
        fileSha256,
        vtFileReport,
        vtAnalysis: { data: { id: analysisId } },
      })
    );
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: err.message || 'Unknown error',
      code: err.code,
      status: err.status,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
  console.log('Static site: /security-monitor.html');
});
