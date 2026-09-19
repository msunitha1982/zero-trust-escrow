'use strict';

/**
 * Zero-Trust Verified File Escrow
 * ------------------------------------------------------------------
 * User A locks an .html file -> gets a share link.
 * User B opens the link, uploads a video -> nothing is released yet.
 * User A streams/downloads the video to verify it is authentic, then
 * Approves (both files unlock) or Rejects (both files are destroyed).
 *
 * Ownership is proven by a per-exchange `ownerToken` that is returned
 * exactly once, to the creator, at creation time. User B only ever
 * receives the `exchangeId`.
 */

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const MAX_HTML_MB = Number(process.env.MAX_HTML_MB || 10);
const MAX_VIDEO_MB = Number(process.env.MAX_VIDEO_MB || 2048);
const EXCHANGE_TTL_MS = Number(process.env.EXCHANGE_TTL_HOURS || 24) * 60 * 60 * 1000;
const PURGE_UPLOADS_ON_BOOT = process.env.PURGE_UPLOADS_ON_BOOT !== 'false';

const VIDEO_EXTS = new Set(['.mp4', '.mov', '.mkv', '.avi', '.webm']);
const HTML_EXTS = new Set(['.html', '.htm']);

const VIDEO_MIME = {
  '.mp4': 'video/mp4',
  '.mov': 'video/quicktime',
  '.mkv': 'video/x-matroska',
  '.avi': 'video/x-msvideo',
  '.webm': 'video/webm',
};

// Formats Chrome/Safari/Firefox will usually play inline. Anything else,
// the UI steers User A straight to "download and check it in VLC".
const BROWSER_FRIENDLY = new Set(['.mp4', '.webm', '.mov']);

// ------------------------------------------------------------------
// State. Deliberately in-memory: an escrow that survives a restart but
// loses its files (ephemeral disks) would be worse than one that does not.
// ------------------------------------------------------------------
/** @type {Map<string, object>} */
const exchanges = new Map();

const STATUS = {
  EMPTY: 'empty',
  WAITING_FOR_B: 'waiting_for_b',
  PENDING_APPROVAL: 'pending_approval',
  RELEASED: 'released',
};

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Our own files are named `<16 hex>-<role>-<8 hex>.<ext>`. On boot the
// in-memory map is empty, so any such file is unreachable garbage.
// Nothing that does not match this pattern is ever touched.
const OWNED_FILE_RE = /^[0-9a-f]{16}-(html|video)-[0-9a-f]{8}\./;
if (PURGE_UPLOADS_ON_BOOT) {
  let purged = 0;
  for (const name of fs.readdirSync(UPLOAD_DIR)) {
    if (!OWNED_FILE_RE.test(name)) continue;
    try {
      fs.unlinkSync(path.join(UPLOAD_DIR, name));
      purged++;
    } catch (_) { /* best effort */ }
  }
  if (purged) console.log(`[boot] purged ${purged} orphaned upload(s) from a previous run`);
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
const newId = (bytes = 8) => crypto.randomBytes(bytes).toString('hex');

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function unlinkQuiet(filePath) {
  if (!filePath) return;
  try {
    fs.unlinkSync(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') console.warn('[unlink] failed:', filePath, err.message);
  }
}

function destroyFiles(ex) {
  unlinkQuiet(ex.html && ex.html.storedPath);
  unlinkQuiet(ex.video && ex.video.storedPath);
  ex.html = null;
  ex.video = null;
}

/** Strip anything path-ish or control-ish out of a user supplied filename. */
function sanitizeName(name, fallback) {
  const base = path.basename(String(name || '')).replace(/[\r\n"\\]/g, '').trim();
  return base && base !== '.' && base !== '..' ? base.slice(0, 180) : fallback;
}

function asciiFallback(name) {
  return name.replace(/[^\x20-\x7e]/g, '_') || 'download';
}

function contentDisposition(type, filename) {
  return `${type}; filename="${asciiFallback(filename)}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

function touch(ex) {
  ex.updatedAt = Date.now();
  ex.rev++;
  return ex;
}

// ------------------------------------------------------------------
// Auth / lookup middleware
// ------------------------------------------------------------------
function loadExchange(req, res, next) {
  const id = req.params.id || req.query.id;
  const ex = id && exchanges.get(String(id));
  if (!ex) return res.status(404).json({ error: 'No such exchange. The link may be wrong or expired.' });
  req.exchange = ex;
  next();
}

function readOwnerToken(req) {
  return req.get('x-owner-token') || req.query.owner || (req.body && req.body.ownerToken) || '';
}

function isOwner(req, ex) {
  return safeEqual(readOwnerToken(req), ex.ownerToken);
}

/** Hard gate. Guests get a flat 403 with no hint about what exists. */
function requireOwner(req, res, next) {
  if (!isOwner(req, req.exchange)) {
    return res.status(403).json({ error: 'Forbidden. Creator credentials required.' });
  }
  next();
}

// ------------------------------------------------------------------
// Uploads
// ------------------------------------------------------------------
function makeStorage(role) {
  return multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      // Every stored file is prefixed with its exchange id so that orphans
      // are always traceable back to a session (or to none, on reboot).
      const owner = (req.exchange && req.exchange.id) || req.newExchangeId || newId(8);
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${owner}-${role}-${newId(4)}${ext}`);
    },
  });
}

const uploadHtml = multer({
  storage: makeStorage('html'),
  limits: { fileSize: MAX_HTML_MB * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!HTML_EXTS.has(ext)) return cb(new UploadError('Only .html or .htm files can be locked.'));
    cb(null, true);
  },
}).single('htmlFile');

const uploadVideo = multer({
  storage: makeStorage('video'),
  limits: { fileSize: MAX_VIDEO_MB * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!VIDEO_EXTS.has(ext)) return cb(new UploadError('Video must be .mp4, .mov, .mkv, .avi or .webm.'));
    cb(null, true);
  },
}).single('videoFile');

class UploadError extends Error {}

/** Wrap a multer middleware so its errors come back as clean JSON. */
function handleUpload(mw) {
  return (req, res, next) => {
    mw(req, res, (err) => {
      if (!err) return next();
      if (err instanceof UploadError) return res.status(400).json({ error: err.message });
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ error: 'File is too large for this server’s limit.' });
        }
        return res.status(400).json({ error: `Upload rejected: ${err.code}` });
      }
      next(err);
    });
  };
}

// ------------------------------------------------------------------
// Views
// ------------------------------------------------------------------
function fileView(f) {
  return f ? { name: f.originalName, size: f.size, ext: f.ext } : null;
}

function statusView(ex, owner) {
  const released = ex.status === STATUS.RELEASED;
  const pending = ex.status === STATUS.PENDING_APPROVAL;
  const base = {
    exchangeId: ex.id,
    status: ex.status,
    rev: ex.rev,
    role: owner ? 'creator' : 'guest',
    updatedAt: ex.updatedAt,
    expiresAt: ex.createdAt + EXCHANGE_TTL_MS,
    html: ex.html ? { name: ex.html.originalName, size: ex.html.size } : null,
    video: null,
    canDownloadHtml: released && !!ex.html,
    canDownloadVideo: false,
    canPreviewVideo: false,
    lastDecision: ex.lastDecision || null,
  };
  if (!owner) return base;

  return Object.assign(base, {
    video: fileView(ex.video),
    canPreviewVideo: (pending || released) && !!ex.video,
    canDownloadVideo: released && !!ex.video,
    inlinePlayable: !!ex.video && BROWSER_FRIENDLY.has(ex.video.ext),
  });
}

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.get('/healthz', (req, res) => res.json({ ok: true, exchanges: exchanges.size, uptime: process.uptime() }));

/** A locks an HTML file and gets back the share link + their owner token. */
app.post('/api/create', (req, res, next) => {
  req.newExchangeId = newId(8);
  next();
}, handleUpload(uploadHtml), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No HTML file received.' });

  const id = req.newExchangeId;
  const ext = path.extname(req.file.originalname).toLowerCase();
  const ex = {
    id,
    ownerToken: newId(24),
    status: STATUS.WAITING_FOR_B,
    rev: 1,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    lastDecision: null,
    html: {
      storedPath: req.file.path,
      originalName: sanitizeName(req.file.originalname, 'locked.html'),
      size: req.file.size,
      ext,
    },
    video: null,
  };
  exchanges.set(id, ex);

  console.log(`[create] ${id} locked "${ex.html.originalName}" (${ex.html.size} bytes)`);
  res.status(201).json({
    exchangeId: id,
    ownerToken: ex.ownerToken,
    sharePath: `/?id=${id}`,
    status: ex.status,
  });
});

/** Re-arm an exchange that was emptied by a rejection, keeping the same link. */
app.post('/api/relock/:id', loadExchange, requireOwner, (req, res, next) => {
  if (req.exchange.status !== STATUS.EMPTY) {
    return res.status(409).json({ error: 'This exchange is already in progress.' });
  }
  next();
}, handleUpload(uploadHtml), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No HTML file received.' });
  const ex = req.exchange;
  ex.html = {
    storedPath: req.file.path,
    originalName: sanitizeName(req.file.originalname, 'locked.html'),
    size: req.file.size,
    ext: path.extname(req.file.originalname).toLowerCase(),
  };
  ex.status = STATUS.WAITING_FOR_B;
  ex.lastDecision = null;
  touch(ex);
  res.json(statusView(ex, true));
});

/** Polled by both sides. The response is scoped to who is asking. */
app.get('/api/status/:id', loadExchange, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(statusView(req.exchange, isOwner(req, req.exchange)));
});

/** B uploads the video. Status is checked BEFORE multer writes anything. */
app.post('/api/upload-video/:id', loadExchange, (req, res, next) => {
  const ex = req.exchange;
  if (ex.status === STATUS.EMPTY) {
    return res.status(409).json({ error: 'Nothing is locked in this exchange right now.' });
  }
  if (ex.status !== STATUS.WAITING_FOR_B) {
    return res.status(409).json({ error: 'A video has already been submitted for this exchange.' });
  }
  next();
}, handleUpload(uploadVideo), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No video file received.' });
  const ex = req.exchange;

  // Race guard: two uploads that both passed the gate above.
  if (ex.status !== STATUS.WAITING_FOR_B) {
    unlinkQuiet(req.file.path);
    return res.status(409).json({ error: 'A video has already been submitted for this exchange.' });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  ex.video = {
    storedPath: req.file.path,
    originalName: sanitizeName(req.file.originalname, `video${ext}`),
    size: req.file.size,
    ext,
  };
  ex.status = STATUS.PENDING_APPROVAL;
  touch(ex);

  console.log(`[upload] ${ex.id} received "${ex.video.originalName}" (${ex.video.size} bytes) -> pending_approval`);
  res.status(201).json(statusView(ex, false));
});

/**
 * Raw, range-capable stream of the video — creator only, available the
 * moment it lands. `?download=1` forces a save so an exotic .mov/.mkv
 * that the browser will not decode can be checked in VLC before approval.
 */
function streamVideo(req, res) {
  const ex = req.exchange;
  if (!ex.video) return res.status(404).json({ error: 'No video has been submitted yet.' });

  let stat;
  try {
    stat = fs.statSync(ex.video.storedPath);
  } catch (_) {
    return res.status(410).json({ error: 'The video file is no longer on disk.' });
  }

  const wantsDownload = req.query.download === '1' || req.query.download === 'true';
  const total = stat.size;

  res.set({
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store, private',
    'Content-Type': wantsDownload
      ? 'application/octet-stream'
      : (VIDEO_MIME[ex.video.ext] || 'application/octet-stream'),
    'Content-Disposition': contentDisposition(
      wantsDownload ? 'attachment' : 'inline',
      ex.video.originalName,
    ),
  });

  const range = req.headers.range;
  if (!range) {
    res.set('Content-Length', String(total));
    if (req.method === 'HEAD') return res.end();
    return fs.createReadStream(ex.video.storedPath).pipe(res);
  }

  const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
  if (!m || (m[1] === '' && m[2] === '')) {
    return res.status(416).set('Content-Range', `bytes */${total}`).end();
  }

  let start;
  let end;
  if (m[1] === '') {
    // Suffix range: last N bytes.
    const suffix = Number(m[2]);
    start = Math.max(0, total - suffix);
    end = total - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === '' ? total - 1 : Math.min(Number(m[2]), total - 1);
  }

  if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= total) {
    return res.status(416).set('Content-Range', `bytes */${total}`).end();
  }

  res.status(206).set({
    'Content-Range': `bytes ${start}-${end}/${total}`,
    'Content-Length': String(end - start + 1),
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(ex.video.storedPath, { start, end }).pipe(res);
}

app.get('/api/preview-video/:id', loadExchange, requireOwner, streamVideo);
app.get('/api/preview-video', loadExchange, requireOwner, streamVideo);

/** Approve: the only transition that unlocks anything. */
app.post('/api/approve/:id', loadExchange, requireOwner, (req, res) => {
  const ex = req.exchange;
  if (ex.status === STATUS.RELEASED) return res.json(statusView(ex, true));
  if (ex.status !== STATUS.PENDING_APPROVAL) {
    return res.status(409).json({ error: 'There is no video awaiting your approval.' });
  }
  ex.status = STATUS.RELEASED;
  ex.lastDecision = { action: 'approved', at: Date.now() };
  touch(ex);
  console.log(`[approve] ${ex.id} released`);
  res.json(statusView(ex, true));
});

/** Reject: both files are unlinked immediately and the slot is emptied. */
app.post('/api/reject/:id', loadExchange, requireOwner, (req, res) => {
  const ex = req.exchange;
  if (ex.status !== STATUS.PENDING_APPROVAL) {
    return res.status(409).json({ error: 'There is no video awaiting your approval.' });
  }
  destroyFiles(ex);
  ex.status = STATUS.EMPTY;
  ex.lastDecision = { action: 'rejected', at: Date.now() };
  touch(ex);
  console.log(`[reject] ${ex.id} destroyed both files`);
  res.json(statusView(ex, true));
});

/** B's payload. Refuses to exist until the creator has said yes. */
app.get('/api/download-html/:id', loadExchange, (req, res) => {
  const ex = req.exchange;
  if (ex.status !== STATUS.RELEASED || !ex.html) {
    return res.status(403).json({ error: 'Locked. This file is released only after the creator approves the video.' });
  }
  if (!fs.existsSync(ex.html.storedPath)) {
    return res.status(410).json({ error: 'The file is no longer on disk.' });
  }
  res.set({
    // Never text/html: the payload must not be able to execute on this origin.
    'Content-Type': 'application/octet-stream',
    'Content-Security-Policy': 'sandbox',
    'Cache-Control': 'no-store',
    'Content-Disposition': contentDisposition('attachment', ex.html.originalName),
  });
  fs.createReadStream(ex.html.storedPath).pipe(res);
});

/** A's copy of the video, post-release. */
app.get('/api/download-video/:id', loadExchange, requireOwner, (req, res) => {
  const ex = req.exchange;
  if (ex.status !== STATUS.RELEASED || !ex.video) {
    return res.status(403).json({ error: 'Locked until you approve the exchange.' });
  }
  req.query.download = '1';
  streamVideo(req, res);
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown endpoint.' }));

// SPA fallback so `/?id=...` and bare `/` both serve the single page.
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  if (res.headersSent) return res.destroy();
  res.status(500).json({ error: 'Internal server error.' });
});

// ------------------------------------------------------------------
// Expiry sweep
// ------------------------------------------------------------------
setInterval(() => {
  const cutoff = Date.now() - EXCHANGE_TTL_MS;
  for (const [id, ex] of exchanges) {
    if (ex.createdAt > cutoff) continue;
    destroyFiles(ex);
    exchanges.delete(id);
    console.log(`[expire] ${id} removed after TTL`);
  }
}, 15 * 60 * 1000).unref();

app.listen(PORT, () => {
  console.log(`Zero-Trust Escrow listening on http://localhost:${PORT}`);
  console.log(`  uploads: ${UPLOAD_DIR}`);
  console.log(`  limits : html ${MAX_HTML_MB}MB, video ${MAX_VIDEO_MB}MB, ttl ${EXCHANGE_TTL_MS / 3600000}h`);
});

module.exports = app;
