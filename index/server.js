const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const PORT = process.env.PORT || 3000;

function hashPassword(password, salt) {
    const s = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, s, 100000, 64, 'sha512').toString('hex');
    return { hash, salt: s };
}

function createUser(email, name, password) {
    if (db.userExists(email)) return null;
    const { hash, salt } = hashPassword(password);
    const verifyToken = crypto.randomBytes(32).toString('hex');
    const verified = !SMTP_ENABLED;
    const isFirst = db.listAllUsers().length === 0;
    db.createUser(email, name, hash, salt, verified, verifyToken);
    if (isFirst) db.setAdmin(email, 1);
    return { email, name, verified };
}

function verifyUser(email, password) {
    const user = db.findUser(email);
    if (!user) return null;
    const { hash } = hashPassword(password, user.salt);
    if (hash !== user.password_hash) return null;
    if (SMTP_ENABLED && !user.verified) return { error: 'Please verify your email first' };
    return { email: user.email, name: user.name };
}

function sanitizeEmail(email) {
    return email.replace(/[@.]/g, '_');
}

function getUserRoot(user) {
    const dir = path.join(__dirname, 'storage', sanitizeEmail(user.email));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function getUserTrash(user) {
    const dir = path.join(getUserRoot(user), '.trash');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

// === SESSIONS ===
function createSession(user) {
    const token = crypto.randomBytes(32).toString('hex');
    db.createSession(token, user.email);
    return token;
}

function destroySession(token) {
    db.destroySession(token);
}

function getSession(token) {
    return db.getSession(token);
}

// === COOKIE HELPERS ===
function parseCookies(req) {
    const cookie = req.headers.cookie || '';
    const result = {};
    cookie.split(';').forEach(c => {
        const parts = c.split('=');
        if (parts.length >= 2) result[parts[0].trim()] = parts.slice(1).join('=').trim();
    });
    return result;
}

function setCookie(res, name, value, opts = {}) {
    let cookie = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax`;
    if (opts.maxAge) cookie += `; Max-Age=${opts.maxAge}`;
    res.setHeader('Set-Cookie', cookie);
}

function clearCookie(res, name) {
    setCookie(res, name, '', { maxAge: 0 });
}

// === AUTH MIDDLEWARE ===
function getUser(req) {
    const cookies = parseCookies(req);
    const token = cookies.session;
    if (!token) return null;
    return getSession(token);
}

function requireAuth(req, res) {
    const user = getUser(req);
    if (!user) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Authentication required' }));
        return null;
    }
    return user;
}

// === EMAIL CONFIG ===
const EMAIL_CONFIG_FILE = path.join(__dirname, 'email_config.json');
let emailConfig = {};
if (fs.existsSync(EMAIL_CONFIG_FILE)) {
    try { emailConfig = JSON.parse(fs.readFileSync(EMAIL_CONFIG_FILE, 'utf8')); } catch (e) { emailConfig = {}; }
}

const SMTP_ENABLED = !!(emailConfig.host && emailConfig.port && emailConfig.from);

function sendEmail(to, subject, html) {
    return new Promise((resolve, reject) => {
        const cfg = emailConfig;
        if (!SMTP_ENABLED) { reject(new Error('SMTP not configured')); return; }
        const net = require('net');
        const tls = require('tls');
        let socket, buf = '', step = 0, errTimer, ehloResp = '', fallbackTimer = setTimeout(() => { try { if (socket) socket.destroy(); } catch (e) {} reject(new Error('SMTP global timeout')); }, 60000);

        function cancelTimeout() { clearTimeout(errTimer); clearTimeout(fallbackTimer); }
        function resetTimeout(ms) {
            cancelTimeout();
            errTimer = setTimeout(() => { try { socket.destroy(); } catch (e) {} reject(new Error('SMTP timeout')); }, ms);
        }

        function send(line) { socket.write(line + '\r\n'); }

        function onData(data) {
            buf += data.toString();
            while (true) {
                const idx = buf.indexOf('\r\n'); const idx2 = buf.indexOf('\n');
                if (idx === -1 && idx2 === -1) break;
                const i = idx !== -1 ? idx : idx2;
                const line = buf.slice(0, i).trim();
                buf = buf.slice(i + (idx !== -1 ? 2 : 1));
                if (!line) continue;
                const code = parseInt(line);
                if (code >= 200 && (line.length < 4 || line[3] !== '-')) {
                    try { handleReply(code, line); } catch (e) { cancelTimeout(); try { socket.destroy(); } catch(ee) {} reject(e); }
                }
            }
        }

        function onError(err) { cancelTimeout(); reject(err); }

        function connectSecure(callback) {
            const raw = net.createConnection(cfg.port, cfg.host);
            resetTimeout(15000);
            raw.once('data', d => {
                if (!d.toString().startsWith('220')) { cancelTimeout(); raw.destroy(); reject(new Error('Connect failed')); return; }
                resetTimeout(15000);
                raw.write('EHLO [127.0.0.1]\r\n');
                raw.once('data', d2 => {
                    const resp = d2.toString();
                    if (resp.includes('STARTTLS')) {
                        resetTimeout(15000);
                        raw.write('STARTTLS\r\n');
                        raw.once('data', d3 => {
                            if (!d3.toString().startsWith('220')) { cancelTimeout(); raw.destroy(); reject(new Error('STARTTLS failed')); return; }
                            resetTimeout(15000);
                            socket = tls.connect({ socket: raw, rejectUnauthorized: false }, () => {
                                socket.on('data', onData); socket.on('error', onError);
                                resetTimeout(15000); callback();
                            });
                        });
                    } else {
                        raw.removeAllListeners('data');
                        socket = raw; socket.on('data', onData); socket.on('error', onError);
                        resetTimeout(15000); callback();
                    }
                });
            });
            raw.on('error', onError);
        }

        function handleReply(code, line) {
            resetTimeout(15000);
            switch (step) {
                case 0:
                    if (code !== 220) throw new Error('SMTP refused: ' + line);
                    send('EHLO [127.0.0.1]'); step = 11; break;
                case 11:
                    if (code !== 250) throw new Error('EHLO failed: ' + line);
                    send('EHLO [127.0.0.1]'); step = 12; break;
                case 12:
                    if (code !== 250) throw new Error('EHLO failed: ' + line);
                    if (cfg.user && cfg.pass) { send('AUTH LOGIN'); step = 2; }
                    else { send('MAIL FROM:<' + cfg.from + '>'); step = 5; }
                    break;
                case 2:
                    if (code !== 334) throw new Error('AUTH failed');
                    send(Buffer.from(cfg.user).toString('base64')); step = 3; break;
                case 3:
                    if (code !== 334) throw new Error('AUTH username rejected');
                    send(Buffer.from(cfg.pass).toString('base64')); step = 4; break;
                case 4:
                    if (code !== 235) throw new Error('AUTH failed');
                    send('MAIL FROM:<' + cfg.from + '>'); step = 5; break;
                case 5:
                    if (code !== 250) throw new Error('MAIL FROM rejected: ' + line);
                    send('RCPT TO:<' + to + '>'); step = 6; break;
                case 6:
                    if (code !== 250) throw new Error('RCPT TO rejected: ' + line);
                    send('DATA'); step = 7; break;
                case 7:
                    if (code !== 354) throw new Error('DATA rejected');
                    send('From: ' + cfg.from + '\r\nTo: ' + to + '\r\nSubject: ' + subject + '\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset="UTF-8"\r\n\r\n' + html + '\r\n.');
                    step = 8; break;
                case 8:
                    if (code !== 250) throw new Error('Send rejected: ' + line);
                    send('QUIT'); step = 9; break;
                case 9:
                    cancelTimeout(); try { socket.end(); } catch (e) {} resolve(); break;
            }
        }

        // Always connect via STARTTLS (works for 587, 25 with STARTTLS, and 465 via direct TLS handled separately)
        const directTLS = cfg.secure || cfg.port === 465;
        if (directTLS) {
            resetTimeout(15000);
            socket = tls.connect(cfg.port, cfg.host, { rejectUnauthorized: false }, () => {
                socket.on('data', onData); socket.on('error', onError);
                resetTimeout(15000); step = 0; handleReply(220, '220 Ready');
            });
        } else {
            connectSecure(() => { step = 0; handleReply(220, '220 Ready'); });
        }
    });
}

// === SHARES ===
// (all share operations use db module)

// === MIME ===
const MIME = {
    '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
    '.json': 'application/json', '.pdf': 'application/pdf',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp',
    '.ico': 'image/x-icon', '.bmp': 'image/bmp', '.tiff': 'image/tiff', '.tif': 'image/tiff',
    '.avif': 'image/avif', '.heic': 'image/heic', '.heif': 'image/heif',
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.avi': 'video/x-msvideo',
    '.mkv': 'video/x-matroska', '.mov': 'video/quicktime', '.wmv': 'video/x-ms-wmv',
    '.flv': 'video/x-flv', '.m4v': 'video/x-m4v', '.ts': 'video/mp2t',
    '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg',
    '.flac': 'audio/flac', '.aac': 'audio/aac', '.wma': 'audio/x-ms-wma',
    '.m4a': 'audio/mp4', '.opus': 'audio/opus',
    '.txt': 'text/plain', '.md': 'text/markdown',
    '.csv': 'text/csv', '.xml': 'text/xml', '.yaml': 'text/yaml', '.yml': 'text/yaml',
    '.log': 'text/plain', '.ini': 'text/plain', '.cfg': 'text/plain',
    '.zip': 'application/zip', '.gz': 'application/gzip', '.tar': 'application/x-tar',
    '.rar': 'application/vnd.rar', '.7z': 'application/x-7z-compressed',
    '.bz2': 'application/x-bzip2', '.xz': 'application/x-xz',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.odt': 'application/vnd.oasis.opendocument.text',
    '.ods': 'application/vnd.oasis.opendocument.spreadsheet',
    '.odp': 'application/vnd.oasis.opendocument.presentation',
    '.rtf': 'application/rtf', '.epub': 'application/epub+zip',
    '.psd': 'image/vnd.adobe.photoshop', '.ai': 'application/postscript',
    '.dwg': 'image/vnd.dwg', '.dxf': 'image/vnd.dxf',
    '.ttf': 'font/ttf', '.otf': 'font/otf', '.woff': 'font/woff', '.woff2': 'font/woff2',
    '.exe': 'application/octet-stream', '.dll': 'application/octet-stream',
    '.msi': 'application/octet-stream', '.apk': 'application/vnd.android.package-archive',
    '.dmg': 'application/x-apple-diskimage', '.iso': 'application/x-iso9660-image',
};

function safeResolve(base, target) {
    const full = path.resolve(base, target);
    if (!full.startsWith(base)) return null;
    return full;
}

function formatSize(bytes) {
    if (bytes == null) return '--';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function getFileType(ext) {
    if (['.jpg','.jpeg','.png','.gif','.svg','.webp','.ico','.bmp','.tiff','.tif','.avif','.heic','.heif','.psd','.ai','.dwg','.dxf'].includes(ext)) return 'image';
    if (['.mp4','.webm','.avi','.mkv','.mov','.wmv','.flv','.m4v','.ts'].includes(ext)) return 'video';
    if (['.mp3','.wav','.ogg','.flac','.aac','.wma','.m4a','.opus'].includes(ext)) return 'audio';
    if (['.zip','.tar','.gz','.rar','.7z','.bz2','.xz'].includes(ext)) return 'archive';
    if (['.js','.ts','.py','.java','.c','.cpp','.cs','.go','.rs','.rb','.php','.swift','.kt','.kts','.dart','.lua','.scala','.hs','.pl','.r','.m','.h','.hpp','.sql','.sh','.bat','.ps1'].includes(ext)) return 'code';
    if (['.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.ods','.odp','.rtf','.epub','.txt','.md','.csv','.xml','.json','.yaml','.yml'].includes(ext)) return 'document';
    return 'file';
}

function isPreviewable(mime) {
    if (!mime) return false;
    if (mime.startsWith('text/') || mime.startsWith('image/') || mime === 'application/pdf' || mime.startsWith('video/') || mime.startsWith('audio/') || ['application/javascript','application/json','text/csv','text/xml'].includes(mime)) return true;
    return false;
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

// === STREAMING MULTIPART UPLOAD ===
function handleUpload(req, res, uploadDir, user) {
    const ct = req.headers['content-type'] || '';
    const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!boundaryMatch) return respond(res, 400, { error: 'Invalid content-type' });
    const boundary = boundaryMatch[1] || boundaryMatch[2];
    const delim = Buffer.from(`--${boundary}`);
    const endDelim = Buffer.from(`--${boundary}--`);

    const results = [];
    let state = 'boundary';
    let buf = Buffer.alloc(0);
    let currentFile = null;
    let currentHeaders = '';

    function finalizeFile() {
        if (currentFile) {
            if (currentFile.ws) { currentFile.ws.end(); currentFile.ws = null; }
            const rel = uploadDir ? uploadDir + '/' + path.basename(currentFile.finalPath) : path.basename(currentFile.finalPath);
            results.push({ name: path.basename(currentFile.finalPath), path: rel, size: 0 });
            currentFile = null;
        }
    }

    function processBuffer() {
        while (buf.length > 0 && state !== 'done') {
            if (state === 'boundary') {
                const idx = buf.indexOf(delim);
                if (idx === -1) return;
                if (idx + endDelim.length <= buf.length && buf.slice(idx, idx + endDelim.length).equals(endDelim)) {
                    finalizeFile(); state = 'done';
                    buf = buf.slice(idx + endDelim.length);
                    return;
                }
                let afterDelim = idx + delim.length;
                if (buf[afterDelim] === 13 && buf[afterDelim+1] === 10) afterDelim += 2;
                else if (buf[afterDelim] === 10) afterDelim += 1;
                buf = buf.slice(afterDelim);
                state = 'headers';
                currentHeaders = '';
                continue;
            }
            if (state === 'headers') {
                const hdrEnd = buf.indexOf('\r\n\r\n');
                if (hdrEnd === -1) { currentHeaders += buf.toString('utf8'); return; }
                currentHeaders += buf.slice(0, hdrEnd).toString('utf8');
                buf = buf.slice(hdrEnd + 4);
                const fnameMatch = currentHeaders.match(/filename="([^"]*)"/i);
                if (fnameMatch && fnameMatch[1]) {
                    let fname = fnameMatch[1];
                    const relDir = path.dirname(fname);
                    const baseName = path.basename(fname);
                    const targetDir = safeResolve(getUserRoot(user), uploadDir || '');
                    if (!targetDir) { state = 'done'; return; }
                    const finalDir = relDir !== '.' ? path.join(targetDir, relDir) : targetDir;
                    if (!fs.existsSync(finalDir)) fs.mkdirSync(finalDir, { recursive: true });
                    let fp = path.join(finalDir, baseName);
                    let counter = 1;
                    while (fs.existsSync(fp)) {
                        const ext = path.extname(fname);
                        const base = path.basename(fname, ext);
                        fp = path.join(targetDir, `${base} (${counter})${ext}`);
                        counter++;
                    }
                    currentFile = { ws: fs.createWriteStream(fp), filename: fname, finalPath: fp };
                    state = 'file';
                    continue;
                } else {
                    state = 'boundary';
                    continue;
                }
            }
            if (state === 'file') {
                const idx = buf.indexOf(delim);
                if (idx === -2 || (idx >= 0 && idx + endDelim.length <= buf.length && buf.slice(idx, idx + endDelim.length).equals(endDelim))) {
                    const dataEnd = buf.indexOf(endDelim);
                    let writeData = buf.slice(0, dataEnd);
                    if (writeData.length >= 2 && writeData[writeData.length-2] === 13 && writeData[writeData.length-1] === 10) writeData = writeData.slice(0, -2);
                    else if (writeData.length >= 1 && writeData[writeData.length-1] === 10) writeData = writeData.slice(0, -1);
                    if (writeData.length > 0 && currentFile.ws) currentFile.ws.write(writeData);
                    finalizeFile(); state = 'done';
                    buf = buf.slice(dataEnd + endDelim.length);
                    return;
                }
                if (idx >= 0) {
                    let writeData = buf.slice(0, idx);
                    if (writeData.length >= 2 && writeData[writeData.length-2] === 13 && writeData[writeData.length-1] === 10) writeData = writeData.slice(0, -2);
                    else if (writeData.length >= 1 && writeData[writeData.length-1] === 10) writeData = writeData.slice(0, -1);
                    if (writeData.length > 0 && currentFile.ws) currentFile.ws.write(writeData);
                    finalizeFile();
                    buf = buf.slice(idx);
                    state = 'boundary';
                    continue;
                }
                const safeLen = buf.length - delim.length + 1;
                if (safeLen > 0 && currentFile.ws) { currentFile.ws.write(buf.slice(0, safeLen)); buf = buf.slice(safeLen); }
                return;
            }
        }
    }

    req.on('data', chunk => { buf = Buffer.concat([buf, chunk]); processBuffer(); });
    req.on('end', () => {
        if (state === 'file' && currentFile && currentFile.ws && buf.length > 0) currentFile.ws.write(buf);
        finalizeFile();
        respond(res, 200, { uploaded: results.length, files: results });
    });
    req.on('close', () => finalizeFile());
}

function walkDir(dirPath, basePath, maxDepth = 5, depth = 0) {
    if (depth > maxDepth) return [];
    const results = [];
    try {
        for (const item of fs.readdirSync(dirPath, { withFileTypes: true })) {
            const full = path.join(dirPath, item.name);
            const rel = path.relative(basePath, full).split(path.sep).join('/');
            if (item.isDirectory()) {
                results.push({ name: item.name, path: rel, type: 'folder', size: null, modified: fs.statSync(full).mtime });
                results.push(...walkDir(full, basePath, maxDepth, depth + 1));
            } else if (item.isFile()) {
                const stat = fs.statSync(full);
                results.push({ name: item.name, path: rel, type: 'file', size: stat.size, modified: stat.mtime });
            }
        }
    } catch (e) {}
    return results;
}

function respond(res, code, data) {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function sendError(res, code, msg) { respond(res, code, { error: msg }); }

const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.searchParams;
    const user = getUser(req);

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    try {
        // === PUBLIC: Auth endpoints ===

        // POST /api/auth/signup
        if (pathname === '/api/auth/signup' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            const { email, name, password } = body;
            if (!email || !name || !password) return sendError(res, 400, 'Email, name, and password required');
            if (password.length < 4) return sendError(res, 400, 'Password must be at least 4 characters');
            const existing = db.findUser(email);
            if (existing) return sendError(res, 409, 'An account with this email already exists');
            const newUser = createUser(email, name, password);
            if (!newUser) return sendError(res, 500, 'Failed to create account');
            if (SMTP_ENABLED) {
                const userRecord = db.findUser(email);
                const link = `http://${req.headers.host || 'localhost:3000'}/api/auth/verify?token=${userRecord.verify_token}`;
                const html = `<h2>Welcome to Drive</h2><p>Click the link below to verify your email:</p><p><a href="${link}">${link}</a></p><p>Or copy this link into your browser.</p>`;
                sendEmail(email, 'Verify your email for Drive', html).catch(err => {
                    console.error('Send verification email failed:', err.message);
                    db.setUserVerified(email);
                });
            }
            return respond(res, 200, { success: true, user: newUser, verificationSent: SMTP_ENABLED });
        }

        // GET /api/auth/verify
        if (pathname === '/api/auth/verify' && req.method === 'GET') {
            const token = query.get('token');
            if (!token) {
                res.writeHead(400, { 'Content-Type': 'text/html' });
                res.end('<html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;color:#fff"><div style="text-align:center"><h2>Missing Token</h2><p>The verification link is invalid.</p><p><a href="/" style="color:#8ab4f8">Go to Drive</a></p></div></body></html>');
                return;
            }
            const user = db.findUserByVerifyToken(token);
            if (!user) {
                res.writeHead(400, { 'Content-Type': 'text/html' });
                res.end('<html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;color:#fff"><div style="text-align:center"><h2>Verification Failed</h2><p>This link is invalid or expired. Your account may already be verified.</p><p><a href="/" style="color:#8ab4f8">Go to Drive</a></p></div></body></html>');
                return;
            }
            db.setUserVerified(user.email);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;background:#1a1a2e;color:#fff"><div style="text-align:center"><h2>Email Verified!</h2><p>You can now sign in to your account.</p><p><a href="/" style="color:#8ab4f8">Go to Drive</a></p></div></body></html>');
            return;
        }

        // POST /api/auth/resend-verification
        if (pathname === '/api/auth/resend-verification' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            const { email } = body;
            if (!email) return sendError(res, 400, 'Email required');
            const user = db.findUser(email);
            if (!user) return sendError(res, 404, 'Account not found');
            if (user.verified) return sendError(res, 400, 'Email already verified');
            const link = `http://${req.headers.host || 'localhost:3000'}/api/auth/verify?token=${user.verify_token}`;
            const html = `<h2>Welcome to Drive</h2><p>Click the link below to verify your email:</p><p><a href="${link}">${link}</a></p>`;
            sendEmail(email, 'Verify your email for Drive', html).catch(err => {
                console.error('Resend verification failed:', err.message);
                db.setUserVerified(email);
            });
            return respond(res, 200, { success: true, emailSent: SMTP_ENABLED });
        }

        // POST /api/auth/signin
        if (pathname === '/api/auth/signin' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            const { email, password } = body;
            if (!email || !password) return sendError(res, 400, 'Email and password required');
            const vUser = verifyUser(email, password);
            if (!vUser) return sendError(res, 401, 'Invalid email or password');
            if (vUser.error) return sendError(res, 403, vUser.error);
            const token = createSession(vUser);
            setCookie(res, 'session', token);
            return respond(res, 200, { success: true, user: vUser });
        }

        // GET /api/auth/me
        if (pathname === '/api/auth/me' && req.method === 'GET') {
            if (!user) return respond(res, 200, { authenticated: false });
            return respond(res, 200, { authenticated: true, email: user.email, name: user.name, admin: !!user.admin });
        }

        // POST /api/auth/update-profile
        if (pathname === '/api/auth/update-profile' && req.method === 'POST') {
            if (!user) return sendError(res, 401, 'Authentication required');
            const body = JSON.parse(await parseBody(req));
            const { name } = body;
            if (!name) return sendError(res, 400, 'Name is required');
            db.updateProfile(user.email, name);
            return respond(res, 200, { success: true, name });
        }

        // POST /api/auth/change-password
        if (pathname === '/api/auth/change-password' && req.method === 'POST') {
            if (!user) return sendError(res, 401, 'Authentication required');
            const body = JSON.parse(await parseBody(req));
            const { currentPassword, newPassword } = body;
            if (!currentPassword || !newPassword) return sendError(res, 400, 'Current and new password required');
            if (newPassword.length < 4) return sendError(res, 400, 'New password must be at least 4 characters');
            const vUser = verifyUser(user.email, currentPassword);
            if (!vUser || vUser.error) return sendError(res, 401, 'Current password is incorrect');
            const { hash, salt } = hashPassword(newPassword);
            db.changePassword(user.email, hash, salt);
            return respond(res, 200, { success: true });
        }

        // GET /api/admin/users
        if (pathname === '/api/admin/users' && req.method === 'GET') {
            if (!user) return sendError(res, 401, 'Authentication required');
            if (!user.admin) return sendError(res, 403, 'Admin access required');
            const users = db.listAllUsers();
            // Add storage stats for each user
            const result = users.map(u => {
                const dir = path.join(__dirname, 'storage', sanitizeEmail(u.email));
                let totalSize = 0, fileCount = 0;
                if (fs.existsSync(dir)) {
                    (function count(dir) { try { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const full = path.join(dir, e.name); if (e.isDirectory()) { count(full); } else if (e.isFile()) { fileCount++; totalSize += fs.statSync(full).size; } } } catch (e) {} })(dir);
                }
                return { email: u.email, name: u.name, created_at: u.created_at, verified: !!u.verified, admin: !!u.admin, storageSize: totalSize, storageSizeFormatted: formatSize(totalSize), fileCount };
            });
            return respond(res, 200, result);
        }

        // POST /api/auth/logout
        if (pathname === '/api/auth/logout' && req.method === 'POST') {
            const cookies = parseCookies(req);
            if (cookies.session) destroySession(cookies.session);
            clearCookie(res, 'session');
            return respond(res, 200, { success: true });
        }

        // === CHECK AUTH for all file management routes ===
        const isFileRoute = pathname.startsWith('/api/files') || pathname.startsWith('/api/tree') ||
            pathname.startsWith('/api/search') || pathname.startsWith('/api/upload') ||
            pathname.startsWith('/api/download') || pathname.startsWith('/api/preview') ||
            pathname.startsWith('/api/rename') || pathname.startsWith('/api/move') ||
            pathname.startsWith('/api/folders') || pathname.startsWith('/api/trash') ||
            pathname.startsWith('/api/stats') || (pathname.startsWith('/api/share') && req.method !== 'GET') ||
            pathname.startsWith('/api/export');

        if (isFileRoute) {
            const authed = requireAuth(req, res);
            if (!authed) return;
        }

        // === FILE MANAGEMENT (all protected) ===

        if (pathname === '/api/files' && req.method === 'GET') {
            const dirPath = query.get('path') || '';
            const target = safeResolve(getUserRoot(user), dirPath);
            if (!target || !fs.existsSync(target)) return sendError(res, 404, 'Not found');
            if (!fs.statSync(target).isDirectory()) return sendError(res, 400, 'Not a directory');
            const items = fs.readdirSync(target, { withFileTypes: true });
            const list = items.map(item => {
                const full = path.join(target, item.name);
                const stat = fs.statSync(full);
                const ext = path.extname(item.name).toLowerCase();
                return {
                    name: item.name,
                    path: (dirPath ? dirPath + '/' : '') + item.name,
                    type: item.isDirectory() ? 'folder' : 'file',
                    size: item.isFile() ? stat.size : null,
                    sizeFormatted: item.isFile() ? formatSize(stat.size) : null,
                    fileType: item.isFile() ? getFileType(ext) : null,
                    modified: stat.mtime,
                };
            });
            list.sort((a, b) => {
                if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
                return a.name.localeCompare(b.name);
            });
            return respond(res, 200, list);
        }

        if (pathname === '/api/tree' && req.method === 'GET') {
            function buildTree(dir, relPath) {
                const items = [];
                try {
                    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
                        if (!e.isDirectory()) continue;
                        const full = path.join(dir, e.name);
                        const childRel = relPath ? relPath + '/' + e.name : e.name;
                        items.push({ name: e.name, path: childRel, children: buildTree(full, childRel) });
                    }
                } catch (e) {}
                items.sort((a, b) => a.name.localeCompare(b.name));
                return items;
            }
            return respond(res, 200, [{ name: 'My Drive', path: '', children: buildTree(getUserRoot(user), '') }]);
        }

        if (pathname === '/api/search' && req.method === 'GET') {
            const q = (query.get('q') || '').toLowerCase().trim();
            if (!q) return respond(res, 200, []);
            const maxResults = parseInt(query.get('max') || '100', 10);
            const results = walkDir(getUserRoot(user), getUserRoot(user), 10);
            return respond(res, 200, results.filter(i => i.name.toLowerCase().includes(q)).slice(0, maxResults).map(f => ({ ...f, sizeFormatted: f.size != null ? formatSize(f.size) : null, fileType: f.type === 'file' ? getFileType(path.extname(f.name).toLowerCase()) : null })));
        }

        if (pathname === '/api/upload' && req.method === 'POST') {
            return handleUpload(req, res, query.get('path') || '', user);
        }

        if (pathname === '/api/download' && req.method === 'GET') {
            const filePath = query.get('path') || '';
            const target = safeResolve(getUserRoot(user), filePath);
            if (!target || !fs.existsSync(target) || !fs.statSync(target).isFile()) return sendError(res, 404, 'File not found');
            const stat = fs.statSync(target);
            res.writeHead(200, { 'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${path.basename(target)}"`, 'Content-Length': stat.size });
            fs.createReadStream(target).pipe(res);
            return;
        }

        if (pathname === '/api/preview' && req.method === 'GET') {
            const filePath = query.get('path') || '';
            const target = safeResolve(getUserRoot(user), filePath);
            if (!target || !fs.existsSync(target) || !fs.statSync(target).isFile()) return sendError(res, 404, 'File not found');
            const stat = fs.statSync(target);
            const mime = MIME[path.extname(target).toLowerCase()] || 'application/octet-stream';
            if (!isPreviewable(mime)) return sendError(res, 400, 'File type not previewable');
            res.writeHead(200, { 'Content-Type': mime, 'Content-Disposition': `inline; filename="${path.basename(target)}"`, 'Content-Length': stat.size });
            fs.createReadStream(target).pipe(res);
            return;
        }

        if (pathname === '/api/rename' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            if (!body.path || !body.name) return sendError(res, 400, 'Missing path or name');
            if (body.name.includes('/') || body.name.includes('\\')) return sendError(res, 400, 'Invalid name');
            const src = safeResolve(getUserRoot(user), body.path);
            if (!src || !fs.existsSync(src)) return sendError(res, 404, 'Not found');
            const dst = path.join(path.dirname(src), body.name);
            if (fs.existsSync(dst)) return sendError(res, 409, 'Name already exists');
            fs.renameSync(src, dst);
            return respond(res, 200, { success: true });
        }

        if (pathname === '/api/move' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            const items = body.items || [body];
            if (!body.destination) return sendError(res, 400, 'Missing destination');
            const destPath = safeResolve(getUserRoot(user), body.destination);
            if (!destPath || !fs.existsSync(destPath)) return sendError(res, 404, 'Destination not found');
            const results = [];
            for (const item of items) {
                const srcPath = safeResolve(getUserRoot(user), item.path);
                if (!srcPath || !fs.existsSync(srcPath)) continue;
                let dst = path.join(destPath, path.basename(srcPath));
                let c = 1;
                while (fs.existsSync(dst)) { const ext = path.extname(dst); const base = path.basename(dst, ext); dst = path.join(destPath, `${base} (${c})${ext}`); c++; }
                fs.renameSync(srcPath, dst);
                results.push({ from: item.path, to: body.destination + '/' + path.basename(dst) });
            }
            return respond(res, 200, { moved: results.length, items: results });
        }

        if (pathname === '/api/folders' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            if (!body.name) return sendError(res, 400, 'Missing name');
            const parent = safeResolve(getUserRoot(user), body.path || '');
            if (!parent || !fs.existsSync(parent)) return sendError(res, 404, 'Parent not found');
            const target = path.join(parent, body.name);
            if (fs.existsSync(target)) return sendError(res, 409, 'Folder already exists');
            fs.mkdirSync(target, { recursive: true });
            return respond(res, 200, { success: true, path: (body.path ? body.path + '/' : '') + body.name });
        }

        if (pathname === '/api/files' && req.method === 'DELETE') {
            const filePath = query.get('path');
            if (!filePath) return sendError(res, 400, 'Missing path');
            const target = safeResolve(getUserRoot(user), filePath);
            if (!target || !fs.existsSync(target)) return sendError(res, 404, 'Not found');
            const trashPath = path.join(getUserTrash(user), filePath);
            const trashDir = path.dirname(trashPath);
            if (!fs.existsSync(trashDir)) fs.mkdirSync(trashDir, { recursive: true });
            let finalTrash = trashPath;
            let c = 1;
            while (fs.existsSync(finalTrash)) { const ext = path.extname(trashPath); const base = path.basename(trashPath, ext); finalTrash = path.join(trashDir, `${base}_${c}${ext}`); c++; }
            fs.renameSync(target, finalTrash);
            fs.writeFileSync(finalTrash + '.meta.json', JSON.stringify({ originalPath: filePath, isDirectory: fs.statSync(finalTrash).isDirectory() }));
            return respond(res, 200, { success: true });
        }

        if (pathname === '/api/trash' && req.method === 'GET') {
            const items = walkDir(getUserTrash(user), getUserTrash(user), 10);
            return respond(res, 200, items.filter(i => !i.name.endsWith('.meta.json')).map(i => {
                const metaPath = path.join(getUserTrash(user), i.path + '.meta.json');
                let original = i.path;
                if (fs.existsSync(metaPath)) { try { original = JSON.parse(fs.readFileSync(metaPath, 'utf8')).originalPath; } catch (e) {} }
                return { ...i, originalPath: original, sizeFormatted: i.size != null ? formatSize(i.size) : null, fileType: i.type === 'file' ? getFileType(path.extname(i.name).toLowerCase()) : null };
            }));
        }

        if (pathname === '/api/trash/restore' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            if (!body.path) return sendError(res, 400, 'Missing path');
            const trashItem = safeResolve(getUserTrash(user), body.path);
            if (!trashItem || !fs.existsSync(trashItem)) return sendError(res, 404, 'Not found in trash');
            const metaPath = trashItem + '.meta.json';
            let originalPath = body.path;
            if (fs.existsSync(metaPath)) { try { originalPath = JSON.parse(fs.readFileSync(metaPath, 'utf8')).originalPath; } catch (e) {} }
            const restoreTarget = safeResolve(getUserRoot(user), originalPath);
            if (!restoreTarget) return sendError(res, 400, 'Invalid restore path');
            const restoreDir = path.dirname(restoreTarget);
            if (!fs.existsSync(restoreDir)) fs.mkdirSync(restoreDir, { recursive: true });
            if (fs.existsSync(restoreTarget)) {
                const ext = path.extname(restoreTarget);
                const base = path.basename(restoreTarget, ext);
                let c = 1, newTarget = path.join(path.dirname(restoreTarget), `${base}_restored${ext}`);
                while (fs.existsSync(newTarget)) { newTarget = path.join(path.dirname(restoreTarget), `${base}_restored_${c}${ext}`); c++; }
                fs.renameSync(trashItem, newTarget);
                if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
                return respond(res, 200, { success: true, restoredTo: path.basename(newTarget) });
            }
            fs.renameSync(trashItem, restoreTarget);
            if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
            return respond(res, 200, { success: true });
        }

        if (pathname === '/api/trash' && req.method === 'DELETE') {
            (function rmDir(dir) { if (!fs.existsSync(dir)) return; for (const e of fs.readdirSync(dir)) { const full = path.join(dir, e); if (fs.statSync(full).isDirectory()) rmDir(full); else fs.unlinkSync(full); } fs.rmdirSync(dir); })(getUserTrash(user));
            if (!fs.existsSync(getUserTrash(user))) fs.mkdirSync(getUserTrash(user));
            return respond(res, 200, { success: true });
        }

        // === SHARE ===
        if (pathname === '/api/share' && req.method === 'GET') {
            const list = db.listShares().map(s => ({ token: s.token, path: s.path, email: s.email, createdAt: s.created_at, url: `/api/share/${s.token}` }));
            return respond(res, 200, list);
        }
        if (pathname === '/api/share' && req.method === 'POST') {
            const body = JSON.parse(await parseBody(req));
            if (!body.path) return sendError(res, 400, 'Missing path');
            const target = safeResolve(getUserRoot(user), body.path);
            if (!target || !fs.existsSync(target)) return sendError(res, 404, 'Not found');
            const token = crypto.randomBytes(16).toString('hex');
            db.createShare(token, body.path, user.email);
            return respond(res, 200, { token, url: `/api/share/${token}` });
        }
        if (pathname.startsWith('/api/share/') && req.method === 'GET') {
            // Shared file access — public (no auth required)
            const token = pathname.replace('/api/share/', '');
            const link = db.getShare(token);
            if (!link) return sendError(res, 404, 'Share link not found');
            const shaUser = { email: link.email };
            const target = safeResolve(getUserRoot(shaUser), link.path);
            if (!target || !fs.existsSync(target)) return sendError(res, 404, 'Shared file no longer exists');
            if (fs.statSync(target).isDirectory()) {
                const items = fs.readdirSync(target, { withFileTypes: true });
                return respond(res, 200, { shared: true, path: link.path, files: items.map(item => { const full = path.join(target, item.name); const stat = fs.statSync(full); return { name: item.name, path: link.path + '/' + item.name, type: item.isDirectory() ? 'folder' : 'file', size: item.isFile() ? stat.size : null, sizeFormatted: item.isFile() ? formatSize(stat.size) : null }; }) });
            }
            const stat = fs.statSync(target);
            res.writeHead(200, { 'Content-Type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream', 'Content-Disposition': `inline; filename="${path.basename(target)}"`, 'Content-Length': stat.size });
            fs.createReadStream(target).pipe(res);
            return;
        }
        if (pathname.startsWith('/api/share/') && req.method === 'DELETE') {
            const token = pathname.replace('/api/share/', '');
            if (db.getShare(token)) { db.deleteShare(token); return respond(res, 200, { success: true }); }
            return sendError(res, 404, 'Share link not found');
        }

        // === STATS ===
        if (pathname === '/api/stats' && req.method === 'GET') {
            let totalSize = 0, fileCount = 0, folderCount = 0;
            (function count(dir) { try { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const full = path.join(dir, e.name); if (e.isDirectory()) { folderCount++; count(full); } else if (e.isFile()) { fileCount++; totalSize += fs.statSync(full).size; } } } catch (e) {} })(getUserRoot(user));
            let trashSize = 0, trashCount = 0;
            if (fs.existsSync(getUserTrash(user))) { (function countTrash(dir) { try { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { if (e.name.endsWith('.meta.json')) continue; const full = path.join(dir, e.name); if (e.isDirectory()) { trashCount++; countTrash(full); } else if (e.isFile()) { trashCount++; trashSize += fs.statSync(full).size; } } } catch (e) {} })(getUserTrash(user)); }
            return respond(res, 200, { totalFiles: fileCount, totalFolders: folderCount, totalSize, totalSizeFormatted: formatSize(totalSize), trashFiles: trashCount, trashSize, trashSizeFormatted: formatSize(trashSize), shareLinks: db.listShares().length });
        }

        // === SERVE STATIC (public) ===
        const fp = pathname === '/' ? '/index.html' : pathname;
        const staticFile = safeResolve(__dirname, 'public' + fp);
        if (staticFile && fs.existsSync(staticFile) && fs.statSync(staticFile).isFile()) {
            const ext = path.extname(staticFile).toLowerCase();
            const stat = fs.statSync(staticFile);
            res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': stat.size, 'Cache-Control': 'no-cache' });
            fs.createReadStream(staticFile).pipe(res);
            return;
        }

        sendError(res, 404, 'Not found');
    } catch (err) {
        console.error('Server error:', err);
        try { sendError(res, 500, err.message || 'Internal server error'); } catch (e) {}
    }
});

server.listen(PORT, () => {
    console.log(`\n  ╔══════════════════════════════════╗`);
    console.log(`  ║    Drive — File Manager          ║`);
    console.log(`  ║    http://localhost:${PORT}            ║`);
    console.log(`  ║    Auth: Email + Password         ║`);
    console.log(`  ╚══════════════════════════════════╝\n`);
});
