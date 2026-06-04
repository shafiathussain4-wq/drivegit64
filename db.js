const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_PATH = path.join(DATA_DIR, 'drive.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  verify_token TEXT,
  admin INTEGER NOT NULL DEFAULT 0
)`);

// Add admin column if missing (existing databases)
try { db.exec('ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0'); } catch (e) {}
// Add google_id column if missing
try { db.exec('ALTER TABLE users ADD COLUMN google_id TEXT'); } catch (e) {}

db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at TEXT NOT NULL
)`);

db.exec(`CREATE TABLE IF NOT EXISTS share_links (
  token TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at TEXT NOT NULL
)`);

// Migrate from JSON files
function migrate() {
  const usersPath = path.join(__dirname, 'users.json');
  if (fs.existsSync(usersPath)) {
    try {
      const existing = db.prepare('SELECT COUNT(*) as c FROM users').get();
      if (existing.c === 0) {
        const data = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        const ins = db.prepare('INSERT OR IGNORE INTO users (email, name, password_hash, salt, created_at, verified, verify_token) VALUES (?, ?, ?, ?, ?, ?, ?)');
        for (const email of Object.keys(data)) {
          const u = data[email];
          ins.run(email, u.name, u.passwordHash, u.salt, u.createdAt, u.verified ? 1 : 0, u.verifyToken || null);
        }
      }
    } catch (e) { console.error('Migrate users error:', e.message); }
  }

  const sessPath = path.join(__dirname, 'sessions.json');
  if (fs.existsSync(sessPath)) {
    try {
      const existing = db.prepare('SELECT COUNT(*) as c FROM sessions').get();
      if (existing.c === 0) {
        const data = JSON.parse(fs.readFileSync(sessPath, 'utf8'));
        const ins = db.prepare('INSERT OR IGNORE INTO sessions (token, email, created_at) VALUES (?, ?, ?)');
        for (const token of Object.keys(data)) {
          const s = data[token];
          ins.run(token, s.email, s.createdAt);
        }
      }
    } catch (e) { console.error('Migrate sessions error:', e.message); }
  }

  const sharePath = path.join(__dirname, 'shares.json');
  if (fs.existsSync(sharePath)) {
    try {
      const existing = db.prepare('SELECT COUNT(*) as c FROM share_links').get();
      if (existing.c === 0) {
        const data = JSON.parse(fs.readFileSync(sharePath, 'utf8'));
        const ins = db.prepare('INSERT OR IGNORE INTO share_links (token, path, email, created_at) VALUES (?, ?, ?, ?)');
        for (const token of Object.keys(data)) {
          const l = data[token];
          ins.run(token, l.path, l.email, l.createdAt);
        }
      }
    } catch (e) { console.error('Migrate shares error:', e.message); }
  }
}

migrate();

const getUser = db.prepare('SELECT * FROM users WHERE email = ?');
const getUserByGoogleId = db.prepare('SELECT * FROM users WHERE google_id = ?');
const getUserByToken = db.prepare('SELECT * FROM users WHERE verify_token = ?');
const insertUser = db.prepare('INSERT INTO users (email, name, password_hash, salt, created_at, verified, verify_token) VALUES (?, ?, ?, ?, ?, ?, ?)');
const updateUser = db.prepare('UPDATE users SET verified = ?, verify_token = ? WHERE email = ?');
const linkGoogleId = db.prepare('UPDATE users SET google_id = ?, verified = 1 WHERE email = ?');
const getSession = db.prepare('SELECT sessions.*, users.name, users.admin FROM sessions JOIN users ON sessions.email = users.email WHERE sessions.token = ?');
const insertSession = db.prepare('INSERT INTO sessions (token, email, created_at) VALUES (?, ?, ?)');
const deleteSession = db.prepare('DELETE FROM sessions WHERE token = ?');
const insertShare = db.prepare('INSERT INTO share_links (token, path, email, created_at) VALUES (?, ?, ?, ?)');
const getShare = db.prepare('SELECT * FROM share_links WHERE token = ?');
const deleteShare = db.prepare('DELETE FROM share_links WHERE token = ?');
const listShares = db.prepare('SELECT * FROM share_links ORDER BY created_at DESC');
const updateUserProfile = db.prepare('UPDATE users SET name = ? WHERE email = ?');
const updateUserPassword = db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE email = ?');
const listAllUsers = db.prepare('SELECT email, name, created_at, verified, admin FROM users ORDER BY created_at DESC');

module.exports = {
  // Users
  findUser(email) {
    return getUser.get(email) || null;
  },
  userExists(email) {
    return !!getUser.get(email);
  },
  createUser(email, name, passwordHash, salt, verified, verifyToken) {
    insertUser.run(email, name, passwordHash, salt, new Date().toISOString(), verified ? 1 : 0, verifyToken);
  },
  verifyUser(email, verifyToken) {
    updateUser.run(1, null, email);
  },
  setUserVerified(email) {
    updateUser.run(1, null, email);
  },
  getUserVerifyToken(email) {
    const row = getUser.get(email);
    return row ? row.verify_token : null;
  },
  findUserByVerifyToken(token) {
    return getUserByToken.get(token) || null;
  },
  findUserByGoogleId(googleId) {
    return getUserByGoogleId.get(googleId) || null;
  },
  createGoogleUser(email, name, googleId) {
    const ins = db.prepare('INSERT INTO users (email, name, password_hash, salt, created_at, verified, verify_token, google_id) VALUES (?, ?, ?, ?, ?, 1, NULL, ?)');
    ins.run(email, name, '', '', new Date().toISOString(), googleId);
  },
  linkGoogleAccount(email, googleId) {
    linkGoogleId.run(googleId, email);
  },

  // Sessions
  getSession(token) {
    return getSession.get(token) || null;
  },
  createSession(token, email) {
    insertSession.run(token, email, new Date().toISOString());
  },
  destroySession(token) {
    deleteSession.run(token);
  },

  // Share links
  createShare(token, filePath, email) {
    insertShare.run(token, filePath, email, new Date().toISOString());
  },
  getShare(token) {
    return getShare.get(token) || null;
  },
  deleteShare(token) {
    deleteShare.run(token);
  },
  listShares() {
    return listShares.all();
  },

  // Profile / Admin
  updateProfile(email, name) {
    updateUserProfile.run(name, email);
  },
  changePassword(email, passwordHash, salt) {
    updateUserPassword.run(passwordHash, salt, email);
  },
  listAllUsers() {
    return listAllUsers.all();
  },
  setAdmin(email, admin = 1) {
    db.prepare('UPDATE users SET admin = ? WHERE email = ?').run(admin ? 1 : 0, email);
  },
};
