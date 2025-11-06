const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'app.db');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123'; // 管理员密钥

// ---- SQLite 初始化 ----
const db = new Database(DB_FILE);
db.exec(`
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  used_by TEXT,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  invite_code TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  answers_json TEXT NOT NULL,
  scores_json TEXT NOT NULL,
  analysis TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

// ---- App 基础中间件 ----
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- 会话工具 ----
function signSession(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.userId = data.uid;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid session' });
  }
}

// ---- 管理：生成邀请码 ----
app.post('/admin/generate', (req, res) => {
  if ((req.headers['x-admin-key'] || '') !== ADMIN_KEY)
    return res.status(403).json({ error: 'Forbidden' });

  const count = Math.min(parseInt(req.query.count || '1'), 200);
  const stmt = db.prepare('INSERT OR REPLACE INTO invites (code) VALUES (?)');
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = nanoid(8);
    codes.push(code);
    stmt.run(code);
  }
  res.json({ ok: true, codes });
});

// ---- 绑定邀请码 → 创建用户并登录 ----
app.post('/api/claim-invite', (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Missing code' });

  const row = db.prepare('SELECT * FROM invites WHERE code = ?').get(code);
  if (!row) return res.status(400).json({ error: 'Invalid code' });
  if (row.used_by) return res.status(400).json({ error: 'Code already used' });

  const userId = nanoid(12);
  const now = new Date().toISOString();
  db.prepare('INSERT INTO users (id, invite_code, created_at) VALUES (?, ?, ?)')
    .run(userId, code, now);
  db.prepare('UPDATE invites SET used_by=?, used_at=? WHERE code=?')
    .run(userId, now, code);

  const token = signSession(userId);
  res.cookie('session', token, { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 3600 * 1000 });
  res.json({ ok: true, userId });
});

// ---- 退出 / 更换验证码 ----
app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// ---- 当前用户 ----
app.get('/api/me', auth, (req, res) => {
  const me = db.prepare('SELECT id, invite_code, created_at FROM users WHERE id=?').get(req.userId);
  res.json({ ok: true, me });
});

// ---- 提交答案 → 计算 0–100 分 + 文案 ----
app.post('/api/submit', auth, (req, res) => {
  const { answers } = req.body || {};
  if (!Array.isArray(answers) || answers.length === 0)
    return res.status(400).json({ error: 'Invalid answers' });

  // 与前端一致：正向/反向题
  const REVERSE = [2, 4, 5, 8, 9]; // 同意→更弱占有欲，需反向计分
  const norm = answers.map((v, i) => REVERSE.includes(i) ? (6 - Number(v || 0)) : Number(v || 0));
  const sum = norm.reduce((a, b) => a + b, 0);          // 10~50
  const composite = Number((sum / norm.length).toFixed(2)); // 1~5
  const composite100 = Math.round(((composite - 1) / 4) * 100); // 0~100

  // 4 档等级（贴近你给的参考）
  let level, advice;
  if (composite100 >= 76) {
    level = '强烈';
    advice = '占有欲较强，可能给关系带来压力。建议练习界限感与情绪调节，建立更稳定的安全感来源。';
  } else if (composite100 >= 51) {
    level = '较强（需要注意）';
    advice = '关注不安与控制欲的触发点，尝试用清晰表达需求、协商规则代替“紧盯”。';
  } else if (composite100 >= 26) {
    level = '适中（恰到好处）';
    advice = '在信任与关注之间取得平衡，保持开放沟通与定期复盘边界。';
  } else {
    level = '较低（自由自在）';
    advice = '给足伴侣自由与信任；也要注意表达投入，避免被误解为疏离。';
  }

  const analysis = `你的总分：${composite100}/100 · 等级：${level}。${advice}`;

  const now = new Date().toISOString();
  const id = nanoid(10);
  const payloadScores = { composite, composite100 };
  db.prepare('INSERT INTO results (id,user_id,answers_json,scores_json,analysis,created_at) VALUES (?,?,?,?,?,?)')
    .run(id, req.userId, JSON.stringify(answers), JSON.stringify(payloadScores), analysis, now);

  res.json({ ok: true, id, scores: payloadScores, analysis });
});

// ---- 最近一次结果 ----
app.get('/api/result', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM results WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.userId);
  if (!row) return res.json({ ok: true, result: null });
  res.json({
    ok: true,
    result: {
      id: row.id,
      created_at: row.created_at,
      answers: JSON.parse(row.answers_json),
      scores: JSON.parse(row.scores_json),
      analysis: row.analysis,
    },
  });
});

// ---- 启动 ----
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
