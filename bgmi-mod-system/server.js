const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.disable('x-powered-by');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'shree_krishna_mod_secret_2025',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: '1h',
  lastModified: true
}));

const dbPath = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// Database schema
 db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    balance INTEGER DEFAULT 0,
    admin_balance INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    is_owner INTEGER DEFAULT 0,
    device_limit INTEGER DEFAULT 1,
    key_expiry DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    device_id TEXT UNIQUE,
    last_login DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE,
    created_by INTEGER,
    balance_amount INTEGER DEFAULT 0,
    device_limit INTEGER DEFAULT 1,
    expiry_days INTEGER,
    is_used INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    used_by_user_id INTEGER,
    used_at DATETIME,
    blocked_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS key_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT,
    action TEXT,
    user_id INTEGER,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.all('PRAGMA table_info(keys)', (err, columns = []) => {
    if (err) return;
    const columnNames = columns.map((column) => column.name);
    if (!columnNames.includes('blocked')) {
      db.run('ALTER TABLE keys ADD COLUMN blocked INTEGER DEFAULT 0');
    }
    if (!columnNames.includes('blocked_at')) {
      db.run('ALTER TABLE keys ADD COLUMN blocked_at DATETIME');
    }
  });
});

// Create owner account if missing
 db.get('SELECT * FROM users WHERE is_owner = 1', async (err, row) => {
  if (!row) {
    const hashed = await bcrypt.hash('8788296319', 10);
    db.run(
      `INSERT INTO users (username, password, balance, admin_balance, is_admin, is_owner, device_limit)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ['pushkar2006', hashed, 999999, 999999, 1, 1, 100]
    );
    console.log('Owner created: pushkar2006 / 8788296319');
  }
});

function isAdmin(req, res, next) {
  if (req.session.userId && (req.session.isAdmin || req.session.isOwner)) return next();
  res.status(403).json({ error: 'Admin only' });
}

function isOwner(req, res, next) {
  if (req.session.userId && req.session.isOwner) return next();
  res.status(403).json({ error: 'Owner only' });
}

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.get('/admin', (req, res) => {
  if (!req.session.userId) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/india-time', (req, res) => {
  const now = new Date();
  const indiaTime = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
  res.json({ time: indiaTime.toISOString(), running: 'Shree Krishna Mod Active' });
});

app.post('/api/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  if (!username || !password || !deviceId) {
    return res.status(400).json({ error: 'Missing credentials or device ID' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid username/password' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid username/password' });

    if (user.key_expiry && new Date(user.key_expiry) < new Date()) {
      return res.status(403).json({ error: 'Your key has expired. Contact admin.' });
    }

    db.get('SELECT user_id FROM user_devices WHERE device_id = ?', [deviceId], (existingErr, existingDevice) => {
      if (existingErr) return res.status(500).json({ error: 'DB error' });
      if (existingDevice && existingDevice.user_id !== user.id) {
        return res.status(403).json({ error: 'Device already registered to another account' });
      }

      db.all('SELECT device_id FROM user_devices WHERE user_id = ?', [user.id], (deviceErr, devices = []) => {
      if (deviceErr) return res.status(500).json({ error: 'DB error' });

      const currentDeviceCount = devices.length;
      const isDeviceBound = devices.some((device) => device.device_id === deviceId);

      if (!isDeviceBound && currentDeviceCount >= user.device_limit) {
        return res.status(403).json({ error: `Device limit reached (${user.device_limit}). Contact admin.` });
      }

      if (!isDeviceBound) {
        db.run(
          'INSERT INTO user_devices (user_id, device_id, last_login) VALUES (?, ?, CURRENT_TIMESTAMP)',
          [user.id, deviceId],
          (insertErr) => {
            if (insertErr && insertErr.code !== 'SQLITE_CONSTRAINT') {
              return res.status(500).json({ error: 'DB error' });
            }
          }
        );
      } else {
        db.run(
          'UPDATE user_devices SET last_login = CURRENT_TIMESTAMP WHERE user_id = ? AND device_id = ?',
          [user.id, deviceId]
        );
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.isAdmin = user.is_admin === 1;
      req.session.isOwner = user.is_owner === 1;
      req.session.adminBalance = user.admin_balance;

      res.json({
        success: true,
        isAdmin: req.session.isAdmin,
        isOwner: req.session.isOwner,
        balance: user.balance,
        deviceLimit: user.device_limit,
        keyExpiry: user.key_expiry,
        message: 'Login successful'
      });
      });
    });
  });
});

app.post('/api/register', async (req, res) => {
  const { username, password, deviceId, keyCode } = req.body;
  if (!username || !password || !deviceId || !keyCode) {
    return res.status(400).json({ error: 'All fields including key code required' });
  }
  if (password.length < 4) return res.status(400).json({ error: 'Password min 4 chars' });

  db.get('SELECT * FROM keys WHERE key_code = ? AND is_used = 0 AND blocked = 0', [keyCode], async (err, key) => {
    if (err || !key) return res.status(400).json({ error: 'Invalid or already used key' });

    db.get('SELECT id FROM user_devices WHERE device_id = ?', [deviceId], async (deviceErr, existingDevice) => {
      if (deviceErr) return res.status(500).json({ error: 'DB error' });
      if (existingDevice) return res.status(400).json({ error: 'This device already registered' });

      const hashed = await bcrypt.hash(password, 10);
      let expiryDate = null;
      if (key.expiry_days) {
        expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + key.expiry_days);
      }

      db.run(
        `INSERT INTO users (username, password, balance, device_limit, key_expiry)
         VALUES (?, ?, ?, ?, ?)`,
        [username, hashed, key.balance_amount, key.device_limit, expiryDate],
        function insertErr(err2) {
          if (err2) return res.status(400).json({ error: 'Username exists' });

          const userId = this.lastID;
          db.run(
            'INSERT INTO user_devices (user_id, device_id) VALUES (?, ?)',
            [userId, deviceId],
            (deviceInsertErr) => {
              if (deviceInsertErr && deviceInsertErr.code !== 'SQLITE_CONSTRAINT') {
                return res.status(500).json({ error: 'DB error' });
              }
            }
          );
          db.run(
            'UPDATE keys SET is_used = 1, used_by_user_id = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?',
            [userId, key.id]
          );
          db.run(
            'INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)',
            [keyCode, 'used', userId, `Balance +${key.balance_amount}, Device limit ${key.device_limit}`]
          );

          res.json({ success: true, message: 'Account created! Please login.' });
        }
      );
    });
  });
});

app.get('/api/me', (req, res) => {
  if (req.session.userId) {
    res.json({
      loggedIn: true,
      username: req.session.username,
      isAdmin: req.session.isAdmin,
      isOwner: req.session.isOwner,
      adminBalance: req.session.adminBalance
    });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.post('/api/admin/generate-key', isAdmin, async (req, res) => {
  const { balance_amount, device_limit, expiry_days, quantity = 1 } = req.body;
  if (!balance_amount || balance_amount <= 0) {
    return res.status(400).json({ error: 'Valid balance amount required' });
  }

  const requiredBalance = balance_amount * quantity;
  const unlimited = req.session.isOwner;

  if (!unlimited) {
    const row = await new Promise((resolve) => {
      db.get('SELECT admin_balance FROM users WHERE id = ?', [req.session.userId], (err, found) => resolve(found));
    });
    if (!row || row.admin_balance < requiredBalance) {
      return res.status(400).json({
        error: `Insufficient admin balance. Need ${requiredBalance}, have ${row ? row.admin_balance : 0}`
      });
    }
  }

  const keys = [];
  for (let i = 0; i < quantity; i++) {
    const keyCode = crypto.randomBytes(12).toString('hex').toUpperCase();
    keys.push(keyCode);
    db.run(
      `INSERT INTO keys (key_code, created_by, balance_amount, device_limit, expiry_days)
       VALUES (?, ?, ?, ?, ?)`,
      [keyCode, req.session.userId, balance_amount, device_limit || 1, expiry_days || null]
    );
    db.run(
      'INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)',
      [keyCode, 'generated', req.session.userId, `Balance: ${balance_amount}, Limit: ${device_limit}`]
    );
  }

  if (!unlimited) {
    db.run('UPDATE users SET admin_balance = admin_balance - ? WHERE id = ?', [requiredBalance, req.session.userId]);
    req.session.adminBalance -= requiredBalance;
  }

  res.json({ success: true, keys, unlimited });
});

app.get('/api/admin/keys', isAdmin, (req, res) => {
  db.all(
    `SELECT k.*, u.username as used_by_username FROM keys k
     LEFT JOIN users u ON k.used_by_user_id = u.id
     ORDER BY k.id DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json(rows);
    }
  );
});

app.delete('/api/admin/keys/:id', isAdmin, (req, res) => {
  const id = req.params.id;
  db.get('SELECT is_used FROM keys WHERE id = ?', [id], (err, key) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (key && key.is_used) return res.status(400).json({ error: 'Cannot delete used key' });
    db.run('DELETE FROM keys WHERE id = ?', [id]);
    res.json({ success: true });
  });
});

app.post('/api/admin/keys/:id/reset', isAdmin, (req, res) => {
  const id = req.params.id;
  db.run(
    `UPDATE keys
     SET is_used = 0,
         blocked = 0,
         used_by_user_id = NULL,
         used_at = NULL,
         blocked_at = NULL
     WHERE id = ?`,
    [id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Reset failed' });
      db.get('SELECT key_code FROM keys WHERE id = ?', [id], (fetchErr, key) => {
        if (!fetchErr && key) {
          db.run(
            'INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)',
            [key.key_code, 'reset', req.session.userId, 'Key reset by admin']
          );
        }
      });
      res.json({ success: true });
    }
  );
});

app.post('/api/admin/keys/:id/block', isAdmin, (req, res) => {
  const id = req.params.id;
  db.run(
    `UPDATE keys
     SET blocked = 1,
         blocked_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Block failed' });
      db.get('SELECT key_code FROM keys WHERE id = ?', [id], (fetchErr, key) => {
        if (!fetchErr && key) {
          db.run(
            'INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)',
            [key.key_code, 'blocked', req.session.userId, 'Key blocked by admin']
          );
        }
      });
      res.json({ success: true });
    }
  );
});

app.get('/api/admin/users', isAdmin, (req, res) => {
  db.all(
    'SELECT id, username, balance, admin_balance, is_admin, is_owner, device_limit, key_expiry, created_at FROM users',
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json(rows);
    }
  );
});

app.post('/api/admin/users', isAdmin, async (req, res) => {
  const { username, password, balance, is_admin } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (is_admin && !req.session.isOwner) return res.status(403).json({ error: 'Only owner can create admins' });

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)',
    [username, hashed, balance || 0, is_admin ? 1 : 0],
    function(err) {
      if (err) return res.status(400).json({ error: 'Username exists' });
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.delete('/api/admin/users/:id', isAdmin, (req, res) => {
  const id = req.params.id;
  if (id == req.session.userId) return res.status(400).json({ error: 'Cannot delete yourself' });

  db.get('SELECT is_admin, is_owner FROM users WHERE id = ?', [id], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (user && (user.is_owner || (user.is_admin && !req.session.isOwner))) {
      return res.status(403).json({ error: 'Cannot delete this user' });
    }
    db.run('DELETE FROM users WHERE id = ?', [id]);
    db.run('DELETE FROM user_devices WHERE user_id = ?', [id]);
    res.json({ success: true });
  });
});

app.post('/api/admin/users/:id/reset-password', isAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Password min 4 chars' });
  const targetId = req.params.id;
  db.get('SELECT is_admin, is_owner FROM users WHERE id = ?', [targetId], async (err, targetUser) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (targetUser && (targetUser.is_owner || (targetUser.is_admin && !req.session.isOwner))) {
      return res.status(403).json({ error: 'Owner only can manage admin accounts' });
    }
    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, targetId], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true });
    });
  });
});

app.post('/api/admin/users/:id/balance', isAdmin, (req, res) => {
  const { balance } = req.body;
  const targetId = req.params.id;
  db.get('SELECT is_admin, is_owner FROM users WHERE id = ?', [targetId], (err, targetUser) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (targetUser && (targetUser.is_owner || (targetUser.is_admin && !req.session.isOwner))) {
      return res.status(403).json({ error: 'Owner only can manage admin accounts' });
    }
    db.run('UPDATE users SET balance = ? WHERE id = ?', [balance, targetId], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: 'Update failed' });
      res.json({ success: true });
    });
  });
});

app.post('/api/owner/add-admin-balance', isOwner, (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || amount <= 0) return res.status(400).json({ error: 'Invalid' });
  db.run('UPDATE users SET admin_balance = admin_balance + ? WHERE id = ?', [amount, userId], (err) => {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

app.post('/api/owner/set-admin', isOwner, (req, res) => {
  const { userId, isAdmin: makeAdmin } = req.body;
  db.get('SELECT is_owner FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (user && user.is_owner) return res.status(400).json({ error: 'Cannot change owner' });
    db.run('UPDATE users SET is_admin = ? WHERE id = ?', [makeAdmin ? 1 : 0, userId]);
    res.json({ success: true });
  });
});

app.get('/api/admin/users/:id/devices', isAdmin, (req, res) => {
  db.all('SELECT device_id, last_login FROM user_devices WHERE user_id = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.post('/api/admin/users/:id/devices', isAdmin, (req, res) => {
  const targetId = req.params.id;
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'Device ID required' });

  db.get('SELECT is_admin, is_owner, device_limit FROM users WHERE id = ?', [targetId], (err, targetUser) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if ((targetUser.is_admin || targetUser.is_owner) && !req.session.isOwner) {
      return res.status(403).json({ error: 'Owner only can manage admin accounts' });
    }

    db.get('SELECT user_id FROM user_devices WHERE device_id = ?', [deviceId], (existingErr, existingDevice) => {
      if (existingErr) return res.status(500).json({ error: 'DB error' });
      if (existingDevice && existingDevice.user_id !== Number(targetId)) {
        return res.status(400).json({ error: 'Device already registered to another user' });
      }

      if (existingDevice && existingDevice.user_id === Number(targetId)) {
        db.run(
          'UPDATE user_devices SET last_login = CURRENT_TIMESTAMP WHERE user_id = ? AND device_id = ?',
          [targetId, deviceId],
          (updateErr) => {
            if (updateErr) return res.status(500).json({ error: 'DB error' });
            res.json({ success: true, updated: true });
          }
        );
        return;
      }

      db.all('SELECT id FROM user_devices WHERE user_id = ?', [targetId], (countErr, devices = []) => {
        if (countErr) return res.status(500).json({ error: 'DB error' });
        if (devices.length >= targetUser.device_limit) {
          return res.status(400).json({ error: `Device limit reached (${targetUser.device_limit})` });
        }

        db.run(
          'INSERT INTO user_devices (user_id, device_id, last_login) VALUES (?, ?, CURRENT_TIMESTAMP)',
          [targetId, deviceId],
          (insertErr) => {
            if (insertErr && insertErr.code !== 'SQLITE_CONSTRAINT') {
              return res.status(500).json({ error: 'DB error' });
            }
            res.json({ success: true });
          }
        );
      });
    });
  });
});

app.listen(PORT, HOST, () => {
  console.log(`BGMI Mod System running on http://${HOST}:${PORT}`);
  console.log('Owner: pushkar2006 / 8788296319');
});
