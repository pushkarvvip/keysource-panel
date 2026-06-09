const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'shree_krishna_mod_secret_key_2025',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Database
const db = new sqlite3.Database('./database.sqlite');

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        balance INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        is_owner INTEGER DEFAULT 0,
        device_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE,
        created_by INTEGER,
        balance_amount INTEGER DEFAULT 0,
        device_limit INTEGER DEFAULT 1,
        expiry_days INTEGER,
        is_used INTEGER DEFAULT 0,
        used_by_user_id INTEGER,
        used_device_id TEXT,
        used_at DATETIME,
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
});

// Create owner account (pushkar2006 / 8788296319)
db.get("SELECT * FROM users WHERE is_owner = 1", async (err, row) => {
    if (!row) {
        const hashed = await bcrypt.hash("8788296319", 10);
        db.run("INSERT INTO users (username, password, balance, is_admin, is_owner) VALUES (?, ?, ?, ?, ?)",
            ["pushkar2006", hashed, 999999, 1, 1]);
        console.log("Owner created: pushkar2006 / 8788296319");
    }
});

// Helper to check owner session
function isOwner(req, res, next) {
    if (req.session.userId && req.session.isOwner) return next();
    res.status(403).json({ error: "Owner access only" });
}
function isAdmin(req, res, next) {
    if (req.session.userId && (req.session.isAdmin || req.session.isOwner)) return next();
    res.status(403).json({ error: "Admin access only" });
}

// ---------- AUTH ROUTES ----------
app.post('/api/login', async (req, res) => {
    const { username, password, deviceId } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing credentials" });
    if (!deviceId) return res.status(400).json({ error: "Device ID missing" });

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Invalid username/password" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid username/password" });

        // Device check (if device already bound to another user)
        if (user.device_id && user.device_id !== deviceId) {
            return res.status(403).json({ error: "Device not authorized. Contact admin." });
        }
        // Bind device if not set
        if (!user.device_id) {
            db.run("UPDATE users SET device_id = ? WHERE id = ?", [deviceId, user.id]);
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isAdmin = user.is_admin === 1;
        req.session.isOwner = user.is_owner === 1;
        req.session.balance = user.balance;

        res.json({
            success: true,
            isAdmin: req.session.isAdmin,
            isOwner: req.session.isOwner,
            balance: user.balance,
            message: "Login successful"
        });
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password, deviceId, keyCode } = req.body;
    if (!username || !password || !deviceId) return res.status(400).json({ error: "Missing fields" });
    if (password.length < 4) return res.status(400).json({ error: "Password min 4 chars" });

    // Check if device already used?
    db.get("SELECT id FROM users WHERE device_id = ?", [deviceId], (err, existing) => {
        if (existing) return res.status(400).json({ error: "This device already registered" });
    });

    // If keyCode provided, validate it
    let balanceToAdd = 0;
    let deviceLimit = 1;
    let expiryDate = null;
    if (keyCode) {
        db.get("SELECT * FROM keys WHERE key_code = ? AND is_used = 0", [keyCode], async (err, key) => {
            if (err || !key) return res.status(400).json({ error: "Invalid or used key" });
            balanceToAdd = key.balance_amount;
            deviceLimit = key.device_limit;
            if (key.expiry_days) {
                expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + key.expiry_days);
            }
            // Hash password and create user
            const hashed = await bcrypt.hash(password, 10);
            db.run("INSERT INTO users (username, password, balance, device_id) VALUES (?, ?, ?, ?)",
                [username, hashed, balanceToAdd, deviceId], function(err) {
                if (err) return res.status(400).json({ error: "Username exists" });
                // Mark key as used
                db.run("UPDATE keys SET is_used = 1, used_by_user_id = ?, used_device_id = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?",
                    [this.lastID, deviceId, key.id]);
                db.run("INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)",
                    [keyCode, "used", this.lastID, `Balance: ${balanceToAdd}`]);
                res.json({ success: true, message: "Account created with key!" });
            });
        });
    } else {
        // Registration without key – requires admin creation normally, but we block unless admin made account first
        return res.status(400).json({ error: "Registration requires a valid key code. Get one from admin." });
    }
});

app.get('/api/me', (req, res) => {
    if (req.session.userId) {
        res.json({
            loggedIn: true,
            username: req.session.username,
            isAdmin: req.session.isAdmin,
            isOwner: req.session.isOwner,
            balance: req.session.balance
        });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// ---------- ADMIN / OWNER KEY MANAGEMENT ----------
// Generate random key
app.post('/api/admin/generate-key', isAdmin, async (req, res) => {
    const { balance_amount, device_limit, expiry_days, quantity = 1 } = req.body;
    if (!balance_amount) return res.status(400).json({ error: "Balance amount required" });
    const keys = [];
    for (let i = 0; i < quantity; i++) {
        const keyCode = crypto.randomBytes(12).toString('hex').toUpperCase();
        keys.push(keyCode);
        db.run(`INSERT INTO keys (key_code, created_by, balance_amount, device_limit, expiry_days)
                VALUES (?, ?, ?, ?, ?)`,
            [keyCode, req.session.userId, balance_amount, device_limit || 1, expiry_days || null]);
        db.run("INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)",
            [keyCode, "generated", req.session.userId, `Balance: ${balance_amount}, Limit: ${device_limit}`]);
    }
    res.json({ success: true, keys });
});

// Get all keys (admin/owner)
app.get('/api/admin/keys', isAdmin, (req, res) => {
    db.all(`SELECT k.*, u.username as used_by_username FROM keys k
            LEFT JOIN users u ON k.used_by_user_id = u.id
            ORDER BY k.id DESC`, (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows);
    });
});

// Delete key (only if unused)
app.delete('/api/admin/keys/:id', isAdmin, (req, res) => {
    const id = req.params.id;
    db.get("SELECT is_used FROM keys WHERE id = ?", [id], (err, key) => {
        if (key && key.is_used) return res.status(400).json({ error: "Cannot delete used key" });
        db.run("DELETE FROM keys WHERE id = ?", [id]);
        res.json({ success: true });
    });
});

// Get all users (admin/owner)
app.get('/api/admin/users', isAdmin, (req, res) => {
    db.all("SELECT id, username, balance, is_admin, is_owner, device_id, created_at FROM users", (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows);
    });
});

// Create user directly (admin/owner) with custom balance
app.post('/api/admin/users', isAdmin, async (req, res) => {
    const { username, password, balance, is_admin } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });
    const hashed = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)",
        [username, hashed, balance || 0, is_admin ? 1 : 0], function(err) {
        if (err) return res.status(400).json({ error: "Username exists" });
        res.json({ success: true, id: this.lastID });
    });
});

// Delete user (admin/owner)
app.delete('/api/admin/users/:id', isAdmin, (req, res) => {
    const id = req.params.id;
    if (id == req.session.userId) return res.status(400).json({ error: "Cannot delete yourself" });
    db.run("DELETE FROM users WHERE id = ?", [id]);
    res.json({ success: true });
});

// Update user balance (admin/owner)
app.post('/api/admin/users/:id/balance', isAdmin, (req, res) => {
    const { balance } = req.body;
    db.run("UPDATE users SET balance = ? WHERE id = ?", [balance, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        res.json({ success: true });
    });
});

// ---------- DEVICE ID & TIME API ----------
app.get('/api/india-time', (req, res) => {
    const now = new Date();
    const indiaTime = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));
    res.json({ time: indiaTime.toISOString(), running: "Shree Krishna Mod Active" });
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Shree Krishna Mod Server on http://localhost:${PORT}`);
    console.log(`Owner: pushkar2006 / 8788296319`);
});
