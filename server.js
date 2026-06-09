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
    secret: 'shree_krishna_owner_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    // Users table: added admin_balance for admins/owner, device_limit (max devices for this user), key_expiry
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

    // Devices table to track bound devices per user
    db.run(`CREATE TABLE IF NOT EXISTS user_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        device_id TEXT UNIQUE,
        last_login DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // Keys table
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE,
        created_by INTEGER,
        balance_amount INTEGER DEFAULT 0,
        device_limit INTEGER DEFAULT 1,
        expiry_days INTEGER,
        is_used INTEGER DEFAULT 0,
        used_by_user_id INTEGER,
        used_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Key logs
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
        db.run(`INSERT INTO users (username, password, balance, admin_balance, is_admin, is_owner, device_limit)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
            ["pushkar2006", hashed, 999999, 999999, 1, 1, 100]);
        console.log("✅ Owner created: pushkar2006 / 8788296319");
    }
});

// Middleware
function isAuthenticated(req, res, next) {
    if (req.session.userId) return next();
    res.status(401).json({ error: "Not logged in" });
}
function isAdmin(req, res, next) {
    if (req.session.userId && (req.session.isAdmin || req.session.isOwner)) return next();
    res.status(403).json({ error: "Admin only" });
}
function isOwner(req, res, next) {
    if (req.session.userId && req.session.isOwner) return next();
    res.status(403).json({ error: "Owner only" });
}

// ---------- AUTH ROUTES ----------
app.post('/api/login', async (req, res) => {
    const { username, password, deviceId } = req.body;
    if (!username || !password || !deviceId) return res.status(400).json({ error: "Missing credentials or device ID" });

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Invalid username/password" });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid username/password" });

        // Check device limit
        db.all("SELECT device_id FROM user_devices WHERE user_id = ?", [user.id], (err, devices) => {
            const currentDeviceCount = devices.length;
            const isDeviceBound = devices.some(d => d.device_id === deviceId);
            if (!isDeviceBound && currentDeviceCount >= user.device_limit) {
                return res.status(403).json({ error: `Device limit reached (${user.device_limit}). Contact admin.` });
            }
            if (!isDeviceBound) {
                db.run("INSERT INTO user_devices (user_id, device_id, last_login) VALUES (?, ?, CURRENT_TIMESTAMP)", [user.id, deviceId]);
            } else {
                db.run("UPDATE user_devices SET last_login = CURRENT_TIMESTAMP WHERE user_id = ? AND device_id = ?", [user.id, deviceId]);
            }
        });

        // Check key expiry
        if (user.key_expiry && new Date(user.key_expiry) < new Date()) {
            return res.status(403).json({ error: "Your key has expired. Please contact admin." });
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
            message: "Login successful"
        });
    });
});

app.post('/api/register', async (req, res) => {
    const { username, password, deviceId, keyCode } = req.body;
    if (!username || !password || !deviceId) return res.status(400).json({ error: "Missing fields" });
    if (password.length < 4) return res.status(400).json({ error: "Password min 4 chars" });

    // Validate key
    db.get("SELECT * FROM keys WHERE key_code = ? AND is_used = 0", [keyCode], async (err, key) => {
        if (err || !key) return res.status(400).json({ error: "Invalid or already used key" });

        const hashed = await bcrypt.hash(password, 10);
        let expiryDate = null;
        if (key.expiry_days) {
            expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + key.expiry_days);
        }

        db.run(`INSERT INTO users (username, password, balance, device_limit, key_expiry)
                VALUES (?, ?, ?, ?, ?)`,
            [username, hashed, key.balance_amount, key.device_limit, expiryDate], function(err) {
            if (err) return res.status(400).json({ error: "Username exists" });

            const userId = this.lastID;
            // Bind device
            db.run("INSERT INTO user_devices (user_id, device_id) VALUES (?, ?)", [userId, deviceId]);
            // Mark key as used
            db.run("UPDATE keys SET is_used = 1, used_by_user_id = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?", [userId, key.id]);
            db.run("INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)",
                [keyCode, "used", userId, `Balance +${key.balance_amount}, Device limit ${key.device_limit}`]);
            res.json({ success: true, message: "Account created! Please login." });
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
    req.session.destroy();
    res.json({ success: true });
});

// ---------- OWNER/ADMIN KEY MANAGEMENT ----------
// Generate key (deducts from admin's balance)
app.post('/api/admin/generate-key', isAdmin, async (req, res) => {
    const { balance_amount, device_limit, expiry_days, quantity = 1 } = req.body;
    if (!balance_amount || balance_amount <= 0) return res.status(400).json({ error: "Valid balance amount required" });
    const requiredBalance = balance_amount * quantity;

    // Check admin balance
    db.get("SELECT admin_balance FROM users WHERE id = ?", [req.session.userId], (err, row) => {
        if (err || row.admin_balance < requiredBalance) {
            return res.status(400).json({ error: `Insufficient admin balance. Need ${requiredBalance}, have ${row.admin_balance}` });
        }

        const keys = [];
        const keyCodes = [];
        for (let i = 0; i < quantity; i++) {
            const keyCode = crypto.randomBytes(12).toString('hex').toUpperCase();
            keyCodes.push(keyCode);
            db.run(`INSERT INTO keys (key_code, created_by, balance_amount, device_limit, expiry_days)
                    VALUES (?, ?, ?, ?, ?)`,
                [keyCode, req.session.userId, balance_amount, device_limit || 1, expiry_days || null]);
            keys.push(keyCode);
            db.run("INSERT INTO key_logs (key_code, action, user_id, details) VALUES (?, ?, ?, ?)",
                [keyCode, "generated", req.session.userId, `Balance: ${balance_amount}, Limit: ${device_limit}`]);
        }
        // Deduct admin balance
        db.run("UPDATE users SET admin_balance = admin_balance - ? WHERE id = ?", [requiredBalance, req.session.userId]);
        if (req.session.userId) req.session.adminBalance -= requiredBalance;
        res.json({ success: true, keys });
    });
});

// Get all keys (with used by username)
app.get('/api/admin/keys', isAdmin, (req, res) => {
    db.all(`SELECT k.*, u.username as used_by_username FROM keys k
            LEFT JOIN users u ON k.used_by_user_id = u.id
            ORDER BY k.id DESC`, (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows);
    });
});

// Delete unused key (only if not used)
app.delete('/api/admin/keys/:id', isAdmin, (req, res) => {
    const id = req.params.id;
    db.get("SELECT is_used FROM keys WHERE id = ?", [id], (err, key) => {
        if (key && key.is_used) return res.status(400).json({ error: "Cannot delete used key" });
        db.run("DELETE FROM keys WHERE id = ?", [id]);
        res.json({ success: true });
    });
});

// ---------- USER MANAGEMENT (Admin & Owner) ----------
app.get('/api/admin/users', isAdmin, (req, res) => {
    db.all("SELECT id, username, balance, is_admin, is_owner, device_limit, key_expiry, created_at FROM users", (err, rows) => {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json(rows);
    });
});

// Add user (admin can add normal users, only owner can add admins)
app.post('/api/admin/users', isAdmin, async (req, res) => {
    const { username, password, balance, is_admin } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });
    if (is_admin && !req.session.isOwner) return res.status(403).json({ error: "Only owner can create admins" });

    const hashed = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)",
        [username, hashed, balance || 0, is_admin ? 1 : 0], function(err) {
        if (err) return res.status(400).json({ error: "Username exists" });
        res.json({ success: true, id: this.lastID });
    });
});

// Delete user (admin can delete normal users, owner can delete any except self)
app.delete('/api/admin/users/:id', isAdmin, (req, res) => {
    const id = req.params.id;
    if (id == req.session.userId) return res.status(400).json({ error: "Cannot delete yourself" });
    // Only owner can delete admin users
    db.get("SELECT is_admin FROM users WHERE id = ?", [id], (err, user) => {
        if (user && user.is_admin && !req.session.isOwner) {
            return res.status(403).json({ error: "Only owner can delete admins" });
        }
        db.run("DELETE FROM users WHERE id = ?", [id]);
        db.run("DELETE FROM user_devices WHERE user_id = ?", [id]);
        res.json({ success: true });
    });
});

// Reset user password (admin/owner)
app.post('/api/admin/users/:id/reset-password', isAdmin, async (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: "Password min 4 chars" });
    const hashed = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hashed, req.params.id]);
    res.json({ success: true });
});

// Update user balance (admin can update any user's balance)
app.post('/api/admin/users/:id/balance', isAdmin, (req, res) => {
    const { balance } = req.body;
    db.run("UPDATE users SET balance = ? WHERE id = ?", [balance, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        res.json({ success: true });
    });
});

// Owner only: add admin balance (replenish)
app.post('/api/owner/add-admin-balance', isOwner, (req, res) => {
    const { userId, amount } = req.body;
    if (!userId || amount <= 0) return res.status(400).json({ error: "Invalid" });
    db.run("UPDATE users SET admin_balance = admin_balance + ? WHERE id = ?", [amount, userId], (err) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        res.json({ success: true });
    });
});

// Owner only: promote/demote admin
app.post('/api/owner/set-admin', isOwner, (req, res) => {
    const { userId, isAdmin } = req.body;
    db.get("SELECT is_owner FROM users WHERE id = ?", [userId], (err, user) => {
        if (user && user.is_owner) return res.status(400).json({ error: "Cannot change owner" });
        db.run("UPDATE users SET is_admin = ? WHERE id = ?", [isAdmin ? 1 : 0, userId]);
        res.json({ success: true });
    });
});

// Get devices of a user (admin/owner)
app.get('/api/admin/users/:id/devices', isAdmin, (req, res) => {
    db.all("SELECT device_id, last_login FROM user_devices WHERE user_id = ?", [req.params.id], (err, rows) => {
        res.json(rows);
    });
});

// ---------- UTILITIES ----------
app.get('/api/india-time', (req, res) => {
    const now = new Date();
    const indiaTime = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));
    res.json({ time: indiaTime.toISOString(), running: "Shree Krishna Mod Active" });
});

app.listen(PORT, () => {
    console.log(`🚀 Shree Krishna Mod Server on http://localhost:${PORT}`);
    console.log(`👑 Owner: pushkar2006 / 8788296319`);
});
