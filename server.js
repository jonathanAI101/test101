const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// Database setup
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS password_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      old_password TEXT NOT NULL,
      changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

// Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// API Routes

// Register
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: '所有字段都是必需的' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: '两次输入的密码不一致' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: '密码长度必须至少6个字符' });
  }

  // Hash password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: '密码加密失败' });
    }

    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed: users.username')) {
            return res.status(400).json({ error: '用户名已存在' });
          }
          if (err.message.includes('UNIQUE constraint failed: users.email')) {
            return res.status(400).json({ error: '邮箱已被注册' });
          }
          return res.status(500).json({ error: '注册失败' });
        }

        const token = jwt.sign(
          { id: this.lastID, username },
          JWT_SECRET,
          { expiresIn: '7d' }
        );

        res.status(201).json({
          message: '注册成功',
          token,
          user: { id: this.lastID, username, email }
        });
      }
    );
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码是必需的' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: '查询失败' });
    }

    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ error: '验证失败' });
      }

      if (!isMatch) {
        return res.status(401).json({ error: '用户名或密码错误' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: '登录成功',
        token,
        user: { id: user.id, username: user.username, email: user.email }
      });
    });
  });
});

// Get current user profile
app.get('/api/auth/profile', verifyToken, (req, res) => {
  db.get('SELECT id, username, email, created_at FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(500).json({ error: '获取用户信息失败' });
    }
    res.json(user);
  });
});

// Change password
app.post('/api/auth/change-password', verifyToken, (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: '所有字段都是必需的' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: '两次输入的新密码不一致' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: '新密码长度必须至少6个字符' });
  }

  db.get('SELECT password FROM users WHERE id = ?', [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(500).json({ error: '用户不存在' });
    }

    bcrypt.compare(oldPassword, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ error: '验证失败' });
      }

      if (!isMatch) {
        return res.status(401).json({ error: '原密码错误' });
      }

      // Save old password to history
      db.run(
        'INSERT INTO password_history (user_id, old_password) VALUES (?, ?)',
        [req.userId, user.password]
      );

      // Hash new password
      bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
          return res.status(500).json({ error: '密码加密失败' });
        }

        db.run(
          'UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
          [hashedPassword, req.userId],
          (err) => {
            if (err) {
              return res.status(500).json({ error: '修改密码失败' });
            }
            res.json({ message: '密码修改成功' });
          }
        );
      });
    });
  });
});

// Get password history
app.get('/api/auth/password-history', verifyToken, (req, res) => {
  db.all(
    'SELECT changed_at FROM password_history WHERE user_id = ? ORDER BY changed_at DESC LIMIT 5',
    [req.userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: '获取密码历史失败' });
      }
      res.json(rows || []);
    }
  );
});

// Logout (token blacklist would be needed for production)
app.post('/api/auth/logout', verifyToken, (req, res) => {
  res.json({ message: '登出成功' });
});

// Update profile
app.put('/api/auth/profile', verifyToken, (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: '邮箱是必需的' });
  }

  db.run(
    'UPDATE users SET email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [email, req.userId],
    (err) => {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed: users.email')) {
          return res.status(400).json({ error: '邮箱已被注册' });
        }
        return res.status(500).json({ error: '更新失败' });
      }
      res.json({ message: '个人信息更新成功' });
    }
  );
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: '服务器错误' });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
