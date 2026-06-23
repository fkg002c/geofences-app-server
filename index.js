const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Настройка подключения к PostgreSQL из переменных окружения Docker
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Доступ запрещен. Токен отсутствует.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Невалидный токен.' });
    req.user = user;
    next();
  });
};

// 1. РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: 'Ошибка регистрации. Возможно, имя или email уже заняты.' });
  }
});

// 2. АВТОРИЗАЦИЯ (ВХОД)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера при авторизации.' });
  }
});

// 3. ОТПРАВКА СООБЩЕНИЯ (Защищенный маршрут)
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { content } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO messages (sender_id, content) VALUES ($1, $2) RETURNING *',
      [req.user.id, content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Не удалось отправить сообщение.' });
  }
});

// 4. ПОЛУЧЕНИЕ СПИСКА СООБЩЕНИЙ (Защищенный маршрут)
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.id, m.content, m.created_at, u.username as sender 
      FROM messages m 
      JOIN users u ON m.sender_id = u.id 
      ORDER BY m.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Не удалось получить сообщения.' });
  }
});

const PORT = 3000;
// Важно: биндим к 127.0.0.1
app.listen(PORT, '0.0.0.0', () => {
  console.log(`REST API запущен на порту ${PORT}`);
});
