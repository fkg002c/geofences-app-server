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
  const { content, receiverId } = req.body;

  if (!content || !receiverId) {
    return res.status(400).json({ error: 'Заполните текст сообщения и получателя.' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, receiverId, content]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    // Код ошибки '23503' в Postgres означает нарушение внешнего ключа (foreign key violation)
    if (err.code === '23503') {
      return res.status(404).json({ error: 'Получатель с таким ID не найден.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Не удалось отправить сообщение.' });
  }
});

// 4. ПОЛУЧЕНИЕ СПИСКА СООБЩЕНИЙ (Защищенный маршрут)
app.get('/api/messages', authenticateToken, async (req, res) => {
  const { chatWith } = req.query; // Получаем ID собеседника из URL, например: /api/messages?chatWith=5
  const currentUserId = req.user.id;

  try {
    let result;

    if (chatWith) {
      // История конкретного диалога (я отправил ему ИЛИ он отправил мне)
      result = await pool.query(`
        SELECT id, sender_id, receiver_id, content, is_read, created_at
        FROM messages
        WHERE (sender_id = $1 AND receiver_id = $2)
           OR (sender_id = $2 AND receiver_id = $1)
        ORDER BY created_at ASC
      `, [currentUserId, chatWith]); // Для чата удобнее старые сообщения сверху (ASC)
    } else {
      // Общая история всех сообщений пользователя
      result = await pool.query(`
        SELECT id, sender_id, receiver_id, content, is_read, created_at
        FROM messages
        WHERE sender_id = $1 OR receiver_id = $1
        ORDER BY created_at DESC
      `, [currentUserId]);
    }

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось получить сообщения.' });
  }
});

// 5. Получение списка пользователей с id
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // Выбираем только безопасные поля, исключая текущего пользователя
    const result = await pool.query(
      'SELECT id, username FROM users WHERE id != $1 ORDER BY username ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось получить список пользователей.' });
  }
});

// 6. Отметить сообщения от конкретного пользователя как прочитанные
app.put('/api/messages/read', authenticateToken, async (req, res) => {
  const { fromUserId } = req.body; // ID того, чьи сообщения мы прочитали

  if (!fromUserId) {
    return res.status(400).json({ error: 'Укажите ID собеседника.' });
  }

  try {
    // Меняем статус на TRUE только для входящих сообщений от этого автора
    await pool.query(`
      UPDATE messages
      SET is_read = TRUE
      WHERE receiver_id = $1 AND sender_id = $2 AND is_read = FALSE
    `, [req.user.id, fromUserId]);

    res.json({ success: true, message: 'Сообщения отмечены как прочитанные.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Не удалось обновить статус сообщений.' });
  }
});

const PORT = 3000;
// Важно: биндим к 127.0.0.1
app.listen(PORT, '0.0.0.0', () => {
  console.log(`REST API запущен на порту ${PORT}`);
});
