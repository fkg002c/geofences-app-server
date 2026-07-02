require('dotenv').config(); // Обязательно должна быть на самой первой строчке!
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

//// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Извлекаем сам токен после "Bearer "

  if (!token) return res.status(401).json({ error: 'Доступ запрещен' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Токен невалиден' });
    req.user = user; // Теперь в req.user.id лежит ID авторизованного пользователя
    next();
  });
};
//function authenticateToken(req, res, next) {
//};

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
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // 1. Твоя логика проверки пользователя в БД (пример):
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    // Данные, которые будут зашиты внутрь токена
    const userPayload = { id: user.id, username: user.username };

    // 2. Создаем Access Token (время жизни 15 минут — '15m')
    const accessToken = jwt.sign(
      userPayload,
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '15m' }
    );

    // 3. Создаем Refresh Token (время жизни 7 дней — '7d')
    const refreshToken = jwt.sign(
      userPayload,
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    // 4. Опционально: Сохраняем refreshToken в базу данных к этому пользователю,
    // чтобы в будущем его можно было валидировать или отозвать (разлогинить)
    // await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

    // 5. Отправляем ОБА токена клиенту в формате JSON (это состыкуется с нашей LoginResponse в Android)
    res.json({
      id: user.id,
      accessToken,
      refreshToken
    });

  } catch (err) {
    console.error(err);
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

// REFRESH TOKEN
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh токен отсутствует.' });
  }

  try {
    // Проверяем валидность и срок годности Refresh токена
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decodedPayload) => {
      if (err) {
        return res.status(403).json({ error: 'Refresh токен просрочен или изменен.' });
      }

      // Если всё ок, генерируем новый чистый Access Token
      const newAccessPayload = { id: decodedPayload.id, username: decodedPayload.username };

      const newAccessToken = jwt.sign(
        newAccessPayload,
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
      );

      // Отправляем новый токен в Android-приложение (состыкуется с TokenResponse)
      res.json({ accessToken: newAccessToken });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка при обновлении токена.' });
  }
});

const PORT = 3000;
// Важно: биндим к 127.0.0.1
app.listen(PORT, '0.0.0.0', () => {
  console.log("Ключ доступа:", process.env.ACCESS_TOKEN_SECRET.slice(0, 7) + "...");
  console.log("Ключ доступа:", process.env.REFRESH_TOKEN_SECRET.slice(0, 7) + "...");
  console.log(`REST API запущен на порту ${PORT}`);
});
