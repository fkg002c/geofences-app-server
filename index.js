require('dotenv').config(); // It must definitely be on the very first line!
const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const messaging = require('./firebase');

const app = express();
app.use(express.json());

// Configuring a PostgreSQL Connection from Docker Environment Variables
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// JWT token validation middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extract the token value after "Bearer "

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'The token is invalid' });
    req.user = user; // Now req.user.id contains the ID of the authorized user.
    next();
  });
};
//function authenticateToken(req, res, next) {
//};

// 1. USER REGISTRATION
app.post('/api/register', async (req, res) => {
  const { username, email, password, firebaseUid } = req.body;
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, firebase_uid) VALUES ($1, $2, $3, $4) RETURNING id, username, email',
      [username, email, passwordHash, firebaseUid]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: 'Registration error. Your name or email address may already be taken.' });
  }
});

// 2. AUTHORIZATION (LOGIN)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // 1. Logic for checking a user in the database
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Incorrect login or password' });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect login or password' });
    }

    // Data that will be embedded in the token
    const userPayload = { id: user.id, username: user.username };

    // 2. Create an Access Token (lifetime 15 minutes - '15m'))
    const accessToken = jwt.sign(
      userPayload,
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '60m' }
    );

    // 3. Create a Refresh Token (lifetime 7 days - '7d')
    const refreshToken = jwt.sign(
      userPayload,
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '30d' }
    );

    // 4. Optional: Save the refreshToken to the database for this user
    // so that it can be validated or revoked (logged out) in the future.
    // await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

    // 5. Send BOTH tokens to the client in JSON format (this will align with our LoginResponse in Android)
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,          // <-- CRITICAL FOR ANDROID
      accessToken,
      refreshToken
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during authorization.' });
  }
});

// 3. SENDING A MESSAGE (Secure Route)
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { content, receiverId } = req.body;
  const senderId = req.user.id; // Sender ID from the JWT token

  console.log('POST /api/messages from:', senderId, "to:", receiverId, "msg:", content);

  if (!content || !receiverId) {
    return res.status(400).json({ error: 'Fill in the message text and recipient.' });
  }

  try {
    // 1. The message is saved to the main message table on the server.
    const insertQuery = `
      INSERT INTO messages (sender_id, receiver_id, content)
      VALUES ($1, $2, $3)
      RETURNING id, sender_id, receiver_id, content, created_at;
    `;
    const messageResult = await pool.query(insertQuery, [senderId, receiverId, content]);
    const savedMessage = messageResult.rows[0];

    // 2. Looking for the fcm_token (or installationId) of the message RECIPIENT in the users table
    const userQuery = 'SELECT fcm_token, username FROM users WHERE id = $1';
    const userResult = await pool.query(userQuery, [receiverId]);
    const receiverToken = userResult.rows[0]?.fcm_token;

    // 3. If the recipient has a linked token, trying to send a push notification.
    if (receiverToken) {

      // IMPORTANT: All values inside the data object MUST be Strings!
      // The Firebase Admin SDK will not accept numbers (Int) or dates (Date) directly.
      const payload = {
        data: {
          id: String(savedMessage.id),
          senderId: String(savedMessage.sender_id),
          senderName: String(userResult.rows[0]?.username),
          receiverId: String(savedMessage.receiver_id),
          content: String(savedMessage.content),
          createdAt: String(savedMessage.created_at.toISOString())
        },
        token: receiverToken
      };

      console.log("FCM payload:", payload);

      // Sending a message via Firebase
      messaging.send(payload)
        .then((response) => {
          console.log('Successfully sent push message:', response);
        })
        .catch((error) => {
          console.error('Error sending push message:', error);
          // If a token is expired or invalid, it's a good practice to reset it
          // in the database to avoid spamming Firebase with requests.
          if (error.code === 'messaging/invalid-argument' || error.code === 'messaging/registration-token-not-registered') {
             pool.query('UPDATE users SET fcm_token = NULL WHERE id = $1', [receiverId]);
          }
        });
    }

    // 4. We return a successful response to the sender.
    return res.status(201).json(savedMessage);

  } catch (err) {
    console.error('Error sending message:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;


// 4. RECEIVING A LIST OF MESSAGES (Secure Route)
app.get('/api/messages', authenticateToken, async (req, res) => {
  const { chatWith } = req.query; // Getting the interlocutor's ID from the URL, for example: /api/messages?chatWith=5
  const currentUserId = req.user.id;

  try {
    let result;

    if (chatWith) {
      // History of a specific dialogue (I sent it to him OR he sent it to me)
      result = await pool.query(`
        SELECT id, sender_id, receiver_id, content, is_read, created_at
        FROM messages
        WHERE (sender_id = $1 AND receiver_id = $2)
           OR (sender_id = $2 AND receiver_id = $1)
        ORDER BY created_at ASC
      `, [currentUserId, chatWith]); // For chat, it's more convenient to have older messages on top (ASC)
    } else {
      // General history of all user messages
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
    res.status(500).json({ error: 'Unable to receive messages.' });
  }
});

// 5. Getting a list of users with ID
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // Selecting only required fields, excluding the current user
    const result = await pool.query(
      'SELECT id, username FROM users WHERE id != $1 ORDER BY username ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get list of users.' });
  }
});

// 6. Mark messages from a specific user as read
app.put('/api/messages/read', authenticateToken, async (req, res) => {
  const { fromUserId } = req.body; // ID of the person whose messages we read

  if (!fromUserId) {
    return res.status(400).json({ error: 'Please enter your interlocutor\'s ID.' });
  }

  try {
    // Changing the status to TRUE only for incoming messages from this user
    await pool.query(`
      UPDATE messages
      SET is_read = TRUE
      WHERE receiver_id = $1 AND sender_id = $2 AND is_read = FALSE
    `, [req.user.id, fromUserId]);

    res.json({ success: true, message: 'Messages are marked as read.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update message status.' });
  }
});

// REFRESH TOKEN
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token is missing.' });
  }

  try {
    // Checking the validity and expiration date of the Refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decodedPayload) => {
      if (err) {
        return res.status(403).json({ error: 'Refresh token has expired or has been changed.' });
      }

      // If everything is ok, we generate a new clean Access Token.
      const newAccessPayload = { id: decodedPayload.id, username: decodedPayload.username };

      const newAccessToken = jwt.sign(
        newAccessPayload,
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
      );

      // Send a new token to the Android app (will be paired with TokenResponse)
      res.json({ accessToken: newAccessToken });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error token updating .' });
  }
});

// FCM token update
app.post('/api/auth/fcm-token', authenticateToken, async (req, res) => {
    const { fcmToken } = req.body;
    const userId = req.user.id;

    // Token validation
    if (!fcmToken) {
        return res.status(400).json({ error: 'fcmToken is required' });
    }

    try {
        // Updating fcm_token for a specific user
        const query = `
            UPDATE users
            SET fcm_token = $1
            WHERE id = $2
        `;
        const values = [fcmToken, userId];

        await pool.query(query, values);

        // Return HTTP 200 OK without a body, as expected by Retrofit Response<Unit>
        return res.status(200).send();

    } catch (error) {
        console.error('Error updating FCM token:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// LOGOUT
router.post('/api/auth/logout', authenticateToken, async (req, res) => {
    const userId = req.user.id;

    console.log(`POST /api/auth/logout from userId: ${userId}`);

    try {
        // Erase the token so that the Firebase Admin SDK no longer sends notifications to this device.
        await pool.query('UPDATE users SET fcm_token = NULL WHERE id = $1', [userId]);

        return res.status(200).send();
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = 3000;
// Important: bind to 127.0.0.1
app.listen(PORT, '0.0.0.0', async () => {
  console.log(" ACCESS_TOKEN_SECRET:", process.env.ACCESS_TOKEN_SECRET.slice(0, 7) + "...");
  console.log("REFRESH_TOKEN_SECRET:", process.env.REFRESH_TOKEN_SECRET.slice(0, 7) + "...");
  console.log(`REST API is running on port ${PORT}`);
  await sendServerStatusPush('start');
});

async function sendServerStatusPush(status) {
  const message = {
    data: {
      type: 'SERVER_STATUS',
      status: status
    },
    android: {
      priority: "high",
      ttl: status === 'start' ? 60 * 60 * 1000 : 5 * 60 * 1000
    },
    topic: 'server_status'
  };

  await messaging.send(message);
}

let isShuttingDown = false;

async function handleShutdown(signal) {
  if (isShuttingDown) {
    console.log(`Signal ${signal} received. Notifying users...`);
    return;
  }

  console.log(`Получен сигнал ${signal}. Оповещаем клиентов...`);

  await sendServerStatusPush('stop');

  console.log("Exit the process.");
  process.exit(0);
}

// Listen for stop signals (for example, from PM2, Docker, or pressing Ctrl+C in the terminal)
process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));