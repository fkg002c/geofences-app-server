const admin = require('firebase-admin');
const path = require('path');

let messagingInstance = null;

try {
//  // FIREBASE_SERVICE_FILE mode
//  const configPath = path.resolve(process.env.FIREBASE_SERVICE_FILE);
//  if (!configPath) {
//    throw new Error("Environment variable FIREBASE_SERVICE_FILE is not set!");
//  }
//  const serviceAccount = require(configPath);

  // FIREBASE_SERVICE_ACCOUNT mode
  const serviceAccountRaw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!serviceAccountRaw) {
    throw new Error("Environment variable FIREBASE_SERVICE_ACCOUNT is not set!");
  }
  const serviceAccount = JSON.parse(serviceAccountRaw);

  const app = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });

  // Getting an instance for working with push messages
  messagingInstance = admin.messaging(app);

  console.log("=====================================================");
  console.log("Firebase Admin SDK successfully initialized via Env!");
  console.log("=====================================================");
} catch (error) {
  console.error("========================================================");
  console.error("Firebase Admin SDK initialization error:", error.message);
  console.error("========================================================");
}

// Exporting an instance for sending messages
module.exports = messagingInstance;
