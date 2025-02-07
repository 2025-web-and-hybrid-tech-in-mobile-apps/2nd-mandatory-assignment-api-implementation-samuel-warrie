const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const port = process.env.PORT || 3000;
const secretKey = "supersecretkey"; // Replace with an environment variable in production

app.use(express.json()); // for parsing application/json

const users = new Map();
const highScores = [];

app.post("/signup", (req, res) => {
  const { userHandle, password } = req.body;

  if (!userHandle || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (typeof userHandle !== "string" || userHandle.trim().length < 6) {
    return res
      .status(400)
      .json({ error: "userHandle must be at least 6 characters long" });
  }
  if (typeof password !== "string" || password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters long" });
  }

  if (users.has(userHandle)) {
    return res.status(400).json({ error: "UserHandle already taken" });
  }

  users.set(userHandle, password);
  res.status(201).json({ message: "User registered successfully" });
});

app.post("/login", (req, res) => {
  const { userHandle, password, ...extraFields } = req.body;

  // Reject extra fields
  if (Object.keys(extraFields).length > 0) {
    return res.status(400).json({ error: "Unexpected fields in request body" });
  }

  if (!userHandle || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (typeof userHandle !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Invalid data type" });
  }

  if (!users.has(userHandle) || users.get(userHandle) !== password) {
    return res
      .status(401)
      .json({ error: "Unauthorized, incorrect username or password" });
  }

  const token = jwt.sign({ userHandle }, secretKey, { expiresIn: "1h" });
  res.status(200).json({ jsonWebToken: token });
});

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Unauthorized, JWT token is missing or invalid" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res
        .status(401)
        .json({ error: "Unauthorized, JWT token is invalid" });
    }
    req.user = user;
    next();
  });
};

app.post("/high-scores", authenticateJWT, (req, res) => {
  const { level, userHandle, score, timestamp } = req.body;

  if (!level || !userHandle || !score || !timestamp) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  highScores.push({ level, userHandle, score, timestamp });
  res.status(201).json({ message: "High score posted successfully" });
});

app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;
  if (!level) {
    return res.status(400).json({ error: "Level parameter is required" });
  }

  const filteredScores = highScores.filter((score) => score.level === level);
  filteredScores.sort((a, b) => b.score - a.score);
  const paginatedScores = filteredScores.slice((page - 1) * 20, page * 20);

  res.status(200).json(paginatedScores);
});

// Export the app instance but don't start it automatically
let serverInstance = null;
module.exports = {
  app,
  start: function () {
    if (!serverInstance) {
      serverInstance = app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
      });
    }
  },
  close: function () {
    if (serverInstance) {
      serverInstance.close(() => {
        console.log("Server closed.");
      });
      users;
      serverInstance = null;
    }
  },
};

// Start server only if running standalone (not during tests)
if (require.main === module) {
  module.exports.start();
}
