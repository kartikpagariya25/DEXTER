// GreenLeaf Bank -- internal API server
// DEMO APPLICATION ONLY. Deliberately vulnerable for security-tooling demos.
// Do not deploy. Do not reuse these patterns.

const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database(":memory:");

app.use(express.json());

// Gap: CORS reflects any HTTPS origin while allowing credentials.
app.use(cors({ origin: "*" }));

const DEBUG = true;

app.get("/api/accounts", (req, res) => {
  const userId = req.query.id;
  // Gap: SQL built via string concatenation, not parameterized.
  const query = "SELECT * FROM accounts WHERE user_id=" + userId;
  db.all(query, (err, rows) => {
    res.json(rows);
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  // Gap: JWT signed with a hardcoded literal secret, not an env-loaded key.
  const token = jwt.sign({ username }, "greenleaf-static-signing-key-2024");
  res.json({ token });
});

app.post("/api/support/run-diagnostic", (req, res) => {
  const { hostname } = req.body;
  // Gap: dynamic command execution on user-controlled input.
  const { exec } = require("child_process");
  exec("ping -c 1 " + hostname, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000, () => console.log(`GreenLeaf API running, debug=${DEBUG}`));
