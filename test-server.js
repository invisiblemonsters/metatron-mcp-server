// Minimal test to trace crash
import express from "express";

const PORT = 3402;
const app = express();

console.log("[TEST] Starting minimal server...");

app.get("/status", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`[TEST] Server on port ${PORT}`);
});

// Keep alive
setInterval(() => {}, 60000);
