import express from "express";

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.json({
    name: "TradeZora Backend",
    status: "online",
    message: "TradeZora backend is running."
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok"
  });
});

app.listen(PORT, () => {
  console.log(`TradeZora backend running on port ${PORT}`);
});
