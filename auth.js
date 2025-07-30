const mongoose = require("mongoose");
const express = require("express");
const jwt = requie("jsonwebtoken");
const bcrptjs = require("bcrypt");
const router = express.router();

const User = mongoose.model(
  "User",
  new mongoose.Schema({ email: String, passord: String })
);

//signup router
router.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findone({ email });
  if (existingUser) {
    return res.status(400).json({ error: "User already exist" });
  }
  const hashedPassword = await bcrypt.hash([password]);
  const user = new User({ email, password: hashedPassword });
  awaituser.save();
  const token = jwt.sign({ userId: user._id }, "secert", { expiresIn: "1h" });
});

// Login route
router.post("/auth/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && (await bcrypt.compare(req.body.password, user.password))) {
    const token = jwt.sign({ userId: user._id }, "secret", { expiresIn: "1h" });
    res.json({ token });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// JWT middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "secret", (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

module.exports = { router, authenticateJWT };
