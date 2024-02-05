const express = require("express");
const authController = require("../controllers/auth");

const router = express.Router();

router.get("/", authController.isLoggedIn, (req, res) => {
  res.render("index", {
    user: req.user,
  });
});

router.get("/register", (req, res) => {
  res.render("register");
});

router.get("/login", (req, res) => {
  res.render("login");
});

router.get("/profile", authController.isLoggedIn, (req, res) => {
  if (req.user) {
    res.render("profile", {
      user: req.user,
    });
  } else {
    res.redirect("/login");
  }
});

// Dodaj nową ścieżkę do resetowania hasła
router.get("/reset-password", authController.isLoggedIn, (req, res) => {
  res.render("reset-password", {
    user: req.user,
  });
});

router.get("/reset-password/:token", (req, res) => {
  const { token } = req.params;
  console.log("Token from URL:", token);
  authController.resetPasswordPage(req, res);
});

module.exports = router;
