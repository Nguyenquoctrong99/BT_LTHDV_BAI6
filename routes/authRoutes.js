import express from "express"; // Express router
import passport from "passport"; // Passport for authentication
import dotenv from "dotenv"; // Load environment variables
import { googleSignInController } from "../controllers/authController.js";

dotenv.config(); // Load .env file

const authRouter = express.Router();
const googleSignIn = new googleSignInController();

// ======================== GOOGLE AUTH ========================

// B1: Chuyển hướng user đến Google để login
authRouter.get(
  "/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

// B2: Google redirect về callbackURL (định nghĩa trong app.js / .env)
authRouter.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: process.env.CLIENT_URL || "/auth/login/success",
    failureRedirect: "/auth/login/failed",
  })
);

// ======================== LOGIN STATUS ========================

// Khi login thành công
authRouter.get("/login/success", googleSignIn.signInSuccess);

// Khi login thất bại
authRouter.get("/login/failed", googleSignIn.signInFailed);

// ======================== LOGOUT ========================
authRouter.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed", error: err });
    }
    req.session.destroy(() => {
      res.redirect("/user/signin"); // redirect về trang signin sau khi logout
    });
  });
});

export default authRouter;
