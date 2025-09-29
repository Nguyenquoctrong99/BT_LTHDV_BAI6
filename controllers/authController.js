import User from "../models/userModel.js"; // User model
import bcrypt from "bcrypt"; // Để hash password từ Google ID

// Controller class for handling Google Sign In
export class googleSignInController {
  // ====== Khi login thành công ======
  signInSuccess = async (req, res) => {
    try {
      if (!req.user || !req.user._json) {
        return res
          .status(403)
          .json({ error: true, message: "Not Authorized (no user data)" });
      }

      const userData = req.user._json;
      const { email, name, sub } = userData;

      if (!email) {
        return res
          .status(403)
          .json({ error: true, message: "Google account has no email" });
      }

      // Tìm user theo email
      let user = await User.findOne({ email });

      if (!user) {
        // Nếu chưa có user → tạo mới
        const hashedPassword = await bcrypt.hash(sub, 10); // hash Google ID
        user = new User({
          username: name,
          email: email,
          password: hashedPassword,
        });
        await user.save();
      }

      // Lưu session
      req.session.userEmail = email;

      // Redirect hoặc render
      return res.status(200).render("homepage", {
        message: `Welcome ${user.username || "User"}!`,
      });
    } catch (error) {
      console.error("Google Sign-In Error:", error);
      return res.status(500).json({
        error: true,
        message: "Internal Server Error during Google Sign-In",
      });
    }
  };

  // ====== Khi login thất bại ======
  signInFailed = (req, res) => {
    return res.status(401).json({
      error: true,
      message: "Google login failed",
    });
  };
}
