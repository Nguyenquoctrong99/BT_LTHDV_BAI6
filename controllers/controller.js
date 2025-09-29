import mongoose from "mongoose";
import User from "../models/userModel.js";
import bcrypt from "bcrypt";
import { transporter } from "../config/nodemailerConfig.js";
import dotenv from "dotenv";

dotenv.config();

// ✅ Hàm verify reCAPTCHA
const verifyRecaptcha = async (token) => {
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;

  const response = await fetch(
    "https://www.google.com/recaptcha/api/siteverify",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${secretKey}&response=${token}`,
    }
  );

  const data = await response.json();
  return data.success;
};

export class UserGetController {
  getSignUpPage = (req, res) => {
    res.render("signup", {
      message: "",
      sitekey: process.env.RECAPTCHA_SITE_KEY,
    });
  };

  getSignInPage = (req, res) => {
    res.render("signin", {
      message: "",
      sitekey: process.env.RECAPTCHA_SITE_KEY,
    });
  };

  homePage = (req, res) => {
    const email = req.session.userEmail;
    if (!email) {
      return res
        .status(404)
        .render("signin", { message: "Please sign in to view the homepage" });
    }
    res.render("homepage");
  };

  getForgotPassword = (req, res) => {
    res.render("forgot-password", {
      message: "",
      sitekey: process.env.RECAPTCHA_SITE_KEY,
    });
  };

  getChangePassword = (req, res) => {
    const email = req.session.userEmail;
    if (!email) {
      return res.status(404).render("signin", {
        message: "Please sign in to change the password",
      });
    }
    res.render("change-password", {
      message: "",
      sitekey: process.env.RECAPTCHA_SITE_KEY,
    });
  };

  logoutUser = (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error("Error signing out:", err);
        res.status(500).send("Error signing out");
      } else {
        res.status(201).render("signin", {
          message: "user logout",
          sitekey: process.env.RECAPTCHA_SITE_KEY,
        });
      }
    });
  };
}

export class UserPostController {
  //sign up
  createUser = async (req, res) => {
    const {
      username,
      email,
      password,
      cpassword,
      "g-recaptcha-response": token,
    } = req.body;

    // ✅ Check captcha
    const isHuman = await verifyRecaptcha(token);
    if (!isHuman) {
      return res
        .status(400)
        .render("signup", { message: "Captcha verification failed" });
    }

    if (password !== cpassword) {
      return res
        .status(400)
        .render("signup", { message: "Passwords don't match" });
    }

    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res
        .status(400)
        .render("signup", { message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    try {
      await newUser.save();
      res.status(201).render("signin", {
        message: "User created successfully",
        sitekey: process.env.RECAPTCHA_SITE_KEY,
      });
    } catch (error) {
      res.status(409).json({ message: error.message });
    }
  };

  //sign in
  signInUser = async (req, res) => {
    const { email, password, "g-recaptcha-response": token } = req.body;

    // ✅ Check captcha
    const isHuman = await verifyRecaptcha(token);
    if (!isHuman) {
      return res.status(400).render("signin", {
        message: "Captcha verification failed",
        sitekey: process.env.RECAPTCHA_SITE_KEY,
      });
    }

    try {
      const existingUser = await User.findOne({ email: email });

      if (!existingUser)
        return res.status(404).render("signin", {
          message: "User doesn't exist",
          sitekey: process.env.RECAPTCHA_SITE_KEY,
        });

      const isPasswordCorrect = await bcrypt.compare(
        password,
        existingUser.password
      );

      if (!isPasswordCorrect)
        return res.status(400).render("signin", {
          message: "Invalid credentials || Incorrect Password",
          sitekey: process.env.RECAPTCHA_SITE_KEY,
        });

      req.session.userEmail = email;
      res.redirect("/user/homepage");
    } catch (error) {
      res.status(500).render("signin", { 
      message: error.message,
      sitekey: process.env.RECAPTCHA_SITE_KEY,
      });
    }
  };

  //forgot password
  forgotPassword = async (req, res) => {
    const { email, "g-recaptcha-response": token } = req.body;

    // ✅ Check captcha
    const isHuman = await verifyRecaptcha(token);
    if (!isHuman) {
      return res
        .status(400)
        .render("forgot-password", { message: "Captcha verification failed" });
    }

    try {
      const existingUser = await User.findOne({ email: email });
      if (!existingUser)
        return res
          .status(404)
          .render("forgot-password", { message: "User doesn't exist" });

      const newPassword = Math.random().toString(36).slice(-8);
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      try {
        await transporter.sendMail({
          from: process.env.EMAIL,
          to: email,
          subject: "Password Reset",
          text: `Your new password is: ${newPassword}`,
        });
      } catch (error) {
        console.log(error);
        return res
          .status(404)
          .render("forgot-password", { message: "Not valid Email" + error });
      }

      existingUser.password = hashedPassword;
      await existingUser.save();

      res
        .status(201)
        .render("signin", {
          message: "New Password sent to your email",
          sitekey: process.env.RECAPTCHA_SITE_KEY,
        });
    } catch (error) {
      res.status(500).render("forgot-password", { message: error.message });
    }
  };

  //change password
  changePassword = async (req, res) => {
    const {
      oldPassword,
      newPassword,
      "g-recaptcha-response": token,
    } = req.body;

    // ✅ Check captcha
    const isHuman = await verifyRecaptcha(token);
    if (!isHuman) {
      return res
        .status(400)
        .render("change-password", { message: "Captcha verification failed" });
    }

    try {
      const email = req.session.userEmail;
      const existingUser = await User.findOne({ email: email });
      if (!existingUser)
        return res
          .status(404)
          .render("change-password", { message: "User doesn't exist" });

      const isPasswordCorrect = await bcrypt.compare(
        oldPassword,
        existingUser.password
      );
      if (!isPasswordCorrect)
        return res
          .status(400)
          .render("change-password", { message: "Invalid credentials" });

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      existingUser.password = hashedPassword;
      await existingUser.save();
      res.status(201).render("signin", {
        message: "Password changed successfully",
        sitekey: process.env.RECAPTCHA_SITE_KEY,
      });
    } catch (error) {
      res.status(500).render("change-password", { message: error.message });
    }
  };
}
