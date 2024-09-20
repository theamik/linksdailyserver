
import express from "express";

const router = express.Router();

// controllers
import {
  signup,
  signin,
  forgotPassword,
  resetPassword,
} from "../controllers/auth.js";

router.get("/", (req, res) => {
  return res.json({
    data: "hello world from kaloraat auth API",
  });
});
router.post("/signup", signup);
router.post("/signin", signin);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

export default router;
