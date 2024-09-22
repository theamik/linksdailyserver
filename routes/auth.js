import express from "express";

const router = express.Router();

// controllers
import {
  signup,
  signin,
  forgotPassword,
  resetPassword,
  requireSignin,
  uploadImage,
  updatePassword,
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
router.post("/upload-image", requireSignin, uploadImage);
router.post("/update-password", requireSignin, updatePassword);

export default router;
