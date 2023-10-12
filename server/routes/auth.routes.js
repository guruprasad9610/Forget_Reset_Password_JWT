import express from 'express';
import { login, registerAdmin, registerUser, resetPassword, sendEmail } from '../controllers/auth.controller.js';

const router = express.Router();

//Register a User
router.post("/register", registerUser);

//Register as Admin
router.post("/registerAdmin", registerAdmin);

//Login a User
router.post("/login", login);

//Send Email for forget password
router.post("/sendEmail", sendEmail);

//Reset Password
router.post("/resetPassword", resetPassword);

export default router;