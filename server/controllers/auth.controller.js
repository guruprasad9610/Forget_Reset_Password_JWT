import Role from '../models/manager.model.js';
import User from '../models/user.model.js';
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { CreateSuccess } from '../utils/success.js';
import { CreateError } from '../utils/error.js';


import nodemailer from "nodemailer";
import UserToken from "../models/UserToken.js";

// Register a New User
export const registerUser = async (req, res, next) => {
    try {
        const role = await Role.find({role: 'User'});
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(req.body.password, salt);
    
        const newUser = new User(
            {
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                username: req.body.userName,
                email: req.body.email,
                password: hashPassword,
                roles: role
        });
        await newUser.save();
        return res.status(200).json("New User Registered Successfully !!!");
    }
    catch (error)
    {
        return res.status(500).json("Something Went WRONG !!!");    
    }
}

// Register an Admin
export const registerAdmin = async (req, res, next) => {
    try {
        const role = await Role.find({});
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(req.body.password, salt);
    
        const newUser = new User(
            {
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                username: req.body.userName,
                email: req.body.email,
                password: hashPassword,
                isAdmin: true,
                roles: role
        });
        await newUser.save();
        return res.status(200).json("Admin Registered Successfully");
    }
    catch (error)
    {
        return res.status(500).json("Something Went WRONG !!!");    
    }
}

// Login User & Admin both
export const login = async (req, res, next) => {
    try {
        const user = await User.findOne({email: req.body.email})
        .populate("roles","role");

        const{ roles } = user;
        if (!user) 
        {
            return res.status(404).json("User Not Found !!!");
        }
        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
        if (!isPasswordCorrect) 
        {
            return res.status(404).json("Incorrect Password !!!");
        }
        const token = jwt.sign(
            {id: user.id, isAdmin: user.isAdmin, roles: roles},
            process.env.JWT_SECRET
        )
        res.cookie("access_token", token, {httpOnly: true})
        .status(200)
        .json({
            status: 200,
            message: "User LogIn Successfully",
            data: user
        });
        // return next(CreateSuccess(200, "User LogIn Successfully"));
    }
    catch (error)
    {
        return res.status(500).json("Something Went WRONG !!!");
    }
}

// Create & Verify user to Send Email for Forget Password
export const sendEmail = async (req, res, next) => {
    const email = req.body.email;
    const user = await User.findOne({email: {$regex: '^'+email+'$', $options: 'i'}});
    if(!user)
    {
        return next(CreateError(404, "User not found to reset the email!"));
    }
    const payload = {
        email: user.email
    }
    const expiryTime = 900;
    const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn: expiryTime});

    const newToken = new UserToken({
        userId: user._id,
        token: token
    });

    const mailTransporter = nodemailer.createTransport(
    {
        service: "gmail",
        auth: 
        {
            user: "resilienteternity01@gmail.com",
            pass: "btnskfidedzzubir"
        }
    });
    let mailDetails = 
    {
        from: "resilienteternity01@gmail.com",
        subject: "Reset Password !",
        to: email,
        html: `<html>
        <head>
            <title>Password Reset Request</title>
        </head>
        <body>
            <h1>Password Reset Request</h1>
            <p>Dear ${user.username},</p>
            <p>We have received a request to reset your password for your account with My Book Store. To complete the password reset process, please click on the button below:</p>
            <a href=${process.env.LIVE_URL}/reset/${token}><button style="background-color: #4CAF50; color: white; padding: 14px 20px; border: none;
            cursor: pointer; border-radius: 4px;">Reset Password</button></a>
            <p>Please note that this link is only valid for a <b>15 minutes</b>.
            If you did not request a password reset, please ignore this message.</p>
            <p>Thank you,</p>
            <p>My Book Store Team</p>
        </body>
        </html>`,
    };

    //Send Email for Forget Password
    mailTransporter.sendMail(mailDetails, async(err, data) => {
        if(err)
        {
            console.log(err);
            return next(CreateError(500, "Something went wrong while sending the mail !!!"));
        }
        else
        {
            console.log("Email sent successfully !!!");
            await newToken.save();
            return next(CreateSuccess(200, "Email sent successfully !!!"));
        }
    });
}

// Reset Password
export const resetPassword = (req, res, next) => {
    const token = req.body.token;
    const newPassword = req.body.password;

    jwt.verify(token, process.env.JWT_SECRET, async (err, data) => {
        if (err)
        {
            return next(CreateError(500, "Password Reset Link is Expired!"));
        }
        else
        {
            const response = data;
            const user = await User.findOne({ email: { $regex: '^' + response.email + '$', $options: 'i'}});
            const salt = await bcrypt.genSalt(10);
            const encryptedPassword = await bcrypt.hash(newPassword, salt);
            user.password = encryptedPassword;
            
            try
            {
                const updatedUser = await User.findOneAndUpdate(
                { _id: user._id },
                { $set: user },
                { new: true });
                return next(CreateSuccess(200, "Password Reset Success!"));
            }
            catch (error)
            {
                return next(CreateError(500, "Something went wrong while resetting the password!"))
            }
        }
    });
}