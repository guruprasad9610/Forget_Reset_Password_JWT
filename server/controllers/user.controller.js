import User from "../models/user.model.js";
import { CreateError } from "../utils/error.js"
import { CreateSuccess } from "../utils/success.js";


// View All Users
export const getAllUsers = async (req, res, next) => {
    try {
        const users = await User.find();
        return next(CreateSuccess(200, "All Users details", users));
    }
    catch (error) {
        return next(CreateError(500, "Internal Server Error !!!"));
    }
}

// View a Single User by ID
export const getById = async (req, res, next) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user)
        {
            return next(CreateError(404, "User not found !!!"));
        }
        else
        {
            return next(CreateSuccess(200, "A Single User's details", user));
        }
    } 
    catch (error) {
        return next(CreateError(500, "Internal Server Error !!!"));
    }
}