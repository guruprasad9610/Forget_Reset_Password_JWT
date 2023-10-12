import jwt from 'jsonwebtoken';
import { CreateError } from './error.js';


// Verify The JWT token
export const verifyToken = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token)
        return next(CreateError(401, "You are not Authorized"));
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err)
        {
            return next(CreateError(403, "Token is invalid"));
        }
        else
        {
            res.user = user;
        }
        next();
    })
}

// Verify The User
export const verifyUser = (req, res, next) => {
    verifyToken(req, res, () => {
        if(res.user.id === req.params.id || res.user.isAdmin)
        {
            next();
        }
        else
        {
            return next(CreateError(403, "You are not Authorized"));
        }
    })
}

// Verify The Admin
export const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        console.log(res.user);
        if(res.user.isAdmin)
        {
            next();
        }
        else
        {
            return next(CreateError(403, "You are not Authorized"));
        }
    })
}