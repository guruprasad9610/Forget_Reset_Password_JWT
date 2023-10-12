import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import roleRoute from './routes/manager.routes.js';
import authRoute from './routes/auth.routes.js';
import userRoute from './routes/user.routes.js';
import cookieParser from 'cookie-parser';


const app = express();
dotenv.config();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:4200',
    credentials: true
}));
app.use("/api/role", roleRoute);
app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);

//Response Handler Middleware
app.use((obj, req, res, next) => {
    const statusCode = obj.status || 500;
    const message = obj.message || "Something went wrong !!!";
    return res.status(statusCode).json({
        success: [200,201,204].some(a=> a === obj.status) ? true : false,
        status: statusCode,
        message: message,
        data : obj.data
    });
})

//DB connection
const connectMongoDB = async ()=>{
    try
    {
        await mongoose.connect(process.env.MONGO_URL);
        console.log("Connected to Database Successfully !!!");
    }
    catch(error)
    {
        throw error;
    }
}

// app.use('/api/login',(req, res)=> {
//     return res.send("<h1>LogIn Successfully !!!</h1>");
// });

// app.use('/api/signup',(req, res)=> {
//     return res.send("<h1>SignUp Successfully !!!</h1>");
// });


app.use('/',(req, res)=> {
    return res.send("<h1>Hello, Welcome to the World!!!</h1>");
});

app.listen(8800, () => {
    connectMongoDB();
    console.log("Connected to Backend Server!!!");
})