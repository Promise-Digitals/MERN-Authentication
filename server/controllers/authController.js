import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const register = async (req, res) => {
    const {name, email, password} = req.body;

    if (!name || !email || !password) {
        return res.json({
            success: false,
            message: "Missing Details"
        })
    }

    try {
        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({
                success: false,
                message: "User Already exists"
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const user = new userModel({name, email, password: hashedPassword})

        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        // Sending Welcome Email
        const mailOptions = {
            from: "Promise Digitals" + "<" + process.env.SENDER_EMAIL + ">",
            to: email,
            subject: 'Welcome to Promise Digitals',
            text: `Welcome to Promise Digitals, your account has been successfully created with email ID: ${email}`
        }


        await transporter.sendMail(mailOptions)


        return res.json({
            success: true
        })

        
    } catch (error) {
        res.json({
            success: false,
            message: error.message
        })
    }
}


export const login = async (req, res) => {

    const {email, password} = req.body;

    if (!email || !password) {
        return res.json({
            success: false,
            message: "Email and Password are required"
        })
    }

    try {

        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({
                success: false,
                message: "Invalid Email"
            })
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({
                success: false,
                message: "Invalid Password"
            })
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({
            success: true
        })
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}


export const logout = async (req, res) => {

    try {
        res.clearCookie('token')

        return res.json({
            success: true,
            message: "Logged Out"
        })


    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}


// Send verification OTP  to the user's Email
export const sendVerifyOtp = async (req, res) => {

    try {

        const {userId} = req.body;

        const user = await userModel.findById(userId);

        if (user.isVerified) {
            res.json({
                success: false,
                message: "Account already verified"
            })
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;

        user.verifyOtpExpiredAT = Date.now() + 24 * 60 * 60 * 1000

        await user.save();

        // Sending Otp via Email
        const mailOptions = {
            from: "Promise Digitals" + "<" + process.env.SENDER_EMAIL + ">",
            to: email,
            subject: 'Account verification OTP',
            text: `Your OTP is ${otp}. verify your account using this OTP`
        }

        await transporter.sendMail(mailOptions)

        return res.json({
            success: true,
            message: "verification OTP sent via Email"
        }) 
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}