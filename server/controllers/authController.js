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
        })

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
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

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

        user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save();

        // Sending Otp via Email
        const mailOptions = {
            from: "Promise Digitals" + "<" + process.env.SENDER_EMAIL + ">",
            to: user.email,
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

// Verify user email
export const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body;

    if (!userId || !otp) {
        return res.json({
            success: false,
            message: "Missing Details"
        }) 
    }

    try {

        const user = await userModel.findById(userId)

        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            }) 
        }

        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({
                success: false,
                message: "Invalid OTP"
            }) 
        }


        if (user.verifyOtpExpiredAt < Date.now()) {
            return res.json({
                success: false,
                message: "OTP expired"
            }) 
        }
        
        user.isVerified = true;

        user.verifyOtp = '',
        user.verifyOtpExpiredAt = 0

        await user.save();

        return res.json({
            success: true,
            message: "Email verified successfully"
        }) 
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}

// Check if user is authenticated
export const isAuthenticated = async (req, res) => {

    try {
        return res.json({
            success: true,
            message: "You are authenticated"
        });
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}

// Send Password reset OTP
export const sendResetOtp = async (req, res) => {
    const {email} = req.body;

    if (!email) {
        return res.json({
            success: false,
            message: "Email is required"
        }) 
    }

    try {
        
        const user = await userModel.findOne({email});

        if (!user) {
            return res.json({
                success: false,
                message: "User not found"
            }) 
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;

        user.resetOtpExpiredAt = Date.now() + 15 * 60 * 1000

        await user.save();

        // Sending Otp via Email
        const mailOptions = {
            from: "Promise Digitals" + "<" + process.env.SENDER_EMAIL + ">",
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP is ${otp}. reset your password using this OTP`
        }

        await transporter.sendMail(mailOptions)

        return res.json({
            success: true,
            message: "OTP sent to your email"
        })
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}


// Reset User Password
export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({
            success: false,
            message: "Email, OTP and new password are required"
        }) 
    }

    try {
        const user = await userModel.findOne({email});

    if (!user) {
        return res.json({
            success: false,
            message: "User not found"
        }) 
    }

    if (user.resetOtp === "" || user.resetOtp !== otp) {
        return res.json({
            success: false,
            message: "Invalid OTP"
        }) 
    }

    if (user.resetOtpExpiredAt < Date.now()) {
        return res.json({
            success: false,
            message: "OTP expired"
        }) 
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;

    user.resetOtp = "";
    user.resetOtpExpiredAt = 0;

    await user.save();

    return res.json({
        success: true,
        message: "Password resetted successfully"
    }) 
    
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}