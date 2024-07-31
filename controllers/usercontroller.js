import UserModel from '../models/User.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'


class UserController {

    /**
     * User Registration
     * */
    static userRegistration = async (req, res) => {
        const {name, email, password, tc} = req.body

        if (!name || !email || !password || tc === undefined) {
            res.send(
                {
                    status: false,
                    message: "All fields are required"
                }
            )
            return
        }

        // Check if the user is already
        const user = await UserModel.findOne({email: email})

        if (user) {
            res.send(
                {
                    status: false,
                    message: "Email already exists"
                }
            )
            return
        }

        // Encrypt Password
        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(password, salt)

        // Create new User
        const newUser = new UserModel({
            name: name,
            email: email,
            password: hashPassword,
            tc: tc
        })

        try {
            await newUser.save()
        } catch (error) {
            console.error(error)

            res.status(500)
                .send({
                    status: false,
                    message: `Server Error : ${error}`
                })
            return
        }

        // Generate JWT Token
        const token = jwt.sign({userID: newUser._id}, process.env.JWT_SECRET_KEY, {expiresIn: '5d'})

        res.status(201)
            .send({
                status: true, message: "Registration Success", token: token
            })
    }

    static userRegistration1 = async (req, res) => {
        const {name, email, password, password_confirmation, tc} = req.body
        const user = await UserModel.findOne({email: email})
        if (user) {
            res.send({"status": "failed", "message": "Email already exists"})
        } else {
            if (name && email && password && password_confirmation && tc) {
                if (password === password_confirmation) {
                    try {
                        const salt = await bcrypt.genSalt(10)
                        const hashPassword = await bcrypt.hash(password, salt)
                        const doc = new UserModel({
                            name: name,
                            email: email,
                            password: hashPassword,
                            tc: tc
                        })
                        await doc.save()
                        const saved_user = await UserModel.findOne({email: email})
                        // Generate JWT Token
                        const token = jwt.sign({userID: saved_user._id}, process.env.JWT_SECRET_KEY, {expiresIn: '5d'})
                        res.status(201).send({"status": "success", "message": "Registration Success", "token": token})
                    } catch (error) {
                        console.log(error)
                        res.send({"status": "failed", "message": "Unable to Register"})
                    }
                } else {
                    res.send({"status": "failed", "message": "Password and Confirm Password doesn't match"})
                }
            } else {
                res.send({"status": "failed", "message": "All fields are required"})
            }
        }
    }


    static userLogin = async (req, res) => {
        try {
            const {email, password} = req.body
            if (email && password) {
                const user = await UserModel.findOne({email: email})
                if (user != null) {
                    const isMatch = await bcrypt.compare(password, user.password)
                    if ((user.email === email) && isMatch) {
                        // Generate JWT Token
                        const token = jwt.sign({userID: user._id}, process.env.JWT_SECRET_KEY, {expiresIn: '15d'})
                        res.send({"status": "success", "message": "Login Success", "token": token})
                    } else {
                        res.send({"status": "failed", "message": "Email or Password is not Valid"})
                    }
                } else {
                    res.send({"status": "failed", "message": "You are not a Registered User"})
                }
            } else {
                res.send({"status": "failed", "message": "All Fields are Required"})
            }
        } catch (error) {
            console.log(error)
            res.send({"status": "failed", "message": "Unable to Login"})
        }
    }


    //middlewere
    static changeUserPassword = async (req, res) => {
        const {password, password_confirmation} = req.body
        if (password && password_confirmation) {
            if (password !== password_confirmation) {
                res.send({"status": "failed", "message": "New Password and Confirm New Password doesn't match"})
            } else {
                const salt = await bcrypt.genSalt(10)
                const newHashPassword = await bcrypt.hash(password, salt)
                await UserModel.findByIdAndUpdate(req.user._id, {$set: {password: newHashPassword}})
                res.send({"status": "success", "message": "Password changed succesfully"})
            }
        } else {
            res.send({"status": "failed", "message": "All Fields are Required"})
        }
    }
    static loggedUser = async (req, res) => {
        res.send({"user": req.user})
    }

    static sendUserPasswordResetEmail = async (req, res) => {
        const {email} = req.body
        if (email) {
            const user = await UserModel.findOne({email: email})
            if (user) {
                const secret = user._id + process.env.JWT_SECRET_KEY
                const token = jwt.sign({userID: user._id}, secret, {expiresIn: '40m'})
                const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`
                console.log(link)

                res.send({"status": "success", "message": "Password Reset Email Sent... Please Check Your Email"})
            } else {
                res.send({"status": "failed", "message": "Email doesn't exists"})
            }
        } else {
            res.send({"status": "failed", "message": "Email Field is Required"})
        }
    }
    static userPasswordReset = async (req, res) => {
        const {password, password_confirmation} = req.body
        const {id, token} = req.params
        const user = await UserModel.findById(id)
        const new_secret = user._id + process.env.JWT_SECRET_KEY
        try {
            jwt.verify(token, new_secret)
            if (password && password_confirmation) {
                if (password !== password_confirmation) {
                    res.send({"status": "failed", "message": "New Password and Confirm New Password doesn't match"})
                } else {
                    const salt = await bcrypt.genSalt(10)
                    const newHashPassword = await bcrypt.hash(password, salt)
                    await UserModel.findByIdAndUpdate(user._id, {$set: {password: newHashPassword}})
                    res.send({"status": "success", "message": "Password Reset Successfully"})
                }
            } else {
                res.send({"status": "failed", "message": "All Fields are Required"})
            }
        } catch (error) {
            console.log(error)
            res.send({"status": "failed", "message": "Invalid Token"})
        }
    }
}

export default UserController
