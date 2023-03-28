import User from "../models/user.model.js"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import createError from "../utils/createError.js";

export const register = async (req,res, next) => {
    try {
        const hash = bcrypt.hashSync(req.body.password, 5);
        const newUser = new User({
            ...req.body,
            password: hash,
        });
    
        await newUser.save();
        res.status(201).send("User has been created.");
      } catch(err){
       next(err)

    }

   
}

export const login = async (req,res,next) => {

    try{
        const user = await User.findOne({username: req.body.username})
        
        if (!user) return next(createError(404, "User not found here"))

        const isCorrect = bcrypt.compareSync(req.body.password, user.password)
        if (!isCorrect) return next(createError(404, "Wrong password or user name"))

        const token = jwt.sign({
            id: user._id,
            isSeller : user.isSeller
        }, process.env.JWT_KEY)

        const { password, ...info } = user._doc
        // removes password from info and sends all user info to user but not password as a message
        // used _doc bc when we first did a post test, info we wanted was inside a _doc object

        // no secrets can breach data. only change it with http request. using cookeis to see if you are the seller
        // if you are logged in and seller, you can delete gigs
        res.cookie("accessToken", token, {
            httpOnly: true,
        })
        .status(200).send(info)

    } catch(err){
        next(err)

    }

   
}

// because different local host api & client so sameSite none
export const logout = (req,res) => {
    res.clearCookie("accessToken",{
        sameSite: "none",
        secure: true,
    }).status(200).send("User has been logged out")
}