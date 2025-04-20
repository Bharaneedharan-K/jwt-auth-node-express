const User = require('../models/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

exports.register = async (req , res) => {
    const {name , email , password} = req.body;
    try{
        const exists = await User.findOne({email});
        if(exists){
            return res.status(400).json({msg : "Email already exists"})
        }
        const hashedPassword = await bcrypt.hash(password,10);
        const user = new User ({name , email , password : hashedPassword})
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch(err){
        res.status(500).json({ error: 'Registration failed' });
    }
}

exports.login = async (req,res) => {
    const {email , password} = req.body;
    try {
        const user = await User.findOne({email})
        if(!user){
            return res.status(400).json({error : "Invalid  Username"})
        }
        
        const match = await bcrypt.compare(password, user.password);
        if(!match){
            return res.status(400).json({error : "Invalid  Password"})
        }

        const token = jwt.sign({userId : user._id},process.env.JWT_SECRET , {
            expiresIn : '30m',
        })
        res.status(200).json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
}