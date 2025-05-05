const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const saltRounds = 10;
const JWT_SECRET = "mysecret123";
const app = express();
const port = 3000;
mongoose.connect("mongodb://localhost:27017/login");

//nodemon ./login_register/main.js

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
})

app.use(express.json());

const newSchema = new mongoose.Schema({
    username: String,
    password: String,
    isLoggedIn: { type: Boolean, default: false }
})

const newUser = mongoose.model("newUser", newSchema);

app.post('/register', async (req, res) => {
    try {
        const data = req.body;

        if (!data.username || !data.password) {
            return res.status(400).json({ error: "Username and password are required" });
        }

        const hashedPassword = await bcrypt.hash(data.password, saltRounds);

        const newRegister = new newUser({
            username: data.username,
            password: hashedPassword,
        })

        let registered = await newRegister.save();

        res.json({ message: "Registered Successfully!", username: registered.username });
    }
    catch (err) {
        console.log("Registration Error", err);
        res.json({ err: "Error occured" });
    }
})

app.post('/login', async (req, res) => {
    try {
        const data = req.body;
        const user = await newUser.findOne({ username: data.username });

        if (!user) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const passwordMatch = await bcrypt.compare(data.password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        //Created JWT token
        const token = jwt.sign(
            { username: user.username },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        user.isLoggedIn = true;
        await user.save();

        res.json({ message: 'Logged in successfully', token });

    }
    catch (err) {
        res.status(500).json({ err: "Error occured" });
    }
})

app.post('/logout', async (req, res) => {
    try {
        const data = req.body;
        const user = await newUser.findOne({ username: data.username });

        if (!user) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const passwordMatch = await bcrypt.compare(data.password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        user.isLoggedIn = false;
        await user.save();

        res.json({ message: 'Logged out successfully' });
    }
    catch (err) {
        res.status(500).json({ err: "Error occured" });
    }
})

//Middleware to verify JWT token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "Token not found or invalid token" });
    }

    jwt.verify(token, JWT_SECRET, (err, userData) => {
        if (err) {
            return res.status(403).json({ message: "Invalid Token" });
        }
        req.user = userData;
        next();
    })
}

//Protected route
app.get('/dashboard', verifyToken, (req, res) => {
    return res.json({message: `Hello ${req.user.username}, Welcome to dashboard`});
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
