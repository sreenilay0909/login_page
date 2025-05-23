const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const path = require('path');
const User = require('./models/User');

const app = express();
mongoose.connect('mongodb://127.0.0.1:27017/students', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'secretkey',
    resave: false,
    saveUninitialized: false
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com', // Replace with your actual email
        pass: 'yourpassword' // Replace with your actual password
    }
});

app.get('/', (req, res) => res.sendFile(__dirname + '/public/login.html'));
app.get('/register', (req, res) => res.sendFile(__dirname + '/public/register.html'));
app.get('/forgot-password', (req, res) => res.sendFile(__dirname + '/public/forgot-password.html'));
app.get('/reset-password', (req, res) => res.sendFile(__dirname + '/public/reset-password.html'));

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.send('All fields are required.');
    }
    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashed });
    await newUser.save();
    res.send('User registered. <a href="/">Login</a>');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.send('Email and password are required.');
    }
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user._id;
        res.send(`Welcome, ${user.username}! <a href="/reset-password">Reset Password</a>`);
    } else {
        res.send('Invalid credentials');
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.send('Email is required.');
    const user = await User.findOne({ email });
    if (!user) return res.send('No user with this email');

    const tempPass = Math.random().toString(36).slice(-8);
    const hashedTemp = await bcrypt.hash(tempPass, 10);
    user.tempPassword = hashedTemp;
    await user.save();

    await transporter.sendMail({
    from: '"Your Card System" <your-email@gmail.com>', // Replace with your actual email
    to: email,
    subject: 'Temporary Password for Reset',
    text: `Hello,

We received a request to reset your password. Please use the temporary password below to proceed:

Temporary Password: ${tempPass}

For security reasons, we recommend that you reset your password as soon as possible.

If you did not request a password reset, please ignore this email.

Best regards,  
Your Card System Support Team`
});

res.send('A temporary password has been sent to your registered email address. Please check your inbox (and spam folder). <br><br><a href="/reset-password">Click here to reset your password</a>');});

app.post('/reset-password', async (req, res) => {
    const { email, tempPassword, newPassword } = req.body;
    if (!email || !tempPassword || !newPassword) {
        return res.send('All fields are required.');
    }
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(tempPassword, user.tempPassword)) {
        return res.send('Invalid temporary password');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.tempPassword = undefined;
    await user.save();
    res.send('Password reset successfully. <a href="/">Login</a>');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));