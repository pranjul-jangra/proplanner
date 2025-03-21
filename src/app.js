import express from "express";
import crypto from "crypto";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import cookieParser from "cookie-parser";

//-------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------BASIC APP CONFIGURATION-----------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------

dotenv.config();
const app = express();
const client = new MongoClient(process.env.URI);

app.use(cors({
    origin: process.env.FRONTEND_URI,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.options("*", cors());

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());


// MIDDLEWARE TO AUTHORIZE THE USER
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "No token provided" });

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded; // Attach user data to request
        next();
    } catch (error) {
        return res.status(403).json({ message: "Invalid or expired token" });
    }
};

//-------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------DATABASE CONNECTION AND VARIABLES----------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------

let db, credentialCollection, dataCollection, feedbackCollection;
async function connectToDatabase(){
    try{
        await client.connect();
        db = client.db(process.env.DATABASE);
    }catch(error){
        console.error("Database connection failed:", error.message);
        throw error;
    }
}

async function createIndex(collection) {
    const existingIndexes = await collection.listIndexes().toArray();
    const emailIndexExists = existingIndexes.some(index => index.key.email);
    const usernameIndexExists = existingIndexes.some(index => index.key.username);

    if (!emailIndexExists) { await collection.createIndex({ email: 1 }, { unique: true }) }
    if (!usernameIndexExists) { await collection.createIndex({ username: 1 }, { unique: true }) }
}

//-------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------AUTHENTICATION ROUTES-------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------

// LOGIN ROUTE
app.post('/login', async (req, res)=>{
    try{
        await connectToDatabase();
        const { username, password } = req.body;

        if (!username || !password) return res.status(400).json({ error: 'All fields are required' });

        credentialCollection = await db.collection('userCredentials');

        const user =  await credentialCollection.findOne({username});
        if(!user || !user.password) return res.status(404).json({ error: 'This username does not exist.' });
        const isVerified = await bcrypt.compare(password, user.password);

        if(isVerified){
            const accessToken = jwt.sign({username: user.username}, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '30m'});
            const refreshToken = jwt.sign({username: user.username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

            res.cookie('proPlannerRefreshToken', refreshToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 24 * 60 * 60 * 1000});
            res.status(200).json({ message: 'Login successful', accessToken, username: user.username });
        }else{
            res.status(400).json({error: 'Invalid Password'});
        }

    }catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// SIGNUP ROUTE
app.post('/signup', async (req, res)=>{
    try{
        await connectToDatabase();
        const { username, email, gender, password } = req.body;

        if (!username || !email || !gender || !password) return res.status(400).json({ error: 'All fields are required' });

        const collections = await db.listCollections({}, { nameOnly: true }).toArray();
        const credentialsCollectionExists = collections.some(col => col.name === 'userCredentials');

        if (!credentialsCollectionExists) await db.createCollection('userCredentials');
        credentialCollection = await db.collection('userCredentials');
        await createIndex(credentialCollection);

        // checking for duplicate username or email
        const isUserExists = await credentialCollection.findOne({$or: [{ username }, { email }]});
        if(isUserExists) {
            if(isUserExists.username === username){
                return res.status(409).json({error: 'This username already exists.'});
            }else if(isUserExists.email === email){
                return res.status(409).json({error: 'This email has already been used.'})
            }
        }

        // checking for duplicate password
        const users = await credentialCollection.find({}, { projection: { password: 1 } }).toArray();
        for (let user of users) {
            const isSamePassword = await bcrypt.compare(password, user.password);
            if (isSamePassword) {
                return res.status(409).json({ error: 'This password is already in use. Please choose a different one.' });
            }
        }
        
        // inserting new credentials
        const hashedPassword = await bcrypt.hash(password, 10);

        await credentialCollection.insertOne({username, email, gender, password: hashedPassword});

        const accessToken = jwt.sign({username: username}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '30m'});
        const refreshToken = jwt.sign({username: username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

        res.cookie('proPlannerRefreshToken', refreshToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 24 * 60 * 60 * 1000});
        res.status(201).json({ message: "User registered successfully", accessToken, username: username });

    }catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
    }    
});


// REFRESHING THE ACCESS TOKEN:
app.post('/refresh', async (req, res) => {
    try {
        const existingRefreshToken = req.cookies?.proPlannerRefreshToken;

        if (!existingRefreshToken) return res.status(404).json({ error: "Refresh token missing" });

        const decoded = jwt.verify(existingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const newAccessToken =  jwt.sign({ username: decoded.username },process.env.ACCESS_TOKEN_SECRET,{ expiresIn: "30m" });
        const refreshToken = jwt.sign({username: decoded.username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

        res.cookie('proPlannerRefreshToken', refreshToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 24 * 60 * 60 * 1000});
        res.status(200).json({ accessToken: newAccessToken });

    } catch (error) {
        if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
            return res.status(403).json({ error: "Invalid or expired refresh token" });
        }
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// VERIFYING THE USER LOGGED IN STATUS
app.get('/auth/verify', (req, res) => {
    try{
        const token = req.headers?.authorization?.split(' ')[1];
        if (!token) return res.status(403).json({ error: 'Unauthorized' });

        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        if(!decoded) return res.status(403).json({ error: 'Invalid or expired token' });

        res.status(200).json({ message: 'User verified', user: decoded });

    }catch(error){
        console.error("Error Verifying loggedin status:", error);
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
});
  

// REQUEST A PASSWORD RESET
app.post('/forgot-password', async (req, res) => {
    try {
        await connectToDatabase();
        const { email } = req.body;

        if (!email) { return res.status(400).json({ error: "Email is required" }) }

        credentialCollection = await db.collection('userCredentials');
        const user = await credentialCollection.findOne({ email });

        if (!user) { return res.status(404).json({ error: "Email does not exist" }) }

        const resetToken = jwt.sign({ id: user._id }, process.env.RESET_LINK_SECRET, { expiresIn: '30m' });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.EMAIL_PASS
            }
        });

        const resetLink = `http://localhost:5173/reset-password/${encodeURIComponent(resetToken)}`;

        const mailOptions = {
            from: process.env.MY_EMAIL,
            to: email,
            subject: "Reset Your Password – Action Required",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background: #ffffff;">
                    <h2 style="color: #333; text-align: center;">Reset Your Password</h2>
                    <p>Hi there,</p>
                    <p>You recently requested to reset your password for your <strong>proplanner</strong> account. Click the button below to reset it:</p>
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="${resetLink}" style="background-color: #007BFF; color: #ffffff; padding: 12px 20px; text-decoration: none; font-size: 16px; border-radius: 5px; display: inline-block;">Reset Password</a>
                    </div>
                    <p>If you didn't request this, you can ignore this email. Your password will remain the same.</p>
                    <p>Alternatively, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; background: #f4f4f4; padding: 10px; border-radius: 5px;">${resetLink}</p>
                    <p>Best regards,</p>
                    <p><strong>proplanner</strong> Team</p>
                    <hr>
                    <p style="font-size: 12px; color: #777; text-align: center;">If you received this email by mistake, please ignore it.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        
        res.status(200).json({ message: "Password reset link sent to your email" });

    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ENDPOINT TO RESET PASSWORD
app.post('/reset-password', async (req, res) => {
    try {
        await connectToDatabase();
        const token = req.headers.authorization?.split(" ")[1];
        const { newPassword } = req.body;

        if (!newPassword) res.status(400).json({ error: "New password is missing" });

        // Verify reset token
        const decoded = jwt.verify(token, process.env.RESET_LINK_SECRET);

        credentialCollection = await db.collection('userCredentials');
        const user = await credentialCollection.findOne({ _id: new ObjectId(decoded.id) });

        if (!user) { return res.status(404).json({ error: "Invalid or expired token" }) }

        const isDuplicate = await bcrypt.compare(newPassword, user.password);

        if(isDuplicate) return res.status(400).json({error: "You can't use your current password"})

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const result = await credentialCollection.updateOne(
            { _id: new ObjectId(decoded.id) },
            { $set: { password: hashedPassword } }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: "User not found or invalid token" });

        res.status(200).json({ message: "Password reset successful" });

    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: "Invalid or expired token" });
    }
});

//-------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------HOME PAGE ROUTES------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------

app.get('/home/data', async (req, res)=>{
    try{
        await connectToDatabase();
        const user = req.query.user;

        const collections = await db.listCollections({}, { nameOnly: true }).toArray();
        const dataCollectionExists = collections.some(col => col.name === 'userData');

        if (!dataCollectionExists) await db.createCollection('userData');
        dataCollection = await db.collection('userData');

        const queryResponse = await dataCollection.find({ username: user }).toArray();
        res.json(queryResponse);

    }catch(error){
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/home/add', async (req, res)=>{
    try{
        await connectToDatabase();
        const {taskText, countdownPeriod, user} = req.body;

        if (!user || !taskText || !countdownPeriod)  return res.status(400).json({ error: "Missing required fields" });

        if(countdownPeriod === 'noExpiry'){
            await db.collection('userData').insertOne({
                username: user,
                task: taskText,
                countdownPeriod: countdownPeriod,
                createdAt: new Date()
            })
        }else{
            await db.collection('userData').insertOne({
                username: user,
                task: taskText,
                countdownPeriod: countdownPeriod,
                isCompleted: false,
                createdAt: new Date()
            })
        }
        res.status(201).json({message: 'Task added successfully'})

    }catch(error){
        res.status(500).json({ error: 'Internal Server Error' })
    }
});

app.delete('/home/delete', async (req, res)=>{
    try{
        const {taskId, user} = req.body;
        const objectId = new ObjectId(taskId);
        if(!taskId || !user) return res.status(400).json({ error: "Missing required fields" })
            
        await connectToDatabase();
        const result = await db.collection('userData').deleteOne({ username: user, _id: objectId })
        if (result.deletedCount === 1) {
            res.status(200).json({ message: 'Task deleted successfully' });
        } else {
            res.status(404).json({ error: "Task not found" });
        }

    }catch(error){
        console.error("Error deleting task:", error);
        res.status(500).json({ error: 'Internal Server Error' })
    }
})

app.patch('/home/edit', async (req, res)=>{
    try{
        const {taskId, taskText, countdownPeriod, user} = req.body;
        if(!taskId || !taskText || !countdownPeriod || !user) return res.status(400).json({error: "Missing required fields"})

        const objectId = new ObjectId(taskId);
        await connectToDatabase();
        const result = await db.collection('userData').updateOne({_id: objectId, username: user}, {
            $set: {
                task: taskText,
                countdownPeriod: countdownPeriod,
                updatedAt: new Date()
            }
        })

        if (result.matchedCount === 0) return res.status(404).json({ error: "Task not found" });

        if (result.modifiedCount === 0) return res.status(200).json({ message: "No changes made" });

        res.status(200).json({ message: 'Task updated successfully' });

    }catch(error){
        console.error("Error updating task:", error);
        res.status(500).json({ error: 'Internal Server Error' })
    }
})

app.patch('/home/markascomplete', async (req, res)=>{
    try{
        const {taskId, user} = req.body;
        if(!taskId || !user) return res.status(400).json({error: 'Missing required fields'})
        
        const objectId = new ObjectId(taskId);
        await connectToDatabase();
        const result = await db.collection('userData').updateOne({username: user, _id: objectId}, {
            $set: {
                isCompleted: true
            }
        })

        if (result.matchedCount === 0) return res.status(404).json({ error: "Task not found" });

        if (result.modifiedCount === 0) return res.status(200).json({ message: "No changes made" });

        res.status(200).json({ message: 'Task updated successfully' });

    }catch(error){
        console.error("Error marking task as completed:", error)
        res.status(500).json({error: "Internal Server Error"})
    }
})


//-------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------SETTINGS PAGE ROUTES--------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------
app.get('/home/settings/user-profile', async (req, res)=>{
    try{
        const {user} = req.query;
        if(!user) return res.status(400).json({error: 'Username is missing'});

        await connectToDatabase();

        credentialCollection = await db.collection('userCredentials');
        const userData = await credentialCollection.findOne({username: user}, {projection: {_id: 0, password: 0}});

        if(!userData) return res.status(404).json({error: "User not found"});

        res.json({userData});

    }catch(error){
        console.log("Error fetching user:", error);
        res.status(500).json({error: "Internal Server Error"});
    }
});

app.delete('/home/settings/empty-tasks', async (req, res)=>{
    try{
        const {user, containerToEmpty} = req.query;
        if(!user || !containerToEmpty) return res.status(400).json({error: 'A field is missing'});

        let taskToEmpty;
        if(containerToEmpty === 'daily'){ taskToEmpty = 'daily'}
        else if(containerToEmpty === 'weekly'){ taskToEmpty = 'weekly'}
        else if(containerToEmpty === 'notes'){ taskToEmpty = 'noExpiry'}
        else{ return res.status(400).json({error: 'A field is missing'}); }

        await connectToDatabase();

        const result = await db.collection('userData').deleteMany({username: user, countdownPeriod: taskToEmpty});
        if(result.deletedCount === 0) return res.status(200).json({ message: "Nothing to delete" });

        if(containerToEmpty === 'daily'){
            res.status(200).json({ message: 'Daily tasks deleted successfully' });
        }else if(containerToEmpty === 'weekly'){
            res.status(200).json({ message: 'Weekly tasks deleted successfully' });
        }else if(containerToEmpty === 'notes'){
            res.status(200).json({ message: 'Notes deleted successfully' });
        }

    }catch(error){
        console.error("Error emptying daily tasks:", error);
        res.status(500).json({error: "Internal Server Error"});
    }
});

app.post('/home/settings/submit-feedback', async (req, res) => {
    const { name, email, feedbackType, message } = req.body;

    if (!message.trim()) return res.status(400).json({ error: 'Message cannot be empty' });

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.MY_EMAIL,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.MY_EMAIL,
        to: process.env.MY_EMAIL,
        subject: `New Feedback Received - ${feedbackType}`,
        html: `
            <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; padding: 10px;">
                <h2 style="color: #007bff;">You've Received a New Feedback Submission</h2>
                
                <p>Hello,</p>
                <p>A new feedback entry has been submitted. Please review the details below:</p>
                
                <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Name:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">${name || 'Anonymous'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Email:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">${email || 'Not Provided'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Feedback Type:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">${feedbackType}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Message:</strong></td>
                        <td style="padding: 8px; border-bottom: 1px solid #ddd;">${message}</td>
                    </tr>
                </table>
                
                <p style="color: #666; font-size: 14px;">Best regards</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        await connectToDatabase();

        const collections = await db.listCollections({}, { nameOnly: true }).toArray();
        const feedbackCollectionExists = collections.some(col => col.name === 'feedbacks');

        if (!feedbackCollectionExists) await db.createCollection('feedbacks');
        feedbackCollection = await db.collection('feedbacks');

        await feedbackCollection.insertOne({
            name: name || 'Anonymous', 
            email: email || 'Not provided', 
            feedbackType, 
            message
        })

        res.status(200).json({ message: 'Feedback submitted successfully!' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ error: 'Failed to send feedback' });
    }
});

app.patch('/home/settings/update-profile', async ( req, res )=>{
    try{
        const { user, dataToEdit } = req.body;  
        const { username, gender } = dataToEdit;
        
        if(!username || !gender) return res.status(400).json({error: 'You submitted an empty field'});

        await connectToDatabase();
        credentialCollection = await db.collection('userCredentials');
        dataCollection = await db.collection('userData');

        // CHECK IF THERE'S ANOTHER USER EXISTS WITH THE SUBMITED USERNAME:
        const anotherUserWithSameCredentials =  await credentialCollection.findOne({username});
        if(anotherUserWithSameCredentials) return res.status(409).json({error: "Profile can't be updated. Please use a different username."});

        // TO CHECK IF THE USER SUBMITS IT'S CURRENT INFORMATION (NO CHANGES):
        const userToUpdate = await credentialCollection.findOne({username: user}, { projection:{ username:1, gender:1 } });
        if(
            username === userToUpdate.username &&
            gender === userToUpdate.gender
        ){
            return res.status(409).json({error: "No change detected"});
        }

        await credentialCollection.updateOne(
            { username: user },
            { $set: { username, gender } }
        );

        await dataCollection.updateMany(
            {username: user},
            { $set: { username }}
        )

        // generate new token with new payload
        const newAccessToken = jwt.sign({ username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "30m" });
        const newRefreshToken = jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

        res.cookie('proPlannerRefreshToken', newRefreshToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 24 * 60 * 60 * 1000 });

        res.status(200).json({ message: "Profile updated successfully", username, gender,accessToken: newAccessToken });

    }catch(error){
        console.error("Error Updating Profile Info:", error);
        res.status(500).json({error: "Failed to update profile"});
    }
})

// OTP VERIFICATION ROUTES:
app.post('/home/settings/generate-otp', async (req,res)=>{
    try{
        const { email, forceOtpGeneration } = req.body;
        if(!email) return res.status(400).json({error: "Email is missing."});

        // clear the cookie if the "resend otp" button is making the request to re-generate OTP. 
        if(forceOtpGeneration){
            res.clearCookie('otpToken', { httpOnly: true, sameSite: 'None', secure: true });  // marks the cookies to clear in the next request
            res.clearCookie('resendCountdown', { httpOnly: true, sameSite: 'None', secure: true });

        }
        
        if(!forceOtpGeneration && req.cookies?.otpToken) {    // Checks for any active OTP
            const resendCountdown = req.cookies?.resendCountdown ? parseInt(req.cookies.resendCountdown) : 0;
            return res.status(429).json({ error: "Please enter the otp send to your email.", resendCountdown });
        }
        
        // generates new otp if previous one is used or expired
        const otp = crypto.randomInt(100000, 999999).toString();

        const otpToken = jwt.sign({ email, otp }, process.env.OTP_TOKEN_SECRET, { expiresIn: "15m" });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.EMAIL_PASS
            }
        });
        const mailOptions = {
            from: process.env.MY_EMAIL,
            to: email,
            subject: 'Your OTP Code for Secure Verification',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px; width: 80%; max-width: 500px; margin: auto;">
                    <h2 style="color: #333; text-align: center;">Your OTP Code</h2>
                    <p style="font-size: 16px; color: #555;">Hello,</p>
                    <p style="font-size: 16px; color: #555;">Your One-Time Password (OTP) is:</p>
                    <p style="font-size: 24px; font-weight: bold; color: #2c3e50; text-align: center;">${otp}</p>
                    <p style="font-size: 16px; color: #555;">This OTP is valid for <strong>15 minutes</strong>. Please use it to complete your verification.</p>
                    <p style="font-size: 14px; color: #777; text-align: center;">If you did not request this, please ignore this email.</p>
                    <hr style="border: none; border-top: 1px solid #ddd;">
                    <p style="font-size: 14px; color: #999; text-align: center;">Need help? Contact us at <a href="mailto:proplanner68@gmail.com">support@proplanner</a></p>
                </div>
            `
        };


        try {
            await transporter.sendMail(mailOptions);
        } catch (mailError) {
            console.error("Email sending failed:", mailError);
            return res.status(500).json({ error: "Failed to send OTP to your email." });
        }
        
        const resendCountdown = Date.now() + 90 * 1000;

        res.cookie('otpToken', otpToken, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 60 * 1000});
        res.cookie('resendCountdown', resendCountdown, {httpOnly: true, sameSite: 'None', secure: true, maxAge: 15 * 60 * 1000})
        res.status(200).json({message: "OTP has been sent to your email.", resendCountdown});

    }catch(error){
        console.error("Error generating otp:", error);
        res.status(500).json({error: "Failed to generate otp. Please try again later."});
    }
});

app.post('/home/settings/verify-otp', async (req, res) => {
    try {
      const { email, otp } = req.body;
      
      if (!email || !otp) return res.status(400).json({ error: "Email and OTP are required." });
      
      const otpToken = req.cookies?.otpToken;
      if (!otpToken) return res.status(400).json({ error: "The OTP has expired." });
      
      try {
        const decoded = jwt.verify(otpToken, process.env.OTP_TOKEN_SECRET);
        
        if (decoded.email !== email) return res.status(400).json({ error: "Email mismatch." });
        if (decoded.otp !== otp) return res.status(400).json({ error: "Invalid OTP." });
        
        res.clearCookie('otpToken', { httpOnly: true, sameSite: 'None', secure: true });
        res.clearCookie('resendCountdown', { httpOnly: true, sameSite: 'None', secure: true });
        
        return res.status(200).json({ message: "OTP verified successfully." });
        
      } catch (jwtError) {
        return res.status(400).json({ error: "OTP has expired or is invalid." });
      }
      
    } catch (error) {
      console.error("Error verifying OTP:", error);
      res.status(500).json({ error: "Failed to verify OTP. Please try again later." });
    }
});


app.patch('/home/settings/update-email', async (req, res)=>{
    try{
        const {currentEmail, newEmail} = req.body;

        if(!currentEmail || !newEmail) return res.status(400).json({error: "Your request can't be completed. Please check your details."});

        await connectToDatabase();
        credentialCollection = await db.collection('userCredentials');

        const isUserExists = await credentialCollection.findOne({email: currentEmail});
        if(!isUserExists) return res.status(400).json({error: "Something went wrong. Please check your details."});

        const isEmailTaken = await credentialCollection.findOne({ email: newEmail });
        if (isEmailTaken) return res.status(409).json({ error: "This email is already in use." });

        const updateResult = await credentialCollection.updateOne({email: currentEmail}, {
            $set: {email: newEmail}
        })

        if (updateResult.modifiedCount === 0) return res.status(500).json({ error: "Failed to update email. Please try again." });

        res.clearCookie('otpToken', { httpOnly: true, sameSite: 'None', secure: true });
        res.clearCookie('resendCountdown', { httpOnly: true, sameSite: 'None', secure: true });
        res.status(200).json({message: "Email updated successfully"});


    }catch(error){
        console.error("Error updating email:", error);
        res.status(500).json({error: "Something went wrong. Failed to update email."});
    }
});


app.patch('/home/settings/update-password', async (req, res)=>{
    try{
        const {user, passwords} = req.body;
        const {currentPassword, newPassword, confirmPassword} = passwords;

        if(!user || !currentPassword || !newPassword || !confirmPassword){
            return res.status(400).json({error: "Your request can't be completed. Please ensure that the data you have submitted is correct."});
        }

        await connectToDatabase();
        credentialCollection = await db.collection('userCredentials');
        const isUserExists = await credentialCollection.findOne({username: user}, { projection:{ username: 1 , password: 1} }); 

        if(!isUserExists) return res.status(404).json({ error: "User doesn't exist in the database." });

        const isPasswordValid = await bcrypt.compare(currentPassword, isUserExists.password);
        if(!isPasswordValid) return res.status(400).json({error: "Invalid Password"});
        if (await bcrypt.compare(newPassword, isUserExists.password)) return res.status(400).json({ error: "New password cannot be the same as the old password." });

        if (newPassword !== confirmPassword) return res.status(400).json({ error: "New passwords do not match." });

        // checking for duplicate password
        const users = await credentialCollection.find({}, { projection: { password: 1 } }).toArray();
        for (let user of users) {
            const isSamePassword = await bcrypt.compare(newPassword, user.password);
            if (isSamePassword) {
                return res.status(409).json({ error: 'This password is already in use. Please choose a different one.' });
            }
        }

        //hashing new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        const updateResult = await credentialCollection.updateOne({username: user}, {
            $set: {password: hashedPassword}
        })

        if (updateResult.modifiedCount === 0) return res.status(500).json({ error: "Failed to change password. Please try again." });

        res.status(200).json({message: "Password changes successfully"})

    }catch(error){
        console.error("Error updating password:", error);
        res.status(500).json({error: "Something went wrong. Failed to update password."});
    }
})


// LOGGING OUT THE USER:
app.post('/home/settings/logout', async (req, res)=>{
    try{
        res.clearCookie('otpToken', { httpOnly: true, sameSite: 'None', secure: true });
        res.clearCookie('resendCountdown', { httpOnly: true, sameSite: 'None', secure: true });

        res.clearCookie('proPlannerRefreshToken', { httpOnly: true, sameSite: 'None', secure: true })

        res.status(200).json({ message: "Logged out successfully" });
    
    }catch(error){
        console.error("Error logging out user:", error);
        res.status(500).json({error: "Something went wrong. Failed to log out."});
    }
})

// DELETING USER ACCOUNT:
app.delete('/home/settings/delete-account', async (req, res)=>{
    try{
        const {username, password} = req.query;

        if(!username, !password) return res.status(400).json({error: 'All fields are required'});

        await connectToDatabase();

        credentialCollection = await db.collection('userCredentials');
        dataCollection = await db.collection('userData');

        const user = await credentialCollection.findOne({username}, { projection: { username: 1, password: 1 } });
        
        const isVerified = bcrypt.compareSync(password, user.password);
        if(!isVerified) return res.status(400).json({error: "Invalid password"});
        if(user.username !== username) return res.status(400).json({error: "Something went wrong. Please try again after some time."});

        res.clearCookie( 'proPlannerRefreshToken', { httpOnly: true, sameSite: 'None', secure: true } );
        await credentialCollection.deleteOne({username}); 
        await dataCollection.deleteMany({username});

        res.status(200).json({message: "Account deleted"});        

    }catch(error){
        console.error('Error Deleting Account:', error);
        res.status(500).json({error: "Failed to delete account"});
    }
})


//-------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------LISTENING TO PORT-----------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------

app.listen(process.env.PORT, ()=>{
    console.log('server is running...' )
})