const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const session = require("express-session");
const passportGoogle = require("passport-google-oauth20").Strategy;
const axios = require("axios");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
.catch(err => console.log("MongoDB Connection Error:", err));

// Password Reset Token Schema
const resetTokenSchema = new mongoose.Schema({
    email: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 } // Token expires after 1 hour
});
const ResetToken = mongoose.model("ResetToken", resetTokenSchema);

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    googleId: String
});
const User = mongoose.model("User", userSchema);

// Anime Schema
const animeSchema = new mongoose.Schema({
    title: String,
    description: String,
    youtubeEmbedUrl: String
});
const Anime = mongoose.model("Anime", animeSchema);

// Favorite Anime Schema

const FavouriteAnimeSchema = new mongoose.Schema({
    userId: String,
    animeId: String,
    title: String,
    description: String,
    youtubeEmbedUrl: String
});
const FavouriteAnime = mongoose.model("FavouriteAnime", FavouriteAnimeSchema);

///////WAtch-Later Schema
const WatchLaterSchema = new mongoose.Schema({
    userId: String,
    animeId: String,
    title: String,
    description: String,
    youtubeEmbedUrl: String
});
const WatchLater = mongoose.model("WatchLater", WatchLaterSchema);
// Register API
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.json({ message: "User registered successfully" });
    } catch (err) {
        res.status(400).json({ message: "Error registering user", error: err });
    }
});

// Login API
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token });
    } catch (err) {
        res.status(500).json({ message: "Error logging in", error: err });
    }
});
// // Google OAuth
app.use(session({ secret: "secret", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new passportGoogle({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
        user = new User({ name: profile.displayName, email: profile.emails[0].value, googleId: profile.id });
        await user.save();
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/" }), (req, res) => {
    // Generate JWT token for Google authenticated user
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    // Redirect to frontend with token
    res.redirect(`http://localhost:3000/auth/google/callback?token=${token}`);
});

/////auth token
const authenticateToken = (req, res, next) => {
    // Check if user is authenticated via Google OAuth (session-based)
    if (req.isAuthenticated()) {
        req.user = { userId: req.user._id };
        return next();
    }

    // Check for JWT token
    const token = req.headers.authorization?.split(" ")[1]; // Extract token
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Forbidden" });
        req.user = user;
        next();
    });
};


// Fetch and store anime from YouTube
const fetchAndStoreAnime = async () => {
    try {
        console.log("Fetching YouTube data...");
        let nextPageToken = "";
        let videos = [];
        const BASE_URL = "https://www.googleapis.com/youtube/v3/search";

        while (videos.length < 500) {
            const response = await axios.get(BASE_URL, {
                params: {
                    key: process.env.YOUTUBE_API_KEY,
                    channelId: "UCP8E_gJhRMApuQYOQ21MkLA",
                    part: "snippet",
                    type: "video",
                    maxResults: 50,
                    pageToken: nextPageToken
                }
            });

            if (!response.data.items || response.data.items.length === 0) break;

            videos.push(
                ...response.data.items.map(video => ({
                    title: video.snippet.title,
                    description: video.snippet.description,
                    youtubeEmbedUrl: `https://www.youtube.com/embed/${video.id.videoId}`
                }))
            );

            console.log(`Fetched ${videos.length} videos so far...`);
            nextPageToken = response.data.nextPageToken;
            if (!nextPageToken) break;
        }

        await Anime.deleteMany();
        await Anime.insertMany(videos);

        console.log(`YouTube data stored successfully! Total videos: ${videos.length}`);
    } catch (err) {
        console.error("Error fetching YouTube data:", err);
    }
};

setInterval(fetchAndStoreAnime, 24 * 60 * 60 * 1000);
fetchAndStoreAnime();

// Get all anime
app.get("/anime", async (req, res) => {
    try {
        const animeList = await Anime.find();
        res.json(animeList);
    } catch (err) {
        res.status(500).json({ message: "Error fetching anime", error: err });
    }
});

app.get("/favourite_anime", authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const favorites = await FavouriteAnime.find({ userId });
        res.json(favorites);
    } catch (err) {
        console.error("Error fetching favourite anime:", err);
        res.status(500).json({ message: "Error fetching favourite anime", error: err });
    }
});

app.post("/favourite_anime", authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { animeId, title, description, youtubeEmbedUrl } = req.body;

    const existing = await FavouriteAnime.findOne({ userId, animeId });
    if (existing) return res.status(400).json({ error: "Already in favourites" });

    const newFav = new FavouriteAnime({ userId, animeId, title, description, youtubeEmbedUrl });
    await newFav.save();
    res.json({ message: "Added to favourites" });
});

app.delete("/favourite_anime/:animeId", authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    await FavouriteAnime.findOneAndDelete({ userId, animeId: req.params.animeId });
    res.json({ message: "Removed from favourites" });
});

app.get("/watch_later", authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const watchLaterList = await WatchLater.find({ userId });
        res.json(watchLaterList);
    } catch (err) {
        console.error("Error fetching watch later anime:", err);
        res.status(500).json({ message: "Error fetching watch later anime", error: err });
    }
});

app.post("/watch_later", authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const { animeId, title, description, youtubeEmbedUrl } = req.body;

    try {
        const existing = await WatchLater.findOne({ userId, animeId });
        if (existing) return res.status(400).json({ error: "Already in watchlist" });

        const newEntry = new WatchLater({ userId, animeId, title, description, youtubeEmbedUrl });
        await newEntry.save();
        res.json({ message: "Added to watchlist" });
    } catch (err) {
        console.error("Error adding to watch later:", err);
        res.status(500).json({ message: "Internal server error", error: err });
    }
});

app.delete("/watch_later/:animeId", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        await WatchLater.findOneAndDelete({ userId, animeId: req.params.animeId });
        res.json({ message: "Removed from watchlist" });
    } catch (err) {
        console.error("Error removing from watch later:", err);
        res.status(500).json({ message: "Internal server error", error: err });
    }
});

///////////////////////////////////////////
app.get("/user", async (req, res) => {
    try {
        let user = null;

        // 🔹 Check if user is authenticated via Google OAuth (session-based)
        if (req.isAuthenticated()) {
            console.log("Google OAuth User:", req.user); // Debugging
            user = req.user;
        }
        
        // 🔹 Check JWT token for regular login users
        else {
            const token = req.headers.authorization?.split(" ")[1]; // Extract JWT token
            if (!token) return res.status(401).json({ message: "Unauthorized" });

            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            user = await User.findById(decoded.userId);
        }

        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({ 
            name: user.name, 
            email: user.email,
            googleId: user.googleId || null
        });
    } catch (error) {
        res.status(401).json({ message: "Invalid token or session expired", error: error.message });
    }
});


app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ message: "Logout failed", error: err });

        req.session.destroy((err) => {
            if (err) return res.status(500).json({ message: "Session destruction failed", error: err });

            res.clearCookie("connect.sid"); // Clear session cookie
            res.json({ message: "Logged out successfully" });
        });
    });
});

app.listen(5001, () => console.log("Server running on port 5001"));

/////////////////////////////////////////////

// Change Password API
app.post("/change-password", authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.userId;

        // Find the user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Check if user is a Google user (has googleId)
        if (user.googleId) {
            return res.status(400).json({ message: "Google users cannot change their password here. Please use Google account settings." });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update password
        user.password = hashedPassword;
        await user.save();
        
        res.json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Error changing password:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Email configuration
let transporter;
let emailConfigured = false;

try {
    // Check if email credentials are provided
    if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
        transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });
        
        // Test email configuration
        transporter.verify((error, success) => {
            if (error) {
                console.error("Email configuration error:", error);
                console.log("Email sending will be disabled. Please check your credentials.");
                emailConfigured = false;
            } else {
                console.log("Email server is ready to send messages");
                emailConfigured = true;
            }
        });
    } else {
        console.log("Email credentials not provided in .env file. Email sending will be disabled.");
        console.log("To enable email sending, add EMAIL_USER and EMAIL_PASSWORD to your .env file.");
        console.log("For Gmail, you need to use an App Password: https://support.google.com/accounts/answer/185833");
        emailConfigured = false;
    }
} catch (error) {
    console.error("Error setting up email transport:", error);
    emailConfigured = false;
}

// Helper function to send email
const sendEmail = async (to, subject, text, html) => {
    // If email is not configured, return false immediately
    if (!emailConfigured) {
        console.log("Email not sent because email service is not configured.");
        return false;
    }
    
    try {
        const mailOptions = {
            from: `"Hokage Anime" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            text,
            html
        };
        
        const info = await transporter.sendMail(mailOptions);
        console.log("Email sent:", info.messageId);
        return true;
    } catch (error) {
        console.error("Error sending email:", error);
        return false;
    }
};

// Forgot Password - Request verification code
app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User with this email does not exist" });
        }
        
        // Check if user is a Google user
        if (user.googleId) {
            return res.status(400).json({ 
                message: "This account uses Google Sign-In. Please reset your password through Google." 
            });
        }
        
        // Generate a random 6-digit code
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Hash the code before storing
        const hashedToken = await bcrypt.hash(verificationCode, 10);
        
        // Delete any existing tokens for this user
        await ResetToken.deleteMany({ email });
        
        // Save the new token
        await new ResetToken({
            email,
            token: hashedToken
        }).save();
        
        // Log the code for development purposes
        console.log(`Verification code for ${email}: ${verificationCode}`);
        
        // Send email with verification code
        const emailSubject = "Password Reset Verification Code";
        const emailText = `Your verification code is: ${verificationCode}. It will expire in 1 hour.`;
        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h2 style="color: #333; text-align: center;">Password Reset</h2>
                <p>Hello,</p>
                <p>We received a request to reset your password for your Hokage Anime account. Please use the verification code below to complete the process:</p>
                <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                    <h3 style="margin: 0; color: #e53935; letter-spacing: 2px;">${verificationCode}</h3>
                </div>
                <p>This code will expire in 1 hour.</p>
                <p>If you didn't request a password reset, you can safely ignore this email.</p>
                <p>Best regards,<br>The Hokage Anime Team</p>
            </div>
        `;
        
        const emailSent = await sendEmail(email, emailSubject, emailText, emailHtml);
        
        if (emailSent) {
            res.json({ message: "Verification code sent to your email" });
        } else {
            // If email fails, still return success but log the error
            console.error("Failed to send email, but code was generated");
            res.json({ 
                message: "Verification code generated. Check console for the code (email sending failed)." 
            });
        }
    } catch (error) {
        console.error("Error in forgot-password:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Verify reset code
app.post("/verify-reset-code", async (req, res) => {
    try {
        const { email, code } = req.body;
        
        // Find the reset token
        const resetToken = await ResetToken.findOne({ email });
        if (!resetToken) {
            return res.status(400).json({ 
                message: "Verification code has expired or is invalid. Please request a new one." 
            });
        }
        
        // Verify the code
        const isValid = await bcrypt.compare(code, resetToken.token);
        if (!isValid) {
            return res.status(400).json({ message: "Invalid verification code" });
        }
        
        res.json({ message: "Code verified successfully" });
    } catch (error) {
        console.error("Error in verify-reset-code:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});

// Reset password
app.post("/reset-password", async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        
        // Find the reset token
        const resetToken = await ResetToken.findOne({ email });
        if (!resetToken) {
            return res.status(400).json({ 
                message: "Verification code has expired or is invalid. Please request a new one." 
            });
        }
        
        // Verify the code
        const isValid = await bcrypt.compare(code, resetToken.token);
        if (!isValid) {
            return res.status(400).json({ message: "Invalid verification code" });
        }
        
        // Find the user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update the user's password
        user.password = hashedPassword;
        await user.save();
        
        // Delete the reset token
        await ResetToken.deleteOne({ _id: resetToken._id });
        
        res.json({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Error in reset-password:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});
