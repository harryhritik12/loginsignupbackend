const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MongoStore = require("connect-mongo");  // ✅ MongoDB session store

dotenv.config();

const app = express();
app.use(express.json());

// ✅ CORS Configuration
app.use(cors({
    origin: ["http://localhost:3000", "https://auth-tan-psi.vercel.app"],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// ✅ Fix Cross-Origin-Opener-Policy (Google OAuth fix)
app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');  
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
});

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ MongoDB connected"))
    .catch((err) => console.log("❌ MongoDB connection error:", err));

// ✅ Use MongoDB to store session data (Fixes MemoryStore issue)
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: "sessions",
        ttl: 14 * 24 * 60 * 60  // Sessions expire in 14 days
    })
}));

app.use(passport.initialize());
app.use(passport.session());

// ✅ User Schema
const UserSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    mobile: String,
    password: String,
    countryCode: String,
    gender: String,
    dob: String,
    googleId: String
});

const User = mongoose.model("User", UserSchema);

// ✅ Signup Route (Email/Password)
app.post("/signup", async (req, res) => {
    try {
        const { firstName, lastName, email, mobile, password, countryCode, gender, dob } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ firstName, lastName, email, mobile, password: hashedPassword, countryCode, gender, dob });

        await newUser.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ Login Route (Email/Password)
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// ✅ Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ email: profile.emails[0].value });
            done(null, user);
        } catch (error) {
            done(error, null);
        }
    }
));

// ✅ Serialize & Deserialize User
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

// ✅ Google Signup Route (Only for new users)
app.post("/auth/google/signup", async (req, res) => {
    try {
        const { email, firstName, lastName, googleId } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists. Please log in." });
        }

        const newUser = new User({ firstName, lastName, email, googleId });
        await newUser.save();

        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, user: newUser });
    } catch (error) {
        res.status(500).json({ message: "Google signup failed" });
    }
});

// ✅ Google Login Route (Only for existing users)
app.post("/auth/google/login", async (req, res) => {
    try {
        const { email, googleId } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: "No account found. Please sign up first." });
        }

        // Ensure the Google ID matches
        if (user.googleId !== googleId) {
            return res.status(400).json({ message: "Google authentication mismatch." });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ message: "Google login failed" });
    }
});

// ✅ Google OAuth Redirect Routes
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        res.redirect("http://localhost:3000/dashboard");
    }
);

// ✅ Logout Route
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ message: "Logout error" });
        res.redirect("http://localhost:3000/");
    });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
