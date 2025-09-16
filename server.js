const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const path = require("path");
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs");
require('dotenv').config();

// Initialize Express
const app = express();

// Set view engine and middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use('/uploads', express.static(path.join(__dirname, "uploads")));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || "exam_paper_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/exam_paper")
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// =================== SCHEMAS ===================

// User schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },
    registeredAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// Admin email constant
const ADMIN_EMAIL = "midhun@vitapstudent.ac.in";

// Paper schema
const paperSchema = new mongoose.Schema({
    batch: String,
    subject: String,
    customSubject: String,
    slot: String,
    examType: String,
    filename: String,
    path: String,
    uploadedBy: String,
    uploadedAt: { type: Date, default: Date.now },
    views: { type: Number, default: 0 }
});

const Paper = mongoose.model('Paper', paperSchema);

// Comment schema
const commentSchema = new mongoose.Schema({
    paper: { type: mongoose.Schema.Types.ObjectId, ref: 'Paper' },
    user: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

// Feedback schema
const feedbackSchema = new mongoose.Schema({
    user: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false }
});

const Feedback = mongoose.model('Feedback', feedbackSchema);

// =================== FILE UPLOAD CONFIGURATION ===================

// Configure multer for image upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = './uploads';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// File filter for images
const fileFilter = (req, file, cb) => {
    // Accept only image files
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// =================== MIDDLEWARES ===================

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.status(403).send('Access denied. Admin rights required.');
};

// Middleware to check if user is blocked
const isNotBlocked = (req, res, next) => {
    if (req.session.user) {
        User.findOne({ email: req.session.user.email })
            .then(user => {
                if (user && user.isBlocked) {
                    req.session.destroy();
                    return res.render("blocked");
                }
                return next();
            })
            .catch(err => {
                console.error(err);
                res.status(500).send("Server error");
            });
    } else {
        next();
    }
};

// Middleware to check cookies
// Middleware to check cookies
app.use((req, res, next) => {
    if (!req.session.user && req.cookies.rememberMe) {
        User.findOne({ email: req.cookies.rememberMe })
            .then(user => {
                if (user && !user.isBlocked) {
                    console.log("Restoring session from cookie for:", user.email, 
                                "Admin status:", user.isAdmin);
                    req.session.user = { 
                        email: user.email,
                        isAdmin: user.isAdmin
                    };
                }
                next();
            })
            .catch(err => {
                console.error(err);
                next();
            });
    } else {
        next();
    }
});

// =================== INITIALIZATION ===================

// Init admin user if not exists
// In your initialization code, add a log to verify the admin creation
async function initAdmin() {
    try {
        const adminExists = await User.findOne({ email: ADMIN_EMAIL });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash("admin123", 10);
            await User.create({
                email: ADMIN_EMAIL,
                password: hashedPassword,
                isAdmin: true
            });
            console.log("Admin user created successfully");
        } else {
            console.log("Admin user already exists");
        }
    } catch (err) {
        console.error("Error creating admin user:", err);
    }
}

// =================== ROUTES ===================

// Home route
app.get("/", (req, res) => {
    res.redirect("/login");
});

// Signup Route - GET
app.get("/signup", (req, res) => res.render("signup"));

// Signup Route - POST
app.post("/signup", async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validate VIT-AP email
        if (!email.endsWith("@vitapstudent.ac.in")) {
            return res.send("Only VIT-AP emails allowed!");
        }
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.send("User already exists!");
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const isUserAdmin = email === ADMIN_EMAIL;
        await User.create({ 
            email, 
            password: hashedPassword,
            isAdmin: isUserAdmin
        });
        
        res.redirect("/login");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error creating account.");
    }
});

// Login Route - GET
app.get("/login", (req, res) => res.render("login"));

// Login Route - POST
// Login Route - POST
app.post("/login", async (req, res) => {
    try {
        const { email, password, remember } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.send("Invalid credentials!");
        }
        
        if (user.isBlocked) {
            return res.render("blocked");
        }
        
        console.log("User login successful:", email, "Admin status:", user.isAdmin);
        
        req.session.user = { 
            email: user.email,
            isAdmin: user.isAdmin
        };
        
        // Verify session is set correctly
        console.log("Session user set:", req.session.user);
        
        if (remember) {
            res.cookie("rememberMe", user.email, { 
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production'
            });
        }
        
        res.redirect("/dashboard");
    } catch (err) {
        console.error(err);
        res.status(500).send("Login error occurred.");
    }
});

// Logout route
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.clearCookie("rememberMe");
    res.redirect("/login");
});

// Dashboard Route
// Dashboard Route
app.get("/dashboard", isAuthenticated, isNotBlocked, async (req, res) => {
    try {
        // Get all papers for display
        const papers = await Paper.find().sort({ uploadedAt: -1 });
        
        // Debug log to verify admin status in session
        console.log("Dashboard accessed by:", req.session.user.email, 
                    "Admin status:", req.session.user.isAdmin);
        
        res.render("dashboard", { 
            user: req.session.user,
            papers: papers,
            isAdmin: req.session.user.isAdmin
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading dashboard.");
    }
});

// Upload paper route
app.post('/upload', isAuthenticated, isNotBlocked, upload.single('examPaper'), async (req, res) => {
    try {
        const { batch, subject, customSubject, slot, examType } = req.body;
        
        // Validate all required fields
        if (!batch || !subject || !slot || !examType) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        
        // If "None of the above" is selected, customSubject is required
        if (subject === 'None of the above' && !customSubject) {
            return res.status(400).json({ success: false, message: 'Custom subject is required' });
        }
        
        // Create new paper record
        await Paper.create({
            batch,
            subject,
            customSubject: subject === 'None of the above' ? customSubject : '',
            slot,
            examType,
            filename: req.file.filename,
            path: '/uploads/' + req.file.filename,
            uploadedBy: req.session.user.email
        });
        
        res.json({ success: true, message: 'Paper uploaded successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'An error occurred during upload' });
    }
});
// =================== ADMIN ROUTES ===================

// Admin dashboard
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ isAdmin: false });
        const totalPapers = await Paper.countDocuments();
        const totalFeedbacks = await Feedback.countDocuments();
        const unreadFeedbacks = await Feedback.countDocuments({ isRead: false });
        
        // Get recent users
        const recentUsers = await User.find({ isAdmin: false })
            .sort({ registeredAt: -1 })
            .limit(5);
            
        // Get recent papers
        const recentPapers = await Paper.find()
            .sort({ uploadedAt: -1 })
            .limit(5);
            
        // Get recent feedbacks
        const recentFeedbacks = await Feedback.find()
            .sort({ createdAt: -1 })
            .limit(5);

        res.render('admin', {
            user: req.session.user,
            stats: {
                totalUsers,
                totalPapers,
                totalFeedbacks,
                unreadFeedbacks
            },
            recentUsers,
            recentPapers,
            recentFeedbacks
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading admin dashboard.");
    }
});
// Admin dashboard (alternative route)
app.get('/admin-panel', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({ isAdmin: false });
        const totalPapers = await Paper.countDocuments();
        const totalFeedbacks = await Feedback.countDocuments();
        const unreadFeedbacks = await Feedback.countDocuments({ isRead: false });
        const blockedUsers = await User.countDocuments({ isBlocked: true });
        
        // Get recent users
        const recentUsers = await User.find({ isAdmin: false })
            .sort({ registeredAt: -1 })
            .limit(5);
            
        // Get recent papers
        const recentPapers = await Paper.find()
            .sort({ uploadedAt: -1 })
            .limit(5);
            
        // Get recent feedbacks
        const recentFeedbacks = await Feedback.find()
            .sort({ createdAt: -1 })
            .limit(5);

        res.render('admin', {
            user: req.session.user,
            stats: {
                totalUsers,
                totalPapers,
                totalFeedbacks,
                unreadFeedbacks,
                blockedUsers
            },
            recentUsers,
            recentPapers,
            recentFeedbacks
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading admin dashboard.");
    }
});

// User management page - redirect to main admin page
app.get('/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    res.redirect('/admin');
});

// Block/unblock user
app.post('/admin/toggle-user-status/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Toggle the isBlocked status
        user.isBlocked = !user.isBlocked;
        await user.save();
        
        res.json({ 
            success: true, 
            message: `User ${user.isBlocked ? 'blocked' : 'unblocked'} successfully`,
            isBlocked: user.isBlocked
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error toggling user status' });
    }
});

// Delete user
app.post('/admin/delete-user/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const userToDelete = await User.findById(req.params.id);
        
        if (!userToDelete) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Don't allow deleting admin accounts
        if (userToDelete.isAdmin) {
            return res.status(400).json({ success: false, message: 'Cannot delete admin accounts' });
        }
        
        const userEmail = userToDelete.email;
        
        // Delete all papers uploaded by this user
        const papers = await Paper.find({ uploadedBy: userEmail });
        
        // Delete the actual files
        for (const paper of papers) {
            const filePath = path.join(__dirname, 'uploads', path.basename(paper.path));
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }
        
        // Delete the paper records
        await Paper.deleteMany({ uploadedBy: userEmail });
        
        // Delete all comments by this user
        await Comment.deleteMany({ user: userEmail });
        
        // Delete all feedback by this user
        await Feedback.deleteMany({ user: userEmail });
        
        // Finally delete the user
        await User.findByIdAndDelete(req.params.id);
        
        res.json({ success: true, message: 'User and all their content deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error deleting user' });
    }
});

// Feedback management page - redirect to main admin page
app.get('/admin/feedback', isAuthenticated, isAdmin, async (req, res) => {
    res.redirect('/admin');
});

// Mark feedback as read
app.post('/admin/mark-feedback-read/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        await Feedback.findByIdAndUpdate(req.params.id, { isRead: true });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error updating feedback' });
    }
});

// Delete feedback
app.post('/admin/delete-feedback/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        await Feedback.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Feedback deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error deleting feedback' });
    }
});

// =================== PAPER ROUTES ===================

// Paper detail view
app.get('/paper/:id', isAuthenticated, isNotBlocked, async (req, res) => {
    try {
        const paper = await Paper.findById(req.params.id);
        if (!paper) {
            return res.status(404).send("Paper not found");
        }
        
        // Increment views
        paper.views += 1;
        await paper.save();
        
        // Get comments for this paper
        const comments = await Comment.find({ paper: paper._id }).sort({ createdAt: -1 });
            
        res.render('paperDetails', { 
            user: req.session.user, 
            paper, 
            comments,
            isAdmin: req.session.user.isAdmin
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading paper details.");
    }
});

// Add comment
app.post('/paper/:id/comment', isAuthenticated, isNotBlocked, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || content.trim() === '') {
            return res.status(400).json({ success: false, message: 'Comment cannot be empty' });
        }
        
        await Comment.create({
            paper: req.params.id,
            user: req.session.user.email,
            content
        });
        
        res.redirect(`/paper/${req.params.id}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Delete comment (admin or owner)
app.post('/comment/:id/delete', isAuthenticated, async (req, res) => {
    try {
        const comment = await Comment.findById(req.params.id);
        
        if (!comment) {
            return res.status(404).json({ success: false, message: 'Comment not found' });
        }
        
        // Only admin or comment owner can delete
        if (comment.user !== req.session.user.email && !req.session.user.isAdmin) {
            return res.status(403).json({ success: false, message: 'Not authorized to delete this comment' });
        }
        
        const paperId = comment.paper;
        await Comment.findByIdAndDelete(req.params.id);
        
        res.redirect(`/paper/${paperId}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Delete paper route (admin only)
app.post('/delete-paper/:id', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const paper = await Paper.findById(req.params.id);
        
        if (!paper) {
            return res.status(404).json({ success: false, message: 'Paper not found' });
        }
        
        // Delete file from filesystem
        const filePath = path.join(__dirname, 'uploads', path.basename(paper.path));
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        
        // Delete associated comments
        await Comment.deleteMany({ paper: paper._id });
        
        // Delete from database
        await Paper.findByIdAndDelete(req.params.id);
        
        res.json({ success: true, message: 'Paper deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'An error occurred during deletion' });
    }
});

// View all uploads route
app.get("/all-uploads", isAuthenticated, isNotBlocked, async (req, res) => {
    try {
        const papers = await Paper.find().sort({ uploadedAt: -1 });
        res.render("alluploads", { 
            user: req.session.user,
            papers: papers,
            isAdmin: req.session.user.isAdmin
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading uploads.");
    }
});

// Submit feedback
app.post('/feedback', isAuthenticated, isNotBlocked, async (req, res) => {
    try {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ success: false, message: 'Feedback cannot be empty' });
        }
        
        await Feedback.create({
            user: req.session.user.email,
            message
        });
        
        res.json({ success: true, message: 'Feedback submitted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'An error occurred' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    initAdmin(); // Initialize admin user
});