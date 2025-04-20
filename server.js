console.log("--- Server.js file executing ---"); // Log to confirm file execution

// --- Import necessary libraries ---
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
require('dotenv').config();

// --- Create instances ---
const app = express();
const prisma = new PrismaClient();

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;
const BACKEND_URL = process.env.BACKEND_URL; // Added for absolute callback URL

// Check for essential environment variables
if (!JWT_SECRET || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !SESSION_SECRET || !FRONTEND_URL || !BACKEND_URL) {
    console.error("FATAL ERROR: Missing required environment variables (JWT_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET, FRONTEND_URL, BACKEND_URL). Check .env file and hosting platform environment settings.");
    process.exit(1);
}

// --- Global Middleware ---
app.use(cors()); // Consider restricting origin in production: app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());

// Session Configuration (BEFORE Passport initialization)
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // cookie: { secure: process.env.NODE_ENV === 'production' } // Enable for HTTPS
}));

// Passport Middleware Initialization (AFTER session)
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Configuration ---

// Google OAuth 2.0 Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    // Use the full, absolute HTTPS URL for the callback
    callbackURL: `${BACKEND_URL}/api/auth/google/callback`, // Use environment variable
    scope: ['profile', 'email']
  },
  async (accessToken, refreshToken, profile, done) => {
    console.log('Google Callback Profile Received:', { id: profile.id, email: profile.emails?.[0]?.value });
    try {
      let user = await prisma.user.findUnique({ where: { googleId: profile.id } });
      if (!user) {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("No email found in Google profile."), null);
        user = await prisma.user.findUnique({ where: { email: email } });
        if (user) {
          user = await prisma.user.update({ where: { email: email }, data: { googleId: profile.id } });
          console.log(`Linked Google ID ${profile.id} to existing user ${user.email}`);
        } else {
          console.log(`Creating new user for Google ID ${profile.id}, email ${email}`);
          const createData = { googleId: profile.id, email: email, passwordHash: '' }; // Use empty string workaround
          console.log("Attempting prisma.user.create with data:", createData);
          user = await prisma.user.create({ data: createData });
          console.log(`Created new user via Google: ${user.email}`);
        }
      } else {
         console.log(`Found existing user via Google ID: ${user.email}`);
      }
      return done(null, user);
    } catch (error) {
      console.error("Error in Google OAuth Strategy Verify Callback:", error);
      return done(error, null);
    }
  }
));

// Serialize user ID into the session
passport.serializeUser((user, done) => {
    console.log("Serializing user:", user.id);
    done(null, user.id);
});

// Deserialize user from the session ID
passport.deserializeUser(async (id, done) => {
    console.log("Deserializing user ID:", id);
    try {
        const user = await prisma.user.findUnique({ where: { id: String(id) } });
        done(null, user);
    } catch(error) {
        console.error("Deserialize Error:", error);
        done(error, null);
    }
});


// --- Authentication Middleware Definition (for JWT) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            return res.sendStatus(403);
        }
        req.user = userPayload;
        next();
    });
};


// --- API Routes ---

// Test Route
app.get('/api/test', (req, res) => {
  res.json({ message: 'Backend API is running!' });
});

// --- Email/Password Authentication Routes ---
app.post('/api/auth/signup', async (req, res) => {
    // ... (includes password validation) ...
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
    // Password Strength Validation
    if (password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    if (!/[A-Z]/.test(password)) return res.status(400).json({ message: 'Password must contain at least one uppercase letter.' });
    if (!/[a-z]/.test(password)) return res.status(400).json({ message: 'Password must contain at least one lowercase letter.' });
    if (!/[0-9]/.test(password)) return res.status(400).json({ message: 'Password must contain at least one number.' });
    // End Validation
    try {
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ message: 'Email already in use.' });
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const user = await prisma.user.create({ data: { email, passwordHash } });
        const userResponse = { id: user.id, email: user.email, createdAt: user.createdAt };
        res.status(201).json({ message: 'User created successfully', user: userResponse });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ message: 'Error creating user.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
     // ... (includes check for empty passwordHash) ...
     const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
    try {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !user.passwordHash) return res.status(401).json({ message: 'Invalid credentials. Please use Google Sign-In if you registered with Google.' });
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials.' });
        const tokenPayload = { userId: user.id, email: user.email };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: 'Login successful', token });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Error logging in.' });
    }
});

// --- Google OAuth Routes ---
// Step 1: Redirect user to Google
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Step 2: Google redirects back here
app.get('/api/auth/google/callback',
  passport.authenticate('google', {
      // Use FRONTEND_URL for failure redirect (auth page)
      failureRedirect: `${FRONTEND_URL}/?error=google-auth-failed`,
      session: false // Don't rely on session after this point
  }),
  (req, res) => {
    // Successful Google authentication
    const user = req.user;
    if (!user) {
         console.error("Google callback success but req.user is missing.");
         return res.redirect(`${FRONTEND_URL}/?error=google-auth-error`);
    }
    console.log("Google callback successful, issuing JWT for user:", user.email);
    // Generate JWT
    const tokenPayload = { userId: user.id, email: user.email };
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });
    // Redirect back to frontend callback handler
    res.redirect(`${FRONTEND_URL}/auth/callback?token=${token}`);
  }
);


// --- Board Routes (Protected by JWT - authenticateToken middleware) ---
app.get('/api/boards', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    try {
        const boards = await prisma.board.findMany({ where: { userId: userId }, orderBy: { createdAt: 'asc' } });
        res.json(boards);
    } catch (error) { console.error("Get Boards Error:", error); res.status(500).json({ message: "Error fetching boards." }); }
});

app.post('/api/boards', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { name } = req.body;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    if (!name) return res.status(400).json({ message: 'Board name is required.' });
    try {
        const newBoard = await prisma.board.create({ data: { name, userId } });
        res.status(201).json(newBoard);
    } catch (error) { console.error("Create Board Error:", error); res.status(500).json({ message: "Error creating board." }); }
});

app.put('/api/boards/:boardId', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { boardId } = req.params;
    const { name } = req.body;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    if (!name) return res.status(400).json({ message: 'New board name is required.' });
    try {
        const board = await prisma.board.findUnique({ where: { id: boardId } });
        if (!board || board.userId !== userId) return res.status(404).json({ message: "Board not found or user not authorized." });
        await prisma.board.update({ where: { id: boardId }, data: { name } });
        res.json({ message: "Board updated successfully." });
    } catch (error) { console.error("Update Board Error:", error); res.status(500).json({ message: "Error updating board." }); }
});

app.delete('/api/boards/:boardId', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { boardId } = req.params;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    try {
        const board = await prisma.board.findUnique({ where: { id: boardId } });
        if (!board || board.userId !== userId) return res.status(404).json({ message: "Board not found or user not authorized." });
        await prisma.board.delete({ where: { id: boardId } });
        res.status(204).send();
    } catch (error) { console.error("Delete Board Error:", error); res.status(500).json({ message: "Error deleting board." }); }
});

// --- Task Routes (Protected by JWT - authenticateToken middleware) ---
app.get('/api/boards/:boardId/tasks', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { boardId } = req.params;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    try {
        const board = await prisma.board.findUnique({ where: { id: boardId } });
        if (!board) return res.status(404).json({ message: "Board not found." });
        if (board.userId !== userId) return res.status(403).json({ message: "User not authorized for this board." });
        const tasks = await prisma.task.findMany({ where: { boardId: boardId }, orderBy: { createdAt: 'asc' } });
        res.json(tasks);
    } catch (error) { console.error("Get Tasks Error:", error); res.status(500).json({ message: "Error fetching tasks." }); }
});

app.post('/api/boards/:boardId/tasks', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { boardId } = req.params;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    const { title, description, status, startDate, estimatedFinishDate, reminderDateTime, progress } = req.body;
    if (!title) return res.status(400).json({ message: "Task title is required." });
    const validStatuses = ['todo', 'inprogress', 'done'];
    const taskStatus = status || 'todo';
    if (!validStatuses.includes(taskStatus)) return res.status(400).json({ message: `Invalid status value.` });
    let taskProgress = progress ?? 0;
    if (taskStatus === 'done') taskProgress = 100; else if (taskStatus === 'todo') taskProgress = 0; else { const numProgress = parseInt(taskProgress, 10); taskProgress = (!isNaN(numProgress) && numProgress >= 0 && numProgress <= 100) ? numProgress : 0; }
    try {
        const board = await prisma.board.findUnique({ where: { id: boardId } });
        if (!board) return res.status(404).json({ message: "Board not found." });
        if (board.userId !== userId) return res.status(403).json({ message: "User not authorized for this board." });
        const newTask = await prisma.task.create({ data: { title, description, status: taskStatus, progress: taskProgress, startDate: startDate ? new Date(startDate) : null, estimatedFinishDate: estimatedFinishDate ? new Date(estimatedFinishDate) : null, reminderDateTime: reminderDateTime ? new Date(reminderDateTime) : null, boardId: boardId } });
        res.status(201).json(newTask);
    } catch (error) { console.error("Create Task Error:", error); res.status(500).json({ message: "Error creating task." }); }
});

app.put('/api/tasks/:taskId', authenticateToken, async (req, res) => {
    // ... (same as before, includes 25% rule) ...
    const { taskId } = req.params;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    const { title, description, status, startDate, estimatedFinishDate, reminderDateTime, progress } = req.body;
    const updateData = {};
    if (title !== undefined) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (startDate !== undefined) updateData.startDate = startDate ? new Date(startDate) : null;
    if (estimatedFinishDate !== undefined) updateData.estimatedFinishDate = estimatedFinishDate ? new Date(estimatedFinishDate) : null;
    if (reminderDateTime !== undefined) updateData.reminderDateTime = reminderDateTime ? new Date(reminderDateTime) : null;
    if (status !== undefined) {
         const validStatuses = ['todo', 'inprogress', 'done'];
         if (!validStatuses.includes(status)) return res.status(400).json({ message: `Invalid status value.` });
         updateData.status = status;
         if (status === 'todo') updateData.progress = 0;
         else if (status === 'done') updateData.progress = 100;
         else if (status === 'inprogress') {
             if (progress === undefined) updateData.progress = 25; else { const numProgress = parseInt(progress, 10); updateData.progress = (!isNaN(numProgress) && numProgress >= 0 && numProgress <= 100) ? numProgress : 25; }
         }
    } else if (progress !== undefined) {
         const numProgress = parseInt(progress, 10);
         if (isNaN(numProgress) || numProgress < 0 || numProgress > 100) return res.status(400).json({ message: "Invalid progress value." });
         updateData.progress = numProgress;
    }
    if (Object.keys(updateData).length === 0) return res.status(400).json({ message: "No valid update data provided." });
    try {
        const task = await prisma.task.findUnique({ where: { id: taskId }, include: { board: { select: { userId: true } } } });
        if (!task) return res.status(404).json({ message: "Task not found." });
        if (task.board.userId !== userId) return res.status(403).json({ message: "User not authorized." });
        if (updateData.progress !== undefined && updateData.status === undefined && task.status !== 'inprogress') { console.log(`Progress update ignored...`); delete updateData.progress; if (Object.keys(updateData).length === 0) return res.status(400).json({ message: `Progress cannot be updated...` }); }
        const updatedTask = await prisma.task.update({ where: { id: taskId }, data: updateData });
        res.json(updatedTask);
    } catch (error) { console.error("Update Task Error:", error); res.status(500).json({ message: "Error updating task." }); }
});

app.delete('/api/tasks/:taskId', authenticateToken, async (req, res) => {
    // ... (same as before) ...
    const { taskId } = req.params;
    const userId = req.user?.userId;
    if (!userId) return res.sendStatus(401);
    try {
        const task = await prisma.task.findUnique({ where: { id: taskId }, select: { board: { select: { userId: true } } } });
        if (!task) return res.status(404).json({ message: "Task not found." });
        if (task.board.userId !== userId) return res.status(403).json({ message: "User not authorized." });
        await prisma.task.delete({ where: { id: taskId } });
        res.status(204).send();
    } catch (error) { console.error("Delete Task Error:", error); res.status(500).json({ message: "Error deleting task." }); }
});


// --- Start the Server ---
async function main() {
    app.listen(PORT, () => {
        console.log(`Server listening on port ${PORT}`);
    });
}

main()
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  })
  .finally(async () => {
    // Optional: await prisma.$disconnect();
  });
