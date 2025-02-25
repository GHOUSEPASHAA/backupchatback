const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const forge = require('node-forge');
const multer = require('multer');
const path = require('path');

// Import models
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');
const File = require('./models/File');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded files

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/employee-chat', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err.message));

// JWT Secret
const JWT_SECRET = 'your-secret-key';

// Multer Configuration for File Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// RSA Key Generation
function generateKeys() {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    return {
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
    };
}

// Message Encryption
const encryptMessage = (content, publicKeyPem) => {
    try {
        console.log('Encrypting with public key:', publicKeyPem.substring(0, 50) + '...');
        console.log('Original content:', content);
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
        const encrypted = publicKey.encrypt(forge.util.encodeUtf8(content), 'RSA-OAEP');
        const encoded = forge.util.encode64(encrypted);
        console.log('Encrypted content:', encoded);
        return encoded;
    } catch (error) {
        console.error('Encryption error:', error.message);
        throw error;
    }
};

// Authentication Middleware
const authenticate = (req, res, next) => {
    let token = req.headers['authorization'];
    if (!token) {
        console.log('No token provided in request');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    if (token.startsWith('Bearer ')) token = token.slice(7);

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        console.log('Authenticated user:', req.userId);
        next();
    } catch (err) {
        console.error('Token verification failed:', err.message);
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Routes

// Test Route
app.get('/test', (req, res) => {
    console.log('Test endpoint hit');
    res.send('Server is running');
});

// User Signup
app.post('/api/signup', upload.single('image'), async (req, res) => {
    const { name, email, password, location, designation } = req.body;
    console.log('Signup request:', { name, email });
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already in use' });

        const { publicKey, privateKey } = generateKeys();
        const userData = {
            name,
            email,
            password, // In production, hash this!
            location,
            designation,
            publicKey,
            privateKey,
            status: 'Online'
        };

        if (req.file) {
            userData.image = `/uploads/${req.file.filename}`; // Store image path
            console.log('Profile image uploaded:', req.file.filename);
        }

        const user = new User(userData);
        await user.save();
        const token = jwt.sign({ id: user._id }, JWT_SECRET);
        res.status(201).json({ token, privateKey });
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});
// User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login request:', { email });
    try {
        const user = await User.findOne({ email, password });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        user.status = 'Online';
        await user.save();
        const token = jwt.sign({ id: user._id }, JWT_SECRET);
        res.json({ token, privateKey: user.privateKey });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Users
app.get('/api/users', authenticate, async (req, res) => {
    console.log('GET /api/users called by user:', req.userId);
    try {
        const users = await User.find({}, 'name _id status');
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/users/:userId', authenticate, async (req, res) => {
    console.log('GET /api/users/:userId called by user:', req.userId, 'for user:', req.params.userId);
    try {
        const user = await User.findById(req.params.userId, 'name email location designation status image');
        if (!user) {
            console.log('User not found:', req.params.userId);
            return res.status(404).json({ error: 'User not found' });
        }
        console.log('User profile fetched:', user);
        res.json(user);
    } catch (error) {
        console.error('Error fetching user profile:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Group
app.post('/api/groups', authenticate, async (req, res) => {
    console.log('POST /api/groups called by user:', req.userId);
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Group name is required' });
        const group = new Group({ name, members: [req.userId] });
        await group.save();
        res.status(201).json(group);
    } catch (error) {
        console.error('Error creating group:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Groups
app.get('/api/groups', authenticate, async (req, res) => {
    console.log('GET /api/groups called by user:', req.userId);
    try {
        const groups = await Group.find({}, 'name _id');
        res.json(groups);
    } catch (error) {
        console.error('Error fetching groups:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// File Upload Endpoint
app.post('/api/upload', authenticate, upload.single('file'), async (req, res) => {
    console.log('POST /api/upload called by user:', req.userId);
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const fileDoc = new File({
            name: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size,
            mimeType: req.file.mimetype,
            path: `/uploads/${req.file.filename}`,
            sender: req.userId,
            recipient: req.body.recipient || null,
            group: req.body.group || null,
        });

        await fileDoc.save();

        const fileData = {
            name: req.file.originalname,
            url: `http://localhost:3000${fileDoc.path}`,
            size: req.file.size,
            mimeType: req.file.mimetype,
            _id: fileDoc._id
        };

        res.json(fileData);

        // Emit file message through socket
        const messageData = {
            sender: { _id: req.userId, name: (await User.findById(req.userId)).name },
            file: fileData,
            recipient: req.body.recipient || null,
            group: req.body.group || null,
            tempId: req.body.tempId,
            timestamp: new Date()
        };

        if (req.body.recipient) {
            io.to(req.body.recipient).emit('chatMessage', messageData);
            io.to(req.userId).emit('chatMessage', messageData);
        } else if (req.body.group) {
            io.emit('chatMessage', messageData);
        }
    } catch (error) {
        console.error('File upload error:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Private Messages (Including Files)
app.get('/api/messages/private/:userId', authenticate, async (req, res) => {
    console.log('GET /api/messages/private called by user:', req.userId);
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.userId, recipient: req.params.userId },
                { sender: req.params.userId, recipient: req.userId },
            ],
        }).populate('sender', 'name');

        const files = await File.find({
            $or: [
                { sender: req.userId, recipient: req.params.userId },
                { sender: req.params.userId, recipient: req.userId },
            ],
        }).populate('sender', 'name');

        const formattedMessages = messages.map(msg => ({
            ...msg.toObject(),
            content: msg.sender._id.toString() === req.userId.toString()
                ? msg.plaintextContent
                : msg.encryptedContent,
        }));

        const formattedFiles = files.map(file => ({
            sender: file.sender,
            file: {
                name: file.originalName,
                url: `http://localhost:3000${file.path}`,
                size: file.size,
                mimeType: file.mimeType,
                _id: file._id
            },
            recipient: file.recipient,
            timestamp: file.createdAt
        }));

        res.json([...formattedMessages, ...formattedFiles].sort((a, b) =>
            new Date(a.timestamp) - new Date(b.timestamp)
        ));
    } catch (error) {
        console.error('Error fetching private messages:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Group Messages (Including Files)
app.get('/api/messages/group/:groupId', authenticate, async (req, res) => {
    console.log('GET /api/messages/group called by user:', req.userId);
    try {
        const messages = await Message.find({ group: req.params.groupId })
            .populate('sender', 'name');

        const files = await File.find({ group: req.params.groupId })
            .populate('sender', 'name');

        const formattedMessages = messages.map(msg => ({
            ...msg.toObject(),
            content: msg.plaintextContent,
        }));

        const formattedFiles = files.map(file => ({
            sender: file.sender,
            file: {
                name: file.originalName,
                url: `http://localhost:3000${file.path}`,
                size: file.size,
                mimeType: file.mimeType,
                _id: file._id
            },
            group: file.group,
            timestamp: file.createdAt
        }));

        res.json([...formattedMessages, ...formattedFiles].sort((a, b) =>
            new Date(a.timestamp) - new Date(b.timestamp)
        ));
    } catch (error) {
        console.error('Error fetching group messages:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Socket.io Connection
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    const token = socket.handshake.auth.token;
    if (!token) {
        console.log('No token provided, disconnecting:', socket.id);
        socket.disconnect(true);
        return;
    }

    let userId;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
        socket.userId = userId;
        socket.join(userId);
        console.log(`User ${userId} joined with socket ID: ${socket.id}`);
        socket.emit('userId', userId);
    } catch (err) {
        console.error('Connection token error:', err.message);
        socket.disconnect(true);
        return;
    }

    socket.on('chatMessage', async (msgData) => {
        try {
            const sender = await User.findById(socket.userId);
            if (!sender) throw new Error('Sender not found');

            if (msgData.file) {
                const fileMessage = {
                    sender: { _id: socket.userId, name: sender.name },
                    file: msgData.file,
                    recipient: msgData.recipient || null,
                    group: msgData.group || null,
                    tempId: msgData.tempId,
                    timestamp: new Date()
                };
                if (msgData.recipient) {
                    io.to(msgData.recipient).emit('chatMessage', fileMessage);
                    io.to(socket.userId).emit('chatMessage', fileMessage);
                } else if (msgData.group) {
                    io.emit('chatMessage', fileMessage);
                }
                return;
            }

            let message = {
                sender: socket.userId,
                timestamp: new Date(),
                tempId: msgData.tempId,
            };

            if (msgData.recipient) {
                const recipient = await User.findById(msgData.recipient);
                if (!recipient) throw new Error('Recipient not found');
                console.log('Sending private message from:', socket.userId, 'to:', msgData.recipient);

                const encryptedContent = encryptMessage(msgData.content, recipient.publicKey);
                message.plaintextContent = msgData.content;
                message.encryptedContent = encryptedContent;
                message.recipient = msgData.recipient;

                const savedMessage = await Message.create(message);
                const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name');

                io.to(msgData.recipient).emit('chatMessage', {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.encryptedContent,
                    tempId: msgData.tempId,
                });

                io.to(socket.userId).emit('chatMessage', {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.plaintextContent,
                    tempId: msgData.tempId,
                });
            } else if (msgData.group) {
                message.group = msgData.group;
                message.plaintextContent = msgData.content;
                message.encryptedContent = null;

                const savedMessage = await Message.create(message);
                const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name');

                io.emit('chatMessage', {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.plaintextContent,
                    tempId: msgData.tempId,
                });
            }
        } catch (err) {
            console.error('Chat message error:', err.message);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    socket.on('disconnect', async () => {
        console.log('Client disconnected:', socket.id);
        try {
            const user = await User.findById(socket.userId);
            if (user) {
                user.status = 'Offline';
                await user.save();
                io.emit('statusUpdate', { userId: socket.userId, status: 'Offline' });
            }
        } catch (err) {
            console.error('Disconnect error:', err.message);
        }
    });
});

// Start Server
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Test endpoint: http://localhost:${PORT}/test`);
    console.log(`API endpoints: /api/signup, /api/login, /api/users, /api/groups, /api/upload, etc.`);
});