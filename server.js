const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const forge = require('node-forge');
const User = require('./models/User');
const Message = require('./models/Message');
const Group = require('./models/Group');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/employee-chat', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

const JWT_SECRET = 'your-secret-key';

function generateKeys() {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    return {
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
    };
}

const encryptMessage = (content, publicKeyPem) => {
    console.log('Encrypting with public key:', publicKeyPem.substring(0, 50) + '...');
    console.log('Original content:', content);
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(forge.util.encodeUtf8(content), 'RSA-OAEP');
    const encoded = forge.util.encode64(encrypted);
    console.log('Encrypted content:', encoded);
    return encoded;
};

const authenticate = (req, res, next) => {
    let token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    if (token.startsWith('Bearer ')) token = token.slice(7);

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.userId = decoded.id;
        next();
    });
};

// User Signup
app.post('/api/signup', async (req, res) => {
    const { name, email, password, location, designation } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already in use' });

        const { publicKey, privateKey } = generateKeys();
        const user = new User({ name, email, password, location, designation, publicKey, privateKey, status: 'Online' });
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
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    user.status = 'Online';
    await user.save();
    const token = jwt.sign({ id: user._id }, JWT_SECRET);
    res.json({ token, privateKey: user.privateKey });
});

// Get All Users
app.get('/api/users', authenticate, async (req, res) => {
    try {
        const users = await User.find({}, 'name _id status');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Group
app.post('/api/groups', authenticate, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Group name is required' });
        const group = new Group({ name, members: [req.userId] });
        await group.save();
        res.status(201).json(group);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Groups
app.get('/api/groups', authenticate, async (req, res) => {
    try {
        const groups = await Group.find({}, 'name _id');
        res.json(groups);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Private Messages
app.get('/api/messages/private/:userId', authenticate, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.userId, recipient: req.params.userId },
                { sender: req.params.userId, recipient: req.userId },
            ],
        }).populate('sender', 'name');

        // Format messages based on user role
        const formattedMessages = messages.map(msg => ({
            ...msg.toObject(),
            content: msg.sender._id.toString() === req.userId.toString()
                ? msg.plaintextContent  // Sender gets plaintext
                : msg.encryptedContent, // Recipient gets encrypted
        }));

        res.json(formattedMessages);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Group Messages
app.get('/api/messages/group/:groupId', authenticate, async (req, res) => {
    try {
        const messages = await Message.find({ group: req.params.groupId })
            .populate('sender', 'name');

        // Group messages use plaintextContent
        const formattedMessages = messages.map(msg => ({
            ...msg.toObject(),
            content: msg.plaintextContent,
        }));

        res.json(formattedMessages);
    } catch (error) {
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
        socket.emit('userId', userId); // Send user ID to client
    } catch (err) {
        console.error('Connection token error:', err.message);
        socket.disconnect(true);
        return;
    }

    socket.on('chatMessage', async (msgData) => {
        try {
            const sender = await User.findById(socket.userId);
            if (!sender) throw new Error('Sender not found');

            let message = {
                sender: socket.userId,
                timestamp: new Date(),
                tempId: msgData.tempId, // For client-side deduplication
            };

            if (msgData.recipient) {
                const recipient = await User.findById(msgData.recipient);
                if (!recipient) throw new Error('Recipient not found');
                console.log('Sender ID:', socket.userId);
                console.log('Recipient ID:', msgData.recipient);
                console.log('Encrypting for recipient:', recipient._id);

                const encryptedContent = encryptMessage(msgData.content, recipient.publicKey);
                message.plaintextContent = msgData.content; // Store plaintext for sender
                message.encryptedContent = encryptedContent; // Store encrypted for recipient
                message.recipient = msgData.recipient;

                const savedMessage = await Message.create(message);
                const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name');

                // Send encrypted version to recipient
                const recipientMessage = {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.encryptedContent,
                    tempId: msgData.tempId,
                };
                io.to(msgData.recipient).emit('chatMessage', recipientMessage);

                // Send plaintext version to sender
                const senderMessage = {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.plaintextContent,
                    tempId: msgData.tempId,
                };
                io.to(socket.userId).emit('chatMessage', senderMessage);
            } else if (msgData.group) {
                message.group = msgData.group;
                message.plaintextContent = msgData.content; // Group messages are plaintext
                message.encryptedContent = null;

                const savedMessage = await Message.create(message);
                const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name');

                // Send plaintext to all clients
                const groupMessage = {
                    ...populatedMessage.toObject(),
                    content: populatedMessage.plaintextContent,
                    tempId: msgData.tempId,
                };
                io.emit('chatMessage', groupMessage);
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
            console.error('Disconnect error:', err);
        }
    });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));