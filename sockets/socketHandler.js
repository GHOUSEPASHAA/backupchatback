const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Message = require('../models/Message');
const Group = require('../models/Group');
const { JWT_SECRET } = require('../middleware/auth');
const { encryptMessage } = require('../utils/encryption');

const socketHandler = (io) => {
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
            socket.emit('userId', userId);
            console.log(`User ${userId} authenticated and joined personal room`);
        } catch (err) {
            console.error('Connection token error:', err.message);
            socket.disconnect(true);
            return;
        }

        socket.on('joinGroup', (groupId) => {
            socket.join(groupId);
            console.log(`User ${socket.userId} joined group room ${groupId}`);
        });

        socket.on('leaveGroup', (groupId) => {
            socket.leave(groupId);
            console.log(`User ${socket.userId} left group room ${groupId}`);
        });

        socket.on('chatMessage', async (msgData) => {
            try {
                const sender = await User.findById(socket.userId).lean();
                if (!sender) throw new Error('Sender not found');

                if (msgData.group) {
                    const group = await Group.findById(msgData.group);
                    if (!group) throw new Error('Group not found');
                    const member = group.members.find(m => m.userId.toString() === socket.userId);
                    if (group.creator.toString() !== socket.userId && (!member || !member.canSendMessages)) {
                        socket.emit('error', { message: 'No permission to send messages in this group' });
                        return;
                    }
                }

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
                        io.to(msgData.group).emit('chatMessage', fileMessage);
                    }
                    return;
                }

                let message = {
                    sender: socket.userId,
                    timestamp: new Date(),
                    tempId: msgData.tempId,
                };

                if (msgData.recipient) {
                    const recipient = await User.findById(msgData.recipient).lean();
                    if (!recipient) throw new Error('Recipient not found');

                    const encryptedContent = encryptMessage(msgData.content, recipient.publicKey);
                    message.plaintextContent = msgData.content;
                    message.encryptedContent = encryptedContent;
                    message.recipient = msgData.recipient;

                    const savedMessage = await Message.create(message);
                    const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name').lean();

                    io.to(msgData.recipient).emit('chatMessage', {
                        ...populatedMessage,
                        sender: { _id: populatedMessage.sender._id, name: populatedMessage.sender.name },
                        content: populatedMessage.encryptedContent,
                        tempId: msgData.tempId,
                    });

                    io.to(socket.userId).emit('chatMessage', {
                        ...populatedMessage,
                        sender: { _id: populatedMessage.sender._id, name: populatedMessage.sender.name },
                        content: populatedMessage.plaintextContent,
                        tempId: msgData.tempId,
                    });
                } else if (msgData.group) {
                    message.group = msgData.group;
                    message.plaintextContent = msgData.content;
                    message.encryptedContent = null;

                    const savedMessage = await Message.create(message);
                    const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'name').lean();

                    io.to(msgData.group).emit('chatMessage', {
                        ...populatedMessage,
                        sender: { _id: populatedMessage.sender._id, name: populatedMessage.sender.name },
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
};

module.exports = socketHandler;