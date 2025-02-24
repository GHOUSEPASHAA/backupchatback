const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Null for group messages
    group: String, // Group name if applicable
    content: String, // Encrypted content
    fileUrl: String, // URL to uploaded file (if any)
    timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Message', messageSchema);