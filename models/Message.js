// const mongoose = require('mongoose');

// const messageSchema = new mongoose.Schema({
//     sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
//     recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Null for group messages
//     group: String, // Group name if applicable
//     content: String, // Encrypted content
//     fileUrl: String, // URL to uploaded file (if any)
//     timestamp: { type: Date, default: Date.now },
// });

// module.exports = mongoose.model('Message', messageSchema);
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Null for group messages
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', default: null },   // Changed to ObjectId reference
    plaintextContent: { type: String, default: null },                             // Plaintext for sender
    encryptedContent: { type: String, default: null },                             // Encrypted for recipient
    fileUrl: { type: String, default: null },                                     // URL to uploaded file (if any)
    timestamp: { type: Date, default: Date.now },                                 // Message timestamp
});

module.exports = mongoose.model('Message', messageSchema);