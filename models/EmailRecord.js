const mongoose = require('mongoose');

const emailRecordSchema = new mongoose.Schema({
    messageId: {
        type: String,
        unique: true,
        required: true,
        index: true
    },
    sender: {
        type: String,
        default: 'Unknown'
    },
    recipient: {
        type: String,
        default: 'Unknown'
    },
    subject: {
        type: String,
        default: 'No Subject'
    },
    receivedAt: {
        type: Date,
        default: null
    },
    collectedAt: {
        type: Date,
        default: Date.now
    },
    sha256Hash: {
        type: String,
        required: true
    },
    emlFilePath: {
        type: String,
        required: true
    },
    fileSize: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['collected', 'analyzing', 'analyzed', 'error'],
        default: 'collected'
    },
    authResults: {
        type: String,
        default: 'Not Found'
    },
    headerAnalysis: {
        type: mongoose.Schema.Types.Mixed,
        default: null
    },
    riskScore: {
        type: Number,
        default: null
    },
    riskLevel: {
        type: String,
        enum: ['LOW', 'MEDIUM', 'HIGH', null],
        default: null
    },
    contentAnalysis: {
        type: mongoose.Schema.Types.Mixed,
        default: null
    },
    socialEngineeringScore: {
        type: Number,
        default: null
    },
    contentVerdict: {
        type: String,
        enum: ['PHISHING', 'SUSPICIOUS', 'SAFE', null],
        default: null
    },
    urlAnalysis: {
        type: mongoose.Schema.Types.Mixed,
        default: null
    }
}, {
    timestamps: true // Tự động thêm createdAt, updatedAt
});

module.exports = mongoose.model('EmailRecord', emailRecordSchema);
