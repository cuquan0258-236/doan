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
        enum: ['MALICIOUS', 'SUSPICIOUS', 'LOW', 'CLEAN', 'INCONCLUSIVE', 'HIGH', 'MEDIUM', null],
        default: null
    },
    ruleEvaluation: {
        type: mongoose.Schema.Types.Mixed,
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
    },
    attachmentAnalysis: {
        type: mongoose.Schema.Types.Mixed,
        default: null
    },
    iocAnalysis: {
        type: mongoose.Schema.Types.Mixed,
        default: null
    },
    overallRiskScore: {
        type: Number,
        default: null
    },
    responseActions: [{
        target: { type: String, required: true },
        title: { type: String },
        action: { type: String, default: 'BLOCK' },
        policy: { type: String },
        iocs: [{
            type: { type: String },
            value: String,
            status: String
        }],
        status: { type: String, default: 'SUCCESS' },
        executedAt: { type: Date, default: Date.now },
        details: { type: mongoose.Schema.Types.Mixed, default: {} }
    }]
}, {
    timestamps: true // Tự động thêm createdAt, updatedAt
});

module.exports = mongoose.model('EmailRecord', emailRecordSchema);
