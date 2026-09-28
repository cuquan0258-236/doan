const mongoose = require('mongoose');

/**
 * Tính toán thời gian hết hạn (TTL) động theo quy tắc Rule Engine:
 * - Malicious: 7 ngày
 * - Hash file not found/clean: 12 giờ
 * - Clean/not found (domain, URL, IP): 6 giờ
 */
function calculateTTL(verdict, iocType) {
    const now = Date.now();
    if (verdict === 'MALICIOUS') {
        // Lưu 7 ngày
        return new Date(now + 7 * 24 * 60 * 60 * 1000);
    }
    if (iocType === 'hash' && (verdict === 'SAFE' || verdict === 'UNKNOWN')) {
        // Lưu 12 giờ
        return new Date(now + 12 * 60 * 60 * 1000);
    }
    // Clean / not found (domain, URL, IP): Lưu 6 giờ
    return new Date(now + 6 * 60 * 60 * 1000);
}

const iocCacheSchema = new mongoose.Schema({
    iocValue: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        index: true
    },
    iocType: {
        type: String,
        enum: ['ip', 'domain', 'url', 'hash'],
        required: true,
        index: true
    },
    reputationScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    verdict: {
        type: String,
        enum: ['MALICIOUS', 'SUSPICIOUS', 'SAFE', 'UNKNOWN'],
        default: 'UNKNOWN'
    },
    sources: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    lastChecked: {
        type: Date,
        default: Date.now,
        index: true
    },
    // TTL Index: Tự động dọn dẹp theo expiresAt động
    expiresAt: {
        type: Date,
        default: function() {
            return calculateTTL(this.verdict, this.iocType);
        },
        index: { expires: 0 }
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('IOCCache', iocCacheSchema);
module.exports.calculateTTL = calculateTTL;
