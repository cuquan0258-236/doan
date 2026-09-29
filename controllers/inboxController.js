const EmailRecord = require('../models/EmailRecord');
const { runCollector } = require('../workers/emailWorker');
const ruleEngineService = require('../services/ruleEngineService');
const crypto = require('crypto');
const fs = require('fs');

/**
 * GET /api/inbox
 * Liệt kê email đã thu thập (phân trang) kèm đánh giá Rule Engine
 */
exports.listEmails = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;

        const [rawEmails, total] = await Promise.all([
            EmailRecord.find()
                .sort({ collectedAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            EmailRecord.countDocuments()
        ]);

        // Đánh giá động qua Rule Engine cho từng email
        const emails = rawEmails.map(email => {
            const ruleEval = ruleEngineService.evaluateEmail(email);
            const isUnanalyzed = ruleEval.verdict === 'UNANALYZED';
            return {
                ...email,
                ruleEvaluation: isUnanalyzed ? null : ruleEval,
                riskScore: isUnanalyzed ? null : ruleEval.totalScore,
                riskLevel: isUnanalyzed ? null : ruleEval.verdict
            };
        });

        return res.status(200).json({
            status: 'success',
            data: {
                emails,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi liệt kê inbox: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi truy vấn database', details: error.message });
    }
};

/**
 * GET /api/inbox/:id
 * Xem chi tiết 1 email record
 */
exports.getEmailDetail = async (req, res) => {
    try {
        const record = await EmailRecord.findById(req.params.id).lean();

        if (!record) {
            return res.status(404).json({ error: 'Không tìm thấy email record' });
        }

        return res.status(200).json({
            status: 'success',
            data: record
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi lấy chi tiết email: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi truy vấn database', details: error.message });
    }
};

/**
 * POST /api/inbox/collect
 * Trigger thu thập email thủ công (không chờ cron)
 */
exports.triggerCollect = async (req, res) => {
    try {
        console.log('[SOAR] Trigger thu thập email thủ công...');

        const result = await runCollector('imap');

        return res.status(200).json({
            status: 'success',
            message: `Thu thập hoàn tất: ${(result.collected || []).length} email mới`,
            data: result
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi thu thập: ${error.details || error.error}`);
        return res.status(500).json({
            error: 'Lỗi khi thu thập email',
            details: error.details || error.error
        });
    }
};

/**
 * GET /api/inbox/:id/verify
 * Xác minh tính toàn vẹn: so sánh SHA-256 trong DB với hash tính lại từ file
 */
exports.verifyIntegrity = async (req, res) => {
    try {
        const record = await EmailRecord.findById(req.params.id).lean();

        if (!record) {
            return res.status(404).json({ error: 'Không tìm thấy email record' });
        }

        // Kiểm tra file tồn tại
        if (!fs.existsSync(record.emlFilePath)) {
            return res.status(404).json({
                error: 'File .eml không tồn tại trên disk',
                emlFilePath: record.emlFilePath
            });
        }

        // Tính lại SHA-256 từ file hiện tại
        const fileBuffer = fs.readFileSync(record.emlFilePath);
        const currentHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        const isIntact = currentHash === record.sha256Hash;

        return res.status(200).json({
            status: 'success',
            data: {
                emailId: record._id,
                messageId: record.messageId,
                storedHash: record.sha256Hash,
                currentHash: currentHash,
                integrity: isIntact ? 'INTACT' : 'TAMPERED',
                verifiedAt: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi xác minh: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi xác minh tính toàn vẹn', details: error.message });
    }
};
