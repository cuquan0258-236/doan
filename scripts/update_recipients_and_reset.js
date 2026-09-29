const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const ruleEngineService = require('../services/ruleEngineService');

const TARGET_RECIPIENT = 'phanquan2973@gmail.com';
const DB_URI = 'mongodb://localhost:27017/mini_soar';

async function main() {
    await mongoose.connect(DB_URI);
    console.log('[Update] Kết nối MongoDB thành công');

    const EmailRecord = require('../models/EmailRecord');
    const docs = await EmailRecord.find();
    console.log(`[Update] Tìm thấy ${docs.length} email records`);

    for (const doc of docs) {
        let filePath = doc.emlFilePath;
        if (!path.isAbsolute(filePath)) {
            filePath = path.join(__dirname, '..', filePath);
        }

        let newHash = doc.sha256Hash;
        let newSize = doc.fileSize;

        if (fs.existsSync(filePath)) {
            let content = fs.readFileSync(filePath, 'utf8');

            // Tìm vị trí kết thúc header
            let headerEnd = content.indexOf('\r\n\r\n');
            let sep = '\r\n\r\n';
            if (headerEnd === -1) {
                headerEnd = content.indexOf('\n\n');
                sep = '\n\n';
            }

            if (headerEnd !== -1) {
                let headers = content.substring(0, headerEnd);
                let body = content.substring(headerEnd + sep.length);

                // Regex thay thế To: header (hỗ trợ cả header gập dòng multiline)
                const toRegex = /^To:.*?(?=\r?\n[^\t\s]|\Z)/ms;
                if (toRegex.test(headers)) {
                    headers = headers.replace(toRegex, `To: ${TARGET_RECIPIENT}`);
                } else {
                    headers = headers + `\r\nTo: ${TARGET_RECIPIENT}`;
                }

                const updatedContent = headers + sep + body;
                fs.writeFileSync(filePath, updatedContent, 'utf8');

                const buffer = fs.readFileSync(filePath);
                newHash = crypto.createHash('sha256').update(buffer).digest('hex');
                newSize = buffer.length;
            }
        } else {
            console.warn(`[Update] Cảnh báo: File không tồn tại: ${filePath}`);
        }

        // Cập nhật record
        doc.recipient = TARGET_RECIPIENT;
        doc.sha256Hash = newHash;
        doc.fileSize = newSize;

        const hasAnyAnalysis = Boolean(
            doc.headerAnalysis || 
            doc.contentAnalysis || 
            doc.urlAnalysis || 
            doc.attachmentAnalysis || 
            doc.iocAnalysis
        );

        if (!hasAnyAnalysis) {
            doc.riskLevel = null;
            doc.riskScore = null;
            doc.overallRiskScore = null;
            doc.ruleEvaluation = null;
            doc.responseActions = [];
            console.log(`[Update] Email ${doc._id} (${doc.sender}): Đặt UNANALYZED (recipient -> ${TARGET_RECIPIENT})`);
        } else {
            const ruleEval = ruleEngineService.evaluateEmail(doc);
            doc.riskScore = ruleEval.totalScore;
            doc.overallRiskScore = ruleEval.totalScore;
            doc.riskLevel = ruleEval.verdict;
            doc.ruleEvaluation = ruleEval;
            if (ruleEval.verdict === 'MALICIOUS' || ruleEval.verdict === 'SUSPICIOUS') {
                doc.responseActions = ruleEval.playbookActions || [];
            } else {
                doc.responseActions = [];
            }
            console.log(`[Update] Email ${doc._id} (${doc.sender}): Đã phân tích (Score: ${doc.riskScore}, Verdict: ${doc.riskLevel})`);
        }

        await doc.save();
    }

    console.log('[Update] Hoàn tất cập nhật 100% email!');
    process.exit(0);
}

main().catch(err => {
    console.error('[Update] Lỗi:', err);
    process.exit(1);
});
