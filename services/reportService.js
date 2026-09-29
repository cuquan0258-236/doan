/**
 * Mini SOAR - Incident Report Service (Xuất Báo Cáo Sự Cố)
 * Tạo báo cáo sự cố an ninh chuẩn SOC dạng HTML/PDF in ấn chuẩn khổ A4
 * Tích hợp Module Phân loại Kiểu Tấn công Email Phishing (NIST & MITRE ATT&CK)
 */

const EmailRecord = require('../models/EmailRecord');
const ruleEngineService = require('./ruleEngineService');
const { classifyPhishingAttack } = require('./report/attackClassifier');
const { renderReportHtml, escapeHtml } = require('./report/reportTemplate');

/**
 * Thu thập và chuẩn hóa toàn bộ dữ liệu điều tra thành báo cáo sự cố tổng hợp
 */
async function buildIncidentData(emailId) {
    const email = await EmailRecord.findById(emailId);
    if (!email) {
        throw new Error(`Không tìm thấy email với ID: ${emailId}`);
    }

    // 1. Đánh giá Động cơ Quy tắc (Rule Engine)
    const ruleEvaluation = ruleEngineService.evaluateEmail(email);
    const overallScore = ruleEvaluation.totalScore;
    const overallLevel = ruleEvaluation.verdict;

    // Lấy danh sách hành động ngăn chặn thực tế theo Playbook của Rule Engine
    const responseActions = (ruleEvaluation.verdict === 'MALICIOUS' || ruleEvaluation.verdict === 'SUSPICIOUS')
        ? (ruleEvaluation.playbookActions || [])
        : [];

    // Cập nhật lại vào MongoDB
    email.overallRiskScore = overallScore;
    email.riskLevel = ruleEvaluation.verdict;
    email.ruleEvaluation = ruleEvaluation;
    email.responseActions = responseActions;
    try {
        await email.save();
    } catch (saveErr) {
        console.warn(`[RuleEngine] Cảnh báo lưu evaluation/responseActions: ${saveErr.message}`);
    }

    // 2. Thu thập tất cả IOCs và trạng thái ngăn chặn
    const allIOCs = [];
    const seenIOCs = new Set();
    const blockedValues = new Set();

    (responseActions || []).forEach(action => {
        (action.iocs || []).forEach(i => {
            if (i.value) blockedValues.add(i.value);
        });
    });

    // IOC từ Threat Intel
    if (email.iocAnalysis?.results) {
        email.iocAnalysis.results.forEach(i => {
            if (!seenIOCs.has(i.value)) {
                seenIOCs.add(i.value);
                allIOCs.push({
                    type: i.type,
                    value: i.value,
                    verdict: i.verdict,
                    source: i.sources?.join(', ') || 'Threat Intel',
                    isBlocked: blockedValues.has(i.value)
                });
            }
        });
    }

    // IOC từ URL Analysis
    if (email.urlAnalysis?.urls) {
        email.urlAnalysis.urls.forEach(u => {
            if (u.url && !seenIOCs.has(u.url)) {
                seenIOCs.add(u.url);
                allIOCs.push({
                    type: 'url',
                    value: u.url,
                    verdict: u.is_malicious ? 'MALICIOUS' : 'SUSPICIOUS',
                    source: 'URL Scanner / URLScan.io',
                    isBlocked: blockedValues.has(u.url)
                });
            }
        });
    }

    // 3. Phân loại kiểu tấn công Phishing chuyên sâu
    const threatClassification = classifyPhishingAttack(email, allIOCs, ruleEvaluation);

    const baseTime = email.receivedAt || email.collectedAt || email.createdAt || new Date();
    const spfVal = email.headerAnalysis?.authentication?.spf?.status || email.headerAnalysis?.authentication?.spf || 'N/A';
    const dkimVal = email.headerAnalysis?.authentication?.dkim?.status || email.headerAnalysis?.authentication?.dkim || 'N/A';
    const dmarcVal = email.headerAnalysis?.authentication?.dmarc?.status || email.headerAnalysis?.authentication?.dmarc || 'N/A';
    const domainAgeVal = email.headerAnalysis?.domain_analysis?.domain_age_days != null 
        ? `${email.headerAnalysis.domain_analysis.domain_age_days} ngày` 
        : 'Không xác định';

    const timeline = [
        {
            time: email.receivedAt || baseTime,
            event: 'Email Ingestion',
            desc: `Thu thập thành công từ Gmail IMAP. Tạo mã băm toàn vẹn chứng cứ SHA-256: ${email.sha256Hash?.substring(0, 16)}...`
        },
        {
            time: baseTime,
            event: 'Header & Domain Analysis',
            desc: `Kiểm tra SPF: ${typeof spfVal === 'string' ? spfVal.toUpperCase() : 'N/A'}, DKIM: ${typeof dkimVal === 'string' ? dkimVal.toUpperCase() : 'N/A'}, DMARC: ${typeof dmarcVal === 'string' ? dmarcVal.toUpperCase() : 'N/A'}. Tuổi tên miền: ${domainAgeVal}.`
        },
        {
            time: baseTime,
            event: 'AI Social Engineering Analysis',
            desc: `Mô hình AI Ollama phát hiện: ${email.contentAnalysis?.tactics?.join(', ') || 'Không phát hiện đòn tâm lý rõ rệt'}. Điểm thao túng: ${email.socialEngineeringScore || 0}/100.`
        },
        {
            time: baseTime,
            event: 'URL Deep Scan & Sandbox',
            desc: email.urlAnalysis ? `Bóc tách ${email.urlAnalysis.urls?.length || 0} liên kết. Phát hiện chuỗi Redirect Chain và gửi Sandbox URLScan.io.` : 'Không có liên kết ngoài.'
        },
        {
            time: baseTime,
            event: 'Attachment Sandbox & Antivirus',
            desc: email.attachmentAnalysis ? `Bóc tách tệp đính kèm, kiểm tra Magic Bytes và đối soát VirusTotal / Hybrid Analysis.` : 'Email không kèm tệp đính kèm.'
        },
        {
            time: baseTime,
            event: 'Threat Intelligence IOC Enrichment',
            desc: email.iocAnalysis ? `Đối chiếu 4 nguồn tình báo an ninh toàn cầu (AbuseIPDB, VirusTotal, PhishTank, URLhaus). Phát hiện ${email.iocAnalysis.maliciousCount || 0} IOCs độc hại.` : 'Chưa chạy làm giàu dữ liệu IOC.'
        }
    ];

    if (responseActions && responseActions.length > 0) {
        responseActions.forEach(act => {
            timeline.push({
                time: act.executedAt || email.createdAt,
                event: act.timelineEvent || `Automated Response Containment (${act.target.toUpperCase()})`,
                desc: act.timelineDesc || `Đã thực thi ${act.policy || act.action}. Trạng thái: ${act.status || 'SUCCESS'}.`
            });
        });
    }

    return {
        reportId: `INC-${(email._id || '').toString().substring(18).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`,
        generatedAt: new Date().toISOString(),
        classification: 'TLP:AMBER (Nội bộ SOC)',
        emailInfo: {
            id: email._id,
            subject: email.subject,
            sender: email.sender,
            recipient: email.recipient,
            receivedAt: email.receivedAt,
            sha256Hash: email.sha256Hash,
            fileSize: email.fileSize
        },
        riskAssessment: {
            overallScore: overallScore,
            severity: overallLevel,
            verdict: ruleEvaluation.verdict || (overallScore >= 75 ? 'MALICIOUS' : (overallScore >= 50 ? 'SUSPICIOUS' : (overallScore >= 25 ? 'LOW' : 'CLEAN'))),
            summary: overallScore >= 75 
                ? 'Phát hiện email có mức độ nguy hiểm cao với dấu hiệu lừa đảo mạo danh, liên kết độc hại đã xác thực hoặc kỹ thuật né tránh kiểm duyệt.'
                : overallScore >= 50
                ? 'Email có nhiều dấu hiệu nghi vấn và chỉ số rủi ro vượt ngưỡng an toàn, hệ thống tự động cách ly vào Spam.'
                : overallScore >= 25
                ? 'Email có một số chỉ số kỹ thuật bất thường ở mức độ thấp, cần lưu ý.'
                : 'Email hoàn toàn nằm trong ngưỡng an toàn.'
        },
        threatClassification: threatClassification,
        ruleEvaluation: ruleEvaluation,
        technicalAnalysis: {
            step1_collection: { hash: email.sha256Hash, path: email.emlFilePath },
            step2_header: email.headerAnalysis,
            step3_content: email.contentAnalysis,
            step4_urls: email.urlAnalysis,
            step5_attachments: email.attachmentAnalysis,
            step6_ioc: email.iocAnalysis
        },
        iocsList: allIOCs,
        timeline: timeline,
        responseActions: responseActions
    };
}

/**
 * Sinh chuỗi HTML hoàn chỉnh của Báo cáo sự cố an ninh SOC (Hỗ trợ in ấn chuẩn A4)
 */
async function generateHTMLReport(emailId) {
    const data = await buildIncidentData(emailId);
    return renderReportHtml(data);
}

module.exports = {
    buildIncidentData,
    generateHTMLReport,
    classifyPhishingAttack,
    escapeHtml
};
