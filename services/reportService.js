/**
 * Mini SOAR - Incident Report Service (Xuất Báo Cáo Sự Cố)
 * Tạo báo cáo sự cố an ninh chuẩn SOC dạng HTML/PDF in ấn chuẩn khổ A4
 * Tích hợp Module Phân loại Kiểu Tấn công Email Phishing (NIST & MITRE ATT&CK)
 */

const EmailRecord = require('../models/EmailRecord');
const ruleEngineService = require('./ruleEngineService');

/**
 * Phân loại kiểu tấn công Email Phishing theo chuẩn quốc tế (NIST SP 800-61 / MITRE ATT&CK)
 */
function classifyPhishingAttack(email, allIOCs = []) {
    const indicators = [];
    const tactics = email.contentAnalysis?.tactics || [];
    const aiVerdict = email.contentVerdict || '';
    const aiSummary = email.contentAnalysis?.summary || '';
    const subject = (email.subject || '').toLowerCase();
    const sender = (email.sender || '').toLowerCase();
    const attachments = email.attachmentAnalysis?.files || [];
    const urls = email.urlAnalysis?.urls || [];
    const headerAuth = email.headerAnalysis?.authentication || {};
    const domainAge = email.headerAnalysis?.domain_analysis?.domain_age_days;

    // 1. Kiểm tra Phát tán Mã độc / Ransomware qua Tệp đính kèm (Malware Delivery)
    let hasMaliciousAttachment = false;
    attachments.forEach(file => {
        if (file.is_spoofed) {
            hasMaliciousAttachment = true;
            indicators.push(`Tệp đính kèm '${file.filename}' ngụy tạo đuôi file (Spoofed extension: ${file.file_type} giả ${file.magic_type})`);
        }
        if (file.vt_result?.malicious > 0) {
            hasMaliciousAttachment = true;
            indicators.push(`Mã băm tệp '${file.filename}' phát hiện bởi ${file.vt_result.malicious} Antivirus engines trên VirusTotal`);
        }
        if (file.hybrid_analysis?.verdict === 'malicious') {
            hasMaliciousAttachment = true;
            indicators.push(`Hybrid Analysis Sandbox kết luận tệp '${file.filename}' là độc hại (Malicious)`);
        }
    });

    if (hasMaliciousAttachment) {
        return {
            id: 'MALWARE_DELIVERY',
            nameVi: 'Phát tán Mã độc qua Tệp đính kèm (Malware / Ransomware Delivery)',
            severity: 'CRITICAL',
            icon: '☣️',
            mitre: {
                id: 'T1566.001',
                name: 'Spearphishing Attachment',
                url: 'https://attack.mitre.org/techniques/T1566/001/'
            },
            description: 'Kẻ tấn công đính kèm các tệp thực thi độc hại, tài liệu chứa mã macro, mã khai thác hoặc tệp ngụy tạo đuôi file (Double Extension) nhằm chiếm quyền điều khiển thiết bị của nạn nhân hoặc triển khai mã độc tống tiền (Ransomware).',
            indicators: indicators,
            remediation: 'Kích hoạt lệnh xóa email độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người dùng tải hoặc mở tệp đính kèm nguy hiểm.'
        };
    }

    // 2. Kiểm tra Đánh cắp Thông tin Xác thực (Credential Harvesting)
    let hasCredentialHarvesting = false;
    const credKeywords = ['login', 'signin', 'xác minh', 'mật khẩu', 'password', 'verify', 'account', 'security', 'cập nhật', 'portal', 'webmail', 'auth'];
    const matchesCredKeyword = credKeywords.some(k => subject.includes(k) || aiSummary.toLowerCase().includes(k));

    let maliciousUrlFound = false;
    urls.forEach(u => {
        if (u.is_malicious || u.risk_level === 'HIGH') {
            maliciousUrlFound = true;
            indicators.push(`Liên kết độc hại được phát hiện: ${u.url} (Điểm rủi ro Sandbox: ${u.risk_score || 'High'})`);
        }
        if (credKeywords.some(k => (u.url || '').toLowerCase().includes(k))) {
            hasCredentialHarvesting = true;
            indicators.push(`URL chứa đường dẫn trang xác thực/đăng nhập: ${u.url}`);
        }
    });

    allIOCs.forEach(ioc => {
        if (ioc.verdict === 'MALICIOUS') {
            indicators.push(`Chỉ số IOC '${ioc.value}' được xác minh độc hại từ nguồn ${ioc.source}`);
        }
    });

    if (hasCredentialHarvesting || (maliciousUrlFound && (tactics.includes('Urgency') || tactics.includes('Phishing Link')))) {
        return {
            id: 'CREDENTIAL_HARVESTING',
            nameVi: 'Đánh cắp Thông tin Xác thực (Credential Harvesting Phishing)',
            severity: 'HIGH',
            icon: '🎣',
            mitre: {
                id: 'T1566.002',
                name: 'Spearphishing Link / Phishing for Information (T1598.003)',
                url: 'https://attack.mitre.org/techniques/T1566/002/'
            },
            description: 'Kẻ tấn công gửi liên kết dẫn dụ người dùng tới trang web giả mạo (Fake Login Page) có giao diện giống hệt Microsoft 365, Google Workspace, Cổng Webmail hoặc Cổng Ngân hàng nhằm chiếm đoạt tài khoản, mật khẩu và mã xác thực đa yếu tố (MFA/OTP).',
            indicators: indicators.length > 0 ? indicators : ['Phát hiện liên kết ngoài kèm yêu cầu đăng nhập tài khoản'],
            remediation: 'Kích hoạt lệnh xóa email độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người nhận nhấp vào liên kết đăng nhập giả mạo và bảo vệ tài khoản.'
        };
    }

    // 3. Kiểm tra Giả mạo Lãnh đạo / Lừa đảo Doanh nghiệp (Business Email Compromise - BEC)
    const becKeywords = ['chuyển tiền', 'thanh toán', 'hóa đơn', 'invoice', 'wire transfer', 'ngân hàng', 'thay đổi số tài khoản', 'urgent payment', 'ceo', 'giám đốc'];
    const isBecContent = becKeywords.some(k => subject.includes(k) || aiSummary.toLowerCase().includes(k));
    const authFailed = (headerAuth.spf === 'fail' || headerAuth.spf === 'softfail' || headerAuth.dmarc === 'fail');

    if (isBecContent && (authFailed || (domainAge && domainAge < 60) || tactics.includes('Authority'))) {
        indicators.push(`Nội dung thư yêu cầu giao dịch tài chính hoặc thay đổi tài khoản nhận tiền khẩn cấp`);
        if (authFailed) indicators.push(`Xác thực người gửi thất bại (SPF: ${headerAuth.spf || 'fail'}, DMARC: ${headerAuth.dmarc || 'fail'})`);
        if (domainAge && domainAge < 60) indicators.push(`Tên miền gửi mới đăng ký gần đây (${domainAge} ngày), dấu hiệu tên miền mạo danh`);

        return {
            id: 'BEC_FRAUD',
            nameVi: 'Lừa đảo Doanh nghiệp / Giả mạo Lãnh đạo (Business Email Compromise - BEC)',
            severity: 'CRITICAL',
            icon: '💼',
            mitre: {
                id: 'T1566',
                name: 'Phishing for Business Email Compromise (T1598.002)',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Hình thức lừa đảo không cần mã độc kỹ thuật cao mà tập trung vào kỹ thuật thao túng xã hội (Social Engineering). Kẻ tấn công giả danh Lãnh đạo cấp cao (CEO, CFO) hoặc Đối tác quen thuộc, lợi dụng thẩm quyền để yêu cầu phòng kế toán chuyển tiền gấp vào tài khoản ngân hàng của thủ phạm.',
            indicators: indicators,
            remediation: 'Di chuyển thư vào thư mục Spam của Gmail hoặc xóa vào Thùng rác để ngăn chặn nhân sự thực hiện các giao dịch chuyển tiền gian lận.'
        };
    }

    // 4. Kiểm tra Mạo danh Thương hiệu Uy tín (Brand Impersonation)
    const brandNames = ['google', 'microsoft', 'apple', 'netflix', 'paypal', 'vietcombank', 'mbbank', 'techcombank', 'evn', 'viettel', 'vnpt', 'amazon', 'dhl', 'fedex', 'vnpost'];
    const brandMatch = brandNames.find(b => subject.includes(b) || sender.includes(b));
    if (brandMatch) {
        indicators.push(`Nội dung email mạo danh tổ chức / thương hiệu lớn: '${brandMatch.toUpperCase()}'`);
        if (authFailed) indicators.push(`Header người gửi không vượt qua xác thực SPF/DKIM của thương hiệu chính thức`);

        return {
            id: 'BRAND_IMPERSONATION',
            nameVi: `Mạo danh Thương hiệu Uy tín (${brandMatch.toUpperCase()} Impersonation)`,
            severity: 'HIGH',
            icon: '🏢',
            mitre: {
                id: 'T1566.002',
                name: 'Spearphishing Link (Brand Spoofing)',
                url: 'https://attack.mitre.org/techniques/T1566/002/'
            },
            description: `Kẻ tấn công lạm dụng uy tín của thương hiệu ${brandMatch.toUpperCase()} nhằm tạo cảm giác tin cậy giả tạo, lừa nạn nhân tin rằng đây là thông báo hóa đơn, sự cố thanh toán hoặc cập nhật bảo mật chính thức.`,
            indicators: indicators,
            remediation: 'Kích hoạt lệnh xóa thư độc hại (di chuyển vào Thùng rác Gmail) hoặc vứt vào thư mục Spam để ngăn chặn tương tác với thương hiệu bị mạo danh.'
        };
    }

    // 5. Kiểm tra Đe dọa Khóa Tài khoản Khẩn cấp (Account Suspension Hoax)
    const suspensionKeywords = ['khóa', 'đóng', 'xóa', 'ngừng', 'chấm dứt', 'hết hạn', 'terminate', 'suspend', 'deactivate', 'expire'];
    if (suspensionKeywords.some(k => subject.includes(k) || aiSummary.toLowerCase().includes(k)) && (tactics.includes('Urgency') || tactics.includes('Fear'))) {
        indicators.push('Phát hiện đòn tâm lý gieo rắc sự sợ hãi (Fear) và thúc ép thời gian (Urgency)');
        indicators.push('Cảnh báo tài khoản sẽ bị đóng hoặc vô hiệu hóa trong thời gian ngắn (24h/48h)');

        return {
            id: 'ACCOUNT_SUSPENSION_HOAX',
            nameVi: 'Đe dọa Khóa / Đóng Tài khoản Khẩn cấp (Account Suspension Hoax)',
            severity: 'HIGH',
            icon: '⚠️',
            mitre: {
                id: 'T1204.001',
                name: 'User Execution: Malicious Link',
                url: 'https://attack.mitre.org/techniques/T1204/001/'
            },
            description: 'Kẻ tấn công lợi dụng tâm lý sợ bị mất dữ liệu hoặc gián đoạn công việc của nạn nhân để đưa ra tối hậu thư khẩn cấp (ví dụ: "Tài khoản của bạn sẽ bị hủy nếu không xác nhận trong 24 giờ"), khiến nạn nhân mất cảnh giác và bấm vào liên kết xấu.',
            indicators: indicators,
            remediation: 'Xóa email độc hại khỏi Hộp thư đến (di chuyển vào Thùng rác Gmail) để ngăn chặn tâm lý hoang mang và không bấm vào nút xác minh giả mạo.'
        };
    }

    // 6. Kiểm tra Lừa đảo Tài chính / Trúng thưởng (Financial Scam / Advance-Fee Fraud)
    const financialKeywords = ['trúng thưởng', 'xổ số', 'thừa kế', 'tiền thưởng', 'bồi thường', 'lottery', 'inheritance', 'crypto', 'bonus', 'investment'];
    if (financialKeywords.some(k => subject.includes(k) || aiSummary.toLowerCase().includes(k))) {
        indicators.push('Hứa hẹn tặng tiền thưởng, giải thưởng hoặc tài sản thừa kế giá trị cao');

        return {
            id: 'FINANCIAL_SCAM',
            nameVi: 'Lừa đảo Tài chính / Tiền thưởng Ảo (Financial Scam / Advance-Fee Fraud)',
            severity: 'MEDIUM',
            icon: '💰',
            mitre: {
                id: 'T1566',
                name: 'Phishing',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Mô hình lừa đảo kinh điển (như thư lừa đảo kiểu Nigeria / 419 Scam), đánh vào lòng tham hoặc sự ngây thơ bằng cách thông báo nạn nhân được nhận một khoản tiền khổng lồ, nhưng yêu cầu nộp một khoản phí nhỏ để làm thủ tục.',
            indicators: indicators,
            remediation: 'Vứt thư vào thư mục Spam của Gmail hoặc xóa vào Thùng rác để loại bỏ triệt để email lừa đảo khỏi Hộp thư đến.'
        };
    }

    // 7. Mặc định nếu có nguy cơ cao nhưng chưa rơi vào các nhóm cụ thể trên
    if (aiVerdict === 'PHISHING' || email.riskLevel === 'HIGH' || email.riskScore >= 50) {
        indicators.push('Phát hiện nội dung có đòn tâm lý Social Engineering và chỉ số rủi ro vượt ngưỡng an toàn');
        return {
            id: 'GENERIC_PHISHING',
            nameVi: 'Tấn công Lừa đảo Kỹ thuật Xã hội Tổng quát (Social Engineering Phishing)',
            severity: 'HIGH',
            icon: '🚨',
            mitre: {
                id: 'T1566',
                name: 'Phishing',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Email có nhiều đặc trưng của một chiến dịch lừa đảo trực tuyến nhắm mục tiêu, kết hợp các đòn tâm lý nhằm làm phân tâm và thao túng hành vi người nhận.',
            indicators: indicators,
            remediation: 'Tự động xử lý hộp thư: di chuyển vào thư mục Spam hoặc xóa vào Thùng rác Gmail nhằm cô lập thư khỏi người nhận.'
        };
    }

    // 8. Thư an toàn / Rủi ro thấp
    return {
        id: 'BENIGN_CLEAN',
        nameVi: 'Email Hợp lệ / An Toàn (Benign / Clean Email)',
        severity: 'LOW',
        icon: '🟢',
        mitre: {
            id: 'N/A',
            name: 'No Threat Detected',
            url: '#'
        },
        description: 'Không phát hiện bất kỳ dấu hiệu tấn công, liên kết độc hại, tệp đính kèm nguy hiểm hay đòn tâm lý bất thường nào trong email.',
        indicators: ['Đạt xác thực SPF/DKIM/DMARC hợp lệ', 'Không phát hiện liên kết hay mã độc trong danh sách đen'],
        remediation: 'Không yêu cầu hành động ứng phó. Email được phép lưu thông bình thường.'
    };
}

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
    const threatClassification = classifyPhishingAttack(email, allIOCs);

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
            verdict: email.contentVerdict || (overallScore >= 50 ? 'PHISHING' : 'SAFE'),
            summary: overallScore >= 50 
                ? 'Phát hiện email có mức độ nguy hiểm cao với dấu hiệu lừa đảo mạo danh, liên kết độc hại hoặc đòn tâm lý khẩn cấp.'
                : 'Email nằm trong ngưỡng an toàn hoặc có độ rủi ro thấp.'
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

    const severityColor = data.riskAssessment.severity === 'CRITICAL' ? '#eb3b5a'
        : data.riskAssessment.severity === 'HIGH' ? '#fa8231'
        : data.riskAssessment.severity === 'MEDIUM' ? '#f7b731' : '#20bf6b';

    const threatColor = data.threatClassification.severity === 'CRITICAL' ? '#eb3b5a'
        : data.threatClassification.severity === 'HIGH' ? '#fa8231'
        : data.threatClassification.severity === 'MEDIUM' ? '#f7b731' : '#20bf6b';

    const iocRows = data.iocsList.length > 0 ? data.iocsList.map((ioc, idx) => `
        <tr style="border-bottom: 1px solid #e0e0e0;">
            <td style="padding: 8px 12px; font-weight: bold; color: #555;">${idx + 1}</td>
            <td style="padding: 8px 12px;"><span class="badge badge-type">${ioc.type.toUpperCase()}</span></td>
            <td style="padding: 8px 12px; font-family: 'Consolas', monospace; font-size: 13px; word-break: break-all;">${escapeHtml(ioc.value)}</td>
            <td style="padding: 8px 12px;"><span class="badge ${ioc.verdict === 'MALICIOUS' ? 'badge-danger' : 'badge-warning'}">${ioc.verdict}</span></td>
            <td style="padding: 8px 12px; color: #666; font-size: 12px;">${escapeHtml(ioc.source)}</td>
            <td style="padding: 8px 12px;">
                ${ioc.isBlocked ? '<span class="badge badge-success">🛡️ ĐÃ CHẶN (BLOCKED)</span>' : '<span class="badge badge-secondary">CHƯA CHẶN</span>'}
            </td>
        </tr>
    `).join('') : '<tr><td colspan="6" style="padding:15px; text-align:center; color:#888;">Không ghi nhận IOCs độc hại trực tiếp.</td></tr>';

    const timelineHtml = data.timeline.map(t => `
        <div style="display: flex; gap: 16px; margin-bottom: 16px;">
            <div style="min-width: 140px; font-size: 12px; color: #777; font-family: monospace;">${new Date(t.time).toLocaleString('vi-VN')}</div>
            <div style="width: 3px; background: #3867d6; position: relative;">
                <div style="width: 9px; height: 9px; background: #3867d6; border-radius: 50%; position: absolute; left: -3px; top: 4px;"></div>
            </div>
            <div style="flex: 1; padding-left: 10px;">
                <strong style="color: #2c3e50; font-size: 13px;">${escapeHtml(t.event)}</strong>
                <p style="margin: 4px 0 0; color: #555; font-size: 13px; line-height: 1.5;">${escapeHtml(t.desc)}</p>
            </div>
        </div>
    `).join('');

    const responseRows = (data.responseActions.length > 0) ? data.responseActions.map((act, i) => {
        const title = act.title || `Lệnh ngăn chặn #${i + 1} — Mục tiêu: ${act.target?.toUpperCase() || 'HỆ THỐNG'}`;
        const logContent = act.logOutput || act.details?.logOutput || '';
        const summary = act.summaryText || `Số lượng IOCs cách ly: <strong>${act.iocs?.length || 0}</strong> | Chính sách: <strong>${escapeHtml(act.policy || 'DROP / REJECT')}</strong>`;

        return `
        <div style="background: #f8f9fa; border: 1px solid #e9ecef; border-left: 4px solid #20bf6b; border-radius: 6px; padding: 12px 16px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="color: #2c3e50; font-size: 13px;">${escapeHtml(title)}</strong>
                <span class="badge badge-success">${act.status || 'SUCCESS'}</span>
            </div>
            <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Thời gian thực thi: ${new Date(act.executedAt || data.generatedAt).toLocaleString('vi-VN')}</div>
            <div style="font-size: 12px; color: #333;">${summary}</div>
            ${logContent ? `<pre style="background: #2d3436; color: #00cec9; padding: 8px 12px; border-radius: 4px; font-size: 11px; margin-top: 6px; overflow-x: auto; white-space: pre-wrap; font-family: 'Consolas', monospace; line-height: 1.4;">${escapeHtml(logContent)}</pre>` : ''}
        </div>
        `;
    }).join('') : '<p style="color: #888; font-style: italic;">Chưa có lệnh phản ứng tự động nào được kích hoạt.</p>';

    return `
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>SOC Incident Report - ${data.reportId}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f1f2f6;
            color: #2f3542;
            margin: 0;
            padding: 20px;
        }
        .report-container {
            max-width: 960px;
            margin: 0 auto;
            background: #ffffff;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            border-radius: 8px;
            overflow: hidden;
            padding: 40px 50px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #2f3542;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }
        .header h1 {
            margin: 0 0 6px 0;
            font-size: 24px;
            color: #1e272e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-danger { background: #ffebee; color: #c62828; }
        .badge-warning { background: #fff8e1; color: #f57f17; }
        .badge-success { background: #e8f5e9; color: #2e7d32; }
        .badge-secondary { background: #eceff1; color: #455a64; }
        .badge-type { background: #e3f2fd; color: #1565c0; font-family: monospace; }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            background: #f8f9fa;
            border-radius: 6px;
            padding: 16px 20px;
            margin-bottom: 25px;
        }
        .meta-item {
            font-size: 13px;
        }
        .meta-item strong {
            color: #57606f;
            display: inline-block;
            width: 140px;
        }
        .section-title {
            font-size: 15px;
            color: #1e272e;
            text-transform: uppercase;
            border-left: 4px solid #3867d6;
            padding-left: 10px;
            margin: 28px 0 14px 0;
            letter-spacing: 0.5px;
            font-weight: bold;
        }
        .risk-banner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 18px 24px;
            border-radius: 8px;
            background: ${severityColor}15;
            border: 1px solid ${severityColor}40;
            margin-bottom: 25px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            margin-bottom: 20px;
        }
        .table th {
            background: #f1f2f6;
            color: #57606f;
            font-size: 12px;
            padding: 10px 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #ced6e0;
        }
        .no-print-bar {
            position: sticky;
            top: 0;
            z-index: 1000;
            background: #1e272e;
            color: #fff;
            padding: 12px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: -20px -20px 20px -20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        .btn {
            background: #3867d6;
            color: #fff;
            border: none;
            padding: 8px 18px;
            border-radius: 4px;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
        }
        .btn:hover { background: #2f55b8; }
        .btn-outline { background: transparent; border: 1px solid #747d8c; color: #ced6e0; }
        .btn-outline:hover { background: #ffffff20; }

        @media print {
            body { background: #fff; padding: 0; }
            .no-print-bar { display: none !important; }
            .report-container { box-shadow: none; padding: 10px; max-width: 100%; }
        }
    </style>
</head>
<body>

    <!-- Thanh công cụ in ấn (ẩn khi in ra giấy/PDF) -->
    <div class="no-print-bar">
        <div>
            <strong style="color: #00d2d3;">🛡️ MINI-SOAR INCIDENT RESPONSE REPORT</strong>
            <span style="color: #a4b0be; font-size: 12px; margin-left: 10px;">ID: ${data.reportId}</span>
        </div>
        <div style="display: flex; gap: 10px;">
            <button class="btn" onclick="window.print()">🖨️ In Báo Cáo / Lưu PDF (Ctrl + P)</button>
            <a href="javascript:window.close()" class="btn btn-outline">Đóng</a>
        </div>
    </div>

    <div class="report-container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>Báo Cáo Sự Cố An Ninh Mạng (SOC Incident Report)</h1>
                <div style="color: #57606f; font-size: 13px;">Hệ thống Tự động hóa Phân tích & Phản ứng Khẩn cấp (Mini-SOAR)</div>
            </div>
            <div style="text-align: right;">
                <div style="font-weight: bold; font-family: monospace; font-size: 14px; color: #2f3542;">${data.reportId}</div>
                <div style="font-size: 12px; color: #747d8c; margin-top: 4px;">Thời gian tạo: ${new Date(data.generatedAt).toLocaleString('vi-VN')}</div>
                <div style="margin-top: 6px;"><span class="badge badge-warning">${data.classification}</span></div>
            </div>
        </div>

        <!-- Risk Banner -->
        <div class="risk-banner">
            <div>
                <div style="font-size: 12px; text-transform: uppercase; color: #57606f; font-weight: bold; margin-bottom: 4px;">Đánh giá rủi ro tổng hợp (Overall Risk Assessment)</div>
                <div style="font-size: 20px; font-weight: bold; color: ${severityColor};">
                    ${data.riskAssessment.verdict} — MỨC ĐỘ ${data.riskAssessment.severity} (${data.riskAssessment.overallScore}/100)
                </div>
                <div style="font-size: 13px; color: #4b6584; margin-top: 4px;">${data.riskAssessment.summary}</div>
            </div>
            <div style="text-align: center; min-width: 90px; padding: 10px; background: #ffffff; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.05);">
                <div style="font-size: 28px; font-weight: bold; color: ${severityColor};">${data.riskAssessment.overallScore}</div>
                <div style="font-size: 10px; color: #888; text-transform: uppercase; font-weight: bold;">Điểm rủi ro</div>
            </div>
        </div>

        <!-- Section: Threat Classification & MITRE ATT&CK -->
        <div class="section-title">Phân Loại Kiểu Tấn Công Email Phishing (Phishing Threat Classification)</div>
        <div style="background: #ffffff; border: 1px solid #dcdde1; border-left: 5px solid ${threatColor}; border-radius: 8px; padding: 20px 24px; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                <div>
                    <div style="font-size: 11px; text-transform: uppercase; color: #7f8fa6; font-weight: bold; letter-spacing: 0.5px;">Loại hình chiến dịch tấn công xác định (Classified Attack Type)</div>
                    <div style="font-size: 18px; font-weight: bold; color: ${threatColor}; margin-top: 4px; display: flex; align-items: center; gap: 8px;">
                        <span>${data.threatClassification.icon}</span> ${data.threatClassification.nameVi}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 11px; text-transform: uppercase; color: #7f8fa6; font-weight: bold;">Ánh xạ Kỹ thuật MITRE ATT&CK&reg;</div>
                    <div style="margin-top: 4px;">
                        <span class="badge" style="background: #2f3542; color: #00d2d3; font-size: 12px; font-family: monospace;">
                            ${data.threatClassification.mitre.id} — ${data.threatClassification.mitre.name}
                        </span>
                    </div>
                </div>
            </div>

            <p style="font-size: 13px; color: #4b6584; line-height: 1.6; margin: 0 0 14px 0;">
                ${data.threatClassification.description}
            </p>

            <!-- Key Indicators -->
            <div style="background: #f8f9fa; border-radius: 6px; padding: 12px 16px; margin-bottom: 14px; border: 1px solid #e9ecef;">
                <div style="font-size: 12px; font-weight: bold; color: #2f3542; margin-bottom: 6px; text-transform: uppercase;">
                    🔍 Dấu hiệu & Bằng chứng nhận diện (Key Detection Indicators):
                </div>
                <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #57606f; line-height: 1.6;">
                    ${data.threatClassification.indicators.map(ind => `<li>${escapeHtml(ind)}</li>`).join('')}
                </ul>
            </div>

            <!-- Targeted SOC Remediation -->
            <div style="background: #fff8e1; border-left: 3px solid #ffa502; border-radius: 4px; padding: 10px 14px; font-size: 12px; color: #b7791f; line-height: 1.5;">
                <strong>⚡ Hướng dẫn Ứng phó Khẩn cấp (SOC Playbook Action):</strong> ${data.threatClassification.remediation}
            </div>
        </div>

        <!-- Section: SOAR Rule Engine Evaluation -->
        <div class="section-title">Ma Trận Đánh Giá Động Cơ Quy Tắc (SOAR Rule Engine Evaluation)</div>
        <div style="background: #ffffff; border: 1px solid #dcdde1; border-left: 5px solid ${data.ruleEvaluation.verdict === 'MALICIOUS' ? '#eb3b5a' : data.ruleEvaluation.verdict === 'SUSPICIOUS' ? '#fa8231' : data.ruleEvaluation.verdict === 'LOW' ? '#f7b731' : '#20bf6b'}; border-radius: 8px; padding: 20px 24px; margin-bottom: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.04);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #e9ecef; padding-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                <div>
                    <strong style="font-size: 15px; color: #2f3542;">Kết luận Phân cấp: <span style="color: ${data.ruleEvaluation.verdict === 'MALICIOUS' ? '#eb3b5a' : data.ruleEvaluation.verdict === 'SUSPICIOUS' ? '#fa8231' : data.ruleEvaluation.verdict === 'LOW' ? '#f7b731' : '#20bf6b'}; font-weight: bold;">${data.ruleEvaluation.verdict}</span></strong>
                    <div style="font-size: 12px; color: #7f8fa6; margin-top: 3px;">Hành động SOAR chỉ định: <strong style="color: #2f3542;">${escapeHtml(data.ruleEvaluation.actionNameVi)}</strong></div>
                </div>
                <div>
                    <span class="badge" style="font-size: 13px; background: ${data.ruleEvaluation.verdict === 'MALICIOUS' ? '#ffebee' : '#e8f5e9'}; color: ${data.ruleEvaluation.verdict === 'MALICIOUS' ? '#c62828' : '#2e7d32'}; border: 1px solid ${data.ruleEvaluation.verdict === 'MALICIOUS' ? '#eb3b5a' : '#20bf6b'}; padding: 6px 14px;">
                        Điểm Quy Tắc: ${data.ruleEvaluation.totalScore}/100
                    </span>
                </div>
            </div>

            ${data.ruleEvaluation.isHardRule ? `
                <div style="background: #ffebee; border-left: 4px solid #c62828; padding: 12px 16px; border-radius: 4px; margin-bottom: 16px;">
                    <strong style="color: #c62828; font-size: 13px;">🚨 KÍCH HOẠT HARD RULE (100 ĐIỂM - MALICIOUS TỨC THÌ):</strong>
                    <ul style="margin: 6px 0 0 0; padding-left: 20px; font-size: 12px; color: #b71c1c;">
                        ${data.ruleEvaluation.hardRuleHits.map(h => `<li>${escapeHtml(h)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}

            ${data.ruleEvaluation.typosquatInfo ? `
                <div style="background: #fff0f0; border-left: 4px solid #e74c3c; padding: 10px 14px; border-radius: 4px; margin-bottom: 12px; font-size: 12px; color: #c0392b;">
                    <strong>🎯 Cảnh Báo Typosquatting (+20đ):</strong> Phát hiện chuỗi <strong>'${escapeHtml(data.ruleEvaluation.typosquatInfo.matchedToken)}'</strong> giả mạo thương hiệu <strong>${escapeHtml(data.ruleEvaluation.typosquatInfo.brand.toUpperCase())}</strong> (Khoảng cách Levenshtein: ${data.ruleEvaluation.typosquatInfo.distance}) trong tên miền người gửi.
                </div>
            ` : ''}

            ${data.ruleEvaluation.isDomainNotFound ? `
                <div style="background: #fff8e7; border-left: 4px solid #e67e22; padding: 10px 14px; border-radius: 4px; margin-bottom: 12px; font-size: 12px; color: #d35400;">
                    <strong>⚠️ Cảnh Báo Tên Miền Không Tồn Tại (+25đ):</strong> Tên miền gửi không tồn tại trên hệ thống máy chủ định danh quốc tế (DNS/WHOIS No Match).
                </div>
            ` : ''}

            <!-- Capped Modules Breakdown -->
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px;">
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">Header Authentication</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.header} <span style="font-size: 11px; color: #888;">/ trần 25đ</span></div>
                </div>
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">Domain & Typosquatting</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.domainAge} <span style="font-size: 11px; color: #888;">/ trần 45đ</span></div>
                </div>
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">Nội dung AI LLM</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.llm} <span style="font-size: 11px; color: #888;">/ trần 20đ</span></div>
                </div>
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">URL Scanner</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.url} <span style="font-size: 11px; color: #888;">/ trần 35đ</span></div>
                </div>
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">Tệp Đính Kèm</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.attachment} <span style="font-size: 11px; color: #888;">/ trần 40đ</span></div>
                </div>
                <div style="background: #f8f9fa; padding: 10px 14px; border-radius: 6px; border: 1px solid #e9ecef;">
                    <div style="font-size: 11px; color: #7f8fa6; text-transform: uppercase;">Threat Intel IOCs</div>
                    <div style="font-size: 16px; font-weight: bold; color: #2f3542; margin-top: 2px;">${data.ruleEvaluation.moduleScores.ioc} <span style="font-size: 11px; color: #888;">/ trần 30đ</span></div>
                </div>
            </div>

            ${data.ruleEvaluation.correlationBonuses && data.ruleEvaluation.correlationBonuses.length > 0 ? `
                <div style="background: #fff8e1; border: 1px solid #ffeaa7; padding: 10px 14px; border-radius: 6px; margin-bottom: 12px; font-size: 12px; color: #d35400;">
                    <strong>⭐ Điểm Thưởng Tương Quan (Correlation Bonus):</strong>
                    ${data.ruleEvaluation.correlationBonuses.map(b => `<div style="margin-top: 2px;">+ ${b.points}đ: ${escapeHtml(b.rule)}</div>`).join('')}
                </div>
            ` : ''}

            ${data.ruleEvaluation.failSafeNotes && data.ruleEvaluation.failSafeNotes.length > 0 ? `
                <div style="background: #f1f2f6; border-left: 3px solid #70a1ff; padding: 8px 12px; border-radius: 4px; font-size: 11px; color: #2f3542;">
                    <strong>🛡️ Ghi chú An toàn Fail-Safe:</strong> ${data.ruleEvaluation.failSafeNotes.map(n => escapeHtml(n)).join(' | ')}
                </div>
            ` : ''}
        </div>

        <!-- Metadata -->
        <div class="meta-grid">
            <div class="meta-item"><strong>Người gửi (From):</strong> <span style="font-family: monospace;">${escapeHtml(data.emailInfo.sender)}</span></div>
            <div class="meta-item"><strong>Người nhận (To):</strong> <span style="font-family: monospace;">${escapeHtml(data.emailInfo.recipient)}</span></div>
            <div class="meta-item"><strong>Tiêu đề (Subject):</strong> <strong>${escapeHtml(data.emailInfo.subject)}</strong></div>
            <div class="meta-item"><strong>Thời gian nhận:</strong> ${data.emailInfo.receivedAt ? new Date(data.emailInfo.receivedAt).toLocaleString('vi-VN') : 'N/A'}</div>
            <div class="meta-item"><strong>Mã băm SHA-256:</strong> <span style="font-family: monospace; font-size: 11px;">${data.emailInfo.sha256Hash || 'N/A'}</span></div>
            <div class="meta-item"><strong>Kích thước tệp:</strong> ${(data.emailInfo.fileSize / 1024).toFixed(1)} KB</div>
        </div>

        <!-- Section: IOCs Table -->
        <div class="section-title">Danh mục Chỉ số Đe dọa (Indicators of Compromise - IOCs)</div>
        <table class="table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th style="width: 90px;">Loại</th>
                    <th>Giá trị IOC</th>
                    <th style="width: 110px;">Kết luận</th>
                    <th>Nguồn bóc tách</th>
                    <th style="width: 140px;">Trạng thái Phản ứng</th>
                </tr>
            </thead>
            <tbody>
                ${iocRows}
            </tbody>
        </table>

        <!-- Section: Response Actions -->
        <div class="section-title">Hành động Xử lý Hộp thư &amp; Ngăn chặn Tự động (Automated Mailbox Actions)</div>
        ${responseRows}

        <!-- Section: Timeline -->
        <div class="section-title">Dòng Thời Gian Điều Tra (Incident Timeline & Chain of Custody)</div>
        <div style="background: #ffffff; border: 1px solid #e9ecef; border-radius: 6px; padding: 20px 24px;">
            ${timelineHtml}
        </div>

        <!-- Footer / Signature -->
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; display: flex; justify-content: space-between; font-size: 12px; color: #888;">
            <div>Mini-SOAR Automated Investigation Platform &copy; 2026. Phân tích tự động chuẩn NIST SP 800-61 Rev. 2 & MITRE ATT&CK.</div>
            <div>Báo cáo bảo mật — TLP:AMBER</div>
        </div>
    </div>

</body>
</html>
    `;
}

function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

module.exports = {
    buildIncidentData,
    generateHTMLReport,
    classifyPhishingAttack
};
