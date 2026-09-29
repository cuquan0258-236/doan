/**
 * Mini SOAR - Phishing Attack Classifier (Module Phân Loại Tấn Công Phishing)
 * Tiêu chuẩn: NIST SP 800-61 Rev. 2 & MITRE ATT&CK Framework
 * 
 * Nhận diện 16 kỹ thuật tấn công email phishing từ dữ liệu điều tra đa tầng:
 * 0. Fail-Safe Clean Guard (Email An Toàn)
 * 1. HTML Smuggling (T1027.006)
 * 2. Password-Protected Archive (T1027)
 * 3. Spearphishing Attachment / Malware Delivery (T1566.001)
 * 4. Thread Hijacking (T1566)
 * 5. OAuth Consent Phishing (T1528)
 * 6. Adversary-in-the-Middle - AiTM (T1557)
 * 7. Callback Phishing TOAD (T1204 / T1566)
 * 8. URL Cloaking & Delayed Activation (T1566.002)
 * 9. BEC CEO Fraud (T1566)
 * 10. Vendor & Supply-Chain Phishing VEC (T1566 / T1195)
 * 11. Credential Harvesting (T1566.002)
 * 12. Brand Impersonation (T1566.002)
 * 13. Account Suspension Hoax (T1204.001)
 * 14. Financial Scam (T1566)
 * 15. Social Engineering Phishing (T1566)
 * 16. Benign / Clean Email (N/A)
 */

function classifyPhishingAttack(email, allIOCs = [], ruleEvaluation = null) {
    const indicators = [];
    const tactics = email.contentAnalysis?.tactics || email.contentAnalysis?.ai_analysis?.data?.tactics || [];
    const aiVerdict = email.contentVerdict || '';
    const aiSummary = email.contentAnalysis?.summary || email.contentAnalysis?.ai_analysis?.data?.explanation || '';
    const subject = (email.subject || '').toLowerCase();
    const sender = (email.sender || '').toLowerCase();
    const bodyText = (email.clean_body || email.body || email.contentAnalysis?.clean_body || '').toLowerCase();
    const attachments = email.attachmentAnalysis?.attachments || email.attachmentAnalysis?.files || [];
    const urls = email.urlAnalysis?.urls || [];
    const headerAuth = email.headerAnalysis?.authentication || {};
    const domainAge = email.headerAnalysis?.domain_analysis?.domain_age_days;
    const authFailed = (headerAuth.spf === 'fail' || headerAuth.spf === 'softfail' || headerAuth.dmarc === 'fail');

    // =========================================================================
    // 0. BẢO VỆ AN TOÀN (FAIL-SAFE / CLEAN VERDICT)
    // Nếu Rule Engine đã kết luận email là CLEAN / LOW (Điểm rủi ro < 35 và không có Hard Rule)
    // -> Đây là Email An Toàn, tuyệt đối KHÔNG gán bất kỳ kiểu tấn công nào!
    // =========================================================================
    const isCleanScore = (ruleEvaluation?.totalScore != null ? ruleEvaluation.totalScore < 35 : (email.overallRiskScore != null ? email.overallRiskScore < 35 : true));
    const isCleanVerdict = ruleEvaluation?.verdict === 'CLEAN' || ruleEvaluation?.verdict === 'LOW' || email.riskLevel === 'CLEAN' || email.riskLevel === 'LOW' || (ruleEvaluation == null && (email.overallRiskScore || 0) < 35);
    const isNotHardRule = !ruleEvaluation?.isHardRule && (!ruleEvaluation?.hardRuleHits || ruleEvaluation.hardRuleHits.length === 0);

    if (isCleanScore && isCleanVerdict && isNotHardRule) {
        return {
            id: 'BENIGN_CLEAN',
            nameVi: 'Email Hợp lệ / An Toàn (Benign / Clean Email)',
            severity: 'LOW',
            icon: '🟢',
            mitre: {
                id: 'N/A',
                name: 'Không phát hiện đe dọa (No Threat Detected)',
                url: '#'
            },
            description: 'Email hoàn toàn hợp lệ và an toàn. Các tiêu chuẩn xác thực danh tính người gửi (SPF/DKIM/DMARC) đều vượt qua kiểm tra, không phát hiện mã độc, liên kết lừa đảo hay đòn tâm lý bất thường.',
            indicators: [
                'Đạt chứng thực người gửi hợp lệ (SPF / DKIM / DMARC Pass)',
                'Không phát hiện liên kết độc hại trong cơ sở dữ liệu đe dọa',
                'Nội dung an toàn, không có đòn tâm lý thao túng'
            ],
            remediation: 'Không yêu cầu hành động ngăn chặn. Email được lưu thông bình thường trong Hộp thư đến (Inbox).'
        };
    }

    // =========================================================================
    // 1. HTML SMUGGLING (Kỹ thuật giấu mã độc trong HTML/JavaScript Client-Side)
    // MITRE ATT&CK: T1027.006 (HTML Smuggling)
    // =========================================================================
    const htmlAttachments = attachments.filter(f => {
        const ext = (f.extension || '').toLowerCase();
        const fname = (f.filename || '').toLowerCase();
        return ext === '.html' || ext === '.htm' || ext === '.svg' || fname.endsWith('.html') || fname.endsWith('.htm');
    });

    const hasHtmlSmugglingFlags = htmlAttachments.some(f => {
        const flags = (f.heuristics?.flags || []).join(' ').toLowerCase();
        return flags.includes('smuggling') || flags.includes('blob') || flags.includes('javascript') || flags.includes('download');
    });

    const bodyHasSmugglingKeywords = bodyText.includes('blob:') || bodyText.includes('createobjecturl') || bodyText.includes('mssaveoropenblob');

    if (htmlAttachments.length > 0 && (hasHtmlSmugglingFlags || bodyHasSmugglingKeywords || htmlAttachments.some(f => f.heuristics?.risk_level === 'HIGH'))) {
        htmlAttachments.forEach(f => indicators.push(`Tệp đính kèm '${f.filename}' sử dụng cấu trúc HTML/JavaScript ngụy tạo (HTML Smuggling) để tự tạo mã độc khi mở trên trình duyệt`));
        return {
            id: 'HTML_SMUGGLING',
            nameVi: 'Khai thác HTML Smuggling (HTML Smuggling Malware Delivery)',
            severity: 'CRITICAL',
            icon: '📦',
            mitre: {
                id: 'T1027.006',
                name: 'HTML Smuggling',
                url: 'https://attack.mitre.org/techniques/T1027/006/'
            },
            description: 'Kẻ tấn công đính kèm tệp HTML/SVG chứa mã JavaScript (như Blob API) để tự động lắp ráp và kích hoạt tải payload độc hại ngay trong trình duyệt của nạn nhân, vượt qua các cổng kiểm duyệt mạng và Sandbox thông thường.',
            indicators: indicators,
            remediation: 'Kích hoạt lệnh xóa email độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người nhận mở tệp HTML trên trình duyệt.'
        };
    }

    // =========================================================================
    // 2. PASSWORD-PROTECTED ARCHIVE (Tệp nén khóa mật khẩu né tránh Sandbox)
    // MITRE ATT&CK: T1027 (Binary Padding / Encrypted & Password-Protected Archive)
    // =========================================================================
    const archiveExtensions = ['.zip', '.rar', '.7z', '.iso', '.tar', '.gz', '.cab'];
    const archiveFiles = attachments.filter(f => archiveExtensions.some(ext => (f.filename || '').toLowerCase().endsWith(ext)));
    const passwordPattern = /(pass(word)?|mật khẩu|mat khau|passcode|code)[\s:]*(là|la|is)?[\s:]*['"]?[A-Za-z0-9@#!$%^&*_-]{3,20}['"]?/i;
    const mentionsPassword = passwordPattern.test(bodyText) || passwordPattern.test(aiSummary) || passwordPattern.test(subject);

    if (archiveFiles.length > 0 && (mentionsPassword || archiveFiles.some(f => (f.heuristics?.flags || []).some(fl => fl.includes('Password') || fl.includes('Encrypted'))))) {
        archiveFiles.forEach(f => indicators.push(`Tệp nén '${f.filename}' được khóa mật khẩu nhằm ngăn chặn hệ thống Antivirus/Sandbox tự động giải nén phân tích`));
        if (mentionsPassword) indicators.push('Nội dung thư cung cấp trực tiếp mật khẩu giải nén để người nhận tự mở');

        return {
            id: 'PASSWORD_PROTECTED_ARCHIVE',
            nameVi: 'Tệp Nén Khóa Mật Khẩu Né Sandbox (Password-Protected Archive Phishing)',
            severity: 'HIGH',
            icon: '🔐',
            mitre: {
                id: 'T1027',
                name: 'Obfuscated Files: Password-Protected Archive',
                url: 'https://attack.mitre.org/techniques/T1027/'
            },
            description: 'Kẻ tấn công đóng gói mã độc vào tệp nén có đặt mật khẩu (.zip, .rar, .7z) và gửi mật khẩu trong nội dung thư. Mục đích là làm tê liệt các hệ thống kiểm duyệt mã độc tự động (Sandbox không thể đọc ruột file nếu không có mật khẩu).',
            indicators: indicators,
            remediation: 'Xóa thư độc hại (di chuyển vào Thùng rác Gmail) và tuyệt đối không giải nén các tệp nén lạ có cung cấp sẵn mật khẩu trong thư.'
        };
    }

    // =========================================================================
    // 3. PHÁT TÁN MÃ ĐỘC QUA TỆP ĐÍNH KÈM THỰC THI / MACRO (Malware Delivery)
    // MITRE ATT&CK: T1566.001 (Spearphishing Attachment)
    // =========================================================================
    let hasMaliciousAttachment = false;

    if (ruleEvaluation) {
        if (ruleEvaluation.moduleScores?.attachment >= 20) hasMaliciousAttachment = true;
        (ruleEvaluation.hardRuleHits || []).forEach(hit => {
            const lowerHit = hit.toLowerCase();
            if (lowerHit.includes('tệp') || lowerHit.includes('magic bytes') || lowerHit.includes('virustotal') || lowerHit.includes('hybrid analysis') || lowerHit.includes('ngụy tạo')) {
                hasMaliciousAttachment = true;
                indicators.push(hit);
            }
        });
    }

    if (email.attachmentAnalysis?.overall_verdict === 'DANGEROUS' || (email.attachmentAnalysis?.high_risk_count || 0) > 0) {
        hasMaliciousAttachment = true;
    }

    attachments.forEach(file => {
        const fname = file.filename || '';
        const vtCount = file.sandbox_reports?.virustotal?.malicious_count || file.vt_result?.malicious || file.malicious_count || 0;
        const haScore = file.sandbox_reports?.hybrid_analysis?.threat_score || file.hybrid_analysis?.threat_score || file.threat_score || 0;
        const haVerdict = file.sandbox_reports?.hybrid_analysis?.verdict || file.hybrid_analysis?.verdict;
        const isDoubleExt = /\.(pdf|doc|docx|xls|xlsx|txt|rtf|jpg|png)\.(exe|scr|bat|com|vbs|lnk|pif|cmd|js|hta)$/i.test(fname) || fname.toLowerCase().includes('.pdf.exe');

        if (file.is_spoofed || isDoubleExt) {
            hasMaliciousAttachment = true;
            indicators.push(`Tệp đính kèm '${fname}' ngụy tạo đuôi file (Double Extension: giả dạng tài liệu nhưng thực chất là mã thực thi nguy hiểm)`);
        }
        if (vtCount > 0) {
            hasMaliciousAttachment = true;
            indicators.push(`Mã băm tệp '${fname}' phát hiện bởi ${vtCount} Antivirus engines trên VirusTotal`);
        }
        if (haVerdict === 'malicious' || haScore >= 70) {
            hasMaliciousAttachment = true;
            indicators.push(`Hybrid Analysis Sandbox kết luận tệp '${fname}' là độc hại (Threat Score: ${haScore || 100}/100)`);
        }
        if (file.heuristics?.risk_level === 'HIGH') {
            hasMaliciousAttachment = true;
            (file.heuristics.flags || []).forEach(flag => {
                if (!indicators.includes(flag)) indicators.push(flag);
            });
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
            indicators: indicators.length > 0 ? Array.from(new Set(indicators)) : ['Phát hiện tệp đính kèm có nguy cơ thực thi mã độc hại'],
            remediation: 'Kích hoạt lệnh xóa email độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người dùng tải hoặc mở tệp đính kèm nguy hiểm.'
        };
    }

    // =========================================================================
    // 4. THREAD HIJACKING (Cướp luồng hội thoại email cũ)
    // MITRE ATT&CK: T1566 (Email Thread / Conversation Hijacking)
    // =========================================================================
    const rawHeaders = email.headerAnalysis?.raw_headers || {};
    const hasThreadHeaders = Boolean(rawHeaders['in-reply-to'] || rawHeaders['references'] || rawHeaders['thread-index']);
    const isReplySubject = subject.startsWith('re:') || subject.startsWith('fwd:');

    if ((hasThreadHeaders || isReplySubject) && (authFailed || (domainAge && domainAge < 60) || ruleEvaluation?.typosquatInfo)) {
        indicators.push(`Email phản hồi vào luồng trao đổi cũ ('${email.subject}') nhưng địa chỉ người gửi không vượt qua xác thực SPF/DKIM`);
        if (domainAge && domainAge < 60) indicators.push(`Tên miền gửi chen ngang được đăng ký mới đây (${domainAge} ngày)`);

        return {
            id: 'THREAD_HIJACKING',
            nameVi: 'Cướp Luồng Hội Thoại Email (Email Thread / Conversation Hijacking)',
            severity: 'CRITICAL',
            icon: '🧵',
            mitre: {
                id: 'T1566',
                name: 'Phishing: Email Thread Hijacking',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Kẻ tấn công đã chiếm quyền điều khiển một tài khoản email trong chuỗi trao đổi công việc trước đó hoặc giả mạo tiêu đề Re:/Fwd: cùng header In-Reply-To để chèn link độc hại/hóa đơn giả vào giữa cuộc đối thoại đang diễn ra, khiến nạn nhân tin tưởng tuyệt đối.',
            indicators: indicators,
            remediation: 'Xóa thư khỏi Hộp thư đến (di chuyển vào Thùng rác Gmail). Liên hệ trực tiếp với người gửi qua điện thoại để xác minh luồng email bị chen ngang.'
        };
    }

    // =========================================================================
    // 5. OAUTH CONSENT PHISHING (Lừa cấp quyền ứng dụng bên thứ ba)
    // MITRE ATT&CK: T1528 (Steal Application Access Token - Illicit Consent Grant)
    // =========================================================================
    const oauthKeywords = ['oauth', 'authorize', 'consent', 'permissions', 'token', 'client_id', 'scope=mail', 'scope=user', 'scope=offline_access'];
    const isOAuthUrl = urls.some(u => {
        const uLower = (u.url || '').toLowerCase();
        return oauthKeywords.some(k => uLower.includes(k));
    });

    if (isOAuthUrl || subject.includes('cấp quyền') || subject.includes('grant permission') || bodyText.includes('đồng ý cấp quyền ứng dụng')) {
        urls.forEach(u => {
            const uLower = (u.url || '').toLowerCase();
            if (oauthKeywords.some(k => uLower.includes(k))) indicators.push(`Liên kết yêu cầu cấp quyền OAuth2 ứng dụng: ${u.url}`);
        });

        return {
            id: 'OAUTH_CONSENT_PHISHING',
            nameVi: 'Lừa Cấp Quyền Ứng Dụng (OAuth Consent / Illicit Consent Grant Phishing)',
            severity: 'HIGH',
            icon: '🔑',
            mitre: {
                id: 'T1528',
                name: 'Steal Application Access Token',
                url: 'https://attack.mitre.org/techniques/T1528/'
            },
            description: 'Kẻ tấn công không đánh cắp mật khẩu mà lừa nạn nhân nhấn "Accept / Allow" để cấp quyền đọc thư, danh bạ hoặc tệp cho một ứng dụng độc hại giả mạo trên Google Workspace hoặc Microsoft Azure. Quyền truy cập vẫn tồn tại kể cả khi người dùng đổi mật khẩu.',
            indicators: indicators.length > 0 ? indicators : ['Phát hiện liên kết ủy quyền OAuth2 đáng ngờ'],
            remediation: 'Xóa email ngay lập tức (di chuyển vào Thùng rác Gmail). Kiểm tra mục "Ứng dụng của bên thứ ba có quyền truy cập vào tài khoản" trên Google để thu hồi quyền ngay.'
        };
    }

    // =========================================================================
    // 6. ADVERSARY-IN-THE-MIDDLE (AiTM) PHISHING (Đánh cắp Cookie & Vượt MFA)
    // MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
    // =========================================================================
    const hasAiTmSigns = email.identityAudit?.mfaFatigueDetected || tactics.includes('Adversary-in-the-Middle') || urls.some(u => {
        const domainParts = ((u.domain || '')).split('.');
        return domainParts.length >= 4 && (domainParts.includes('login') || domainParts.includes('live') || domainParts.includes('signin'));
    });

    if (hasAiTmSigns) {
        indicators.push('Phát hiện kỹ thuật Reverse Proxy giả lập cổng đăng nhập trực tiếp (AiTM Phishing Kit như Evilginx/Modlishka)');
        indicators.push('Trang web giả mạo có khả năng đánh cắp đồng thời Mật khẩu, Mã OTP và Session Cookie xác thực');

        return {
            id: 'AITM_PHISHING',
            nameVi: 'Đánh cắp Phiên & Vượt MFA (Adversary-in-the-Middle - AiTM Phishing)',
            severity: 'CRITICAL',
            icon: '🥷',
            mitre: {
                id: 'T1557',
                name: 'Adversary-in-the-Middle (AiTM)',
                url: 'https://attack.mitre.org/techniques/T1557/'
            },
            description: 'Kẻ tấn công triển khai máy chủ Proxy trung gian nằm giữa nạn nhân và dịch vụ xác thực thật. Khi nạn nhân nhập tài khoản và mã xác thực 2 bước (MFA/OTP), proxy sẽ chuyển tiếp đến dịch vụ thật rồi âm thầm cướp lấy Session Cookie hoàn chỉnh, cho phép hacker đăng nhập mà không cần mật khẩu.',
            indicators: indicators,
            remediation: 'Xóa thư vào Thùng rác Gmail. Buộc đăng xuất tất cả các phiên làm việc (Revoke Sessions) và kích hoạt khóa bảo mật phần cứng FIDO2.'
        };
    }

    // =========================================================================
    // 7. CALLBACK PHISHING (TOAD - Đe dọa hóa đơn ép gọi tổng đài giả mạo)
    // MITRE ATT&CK: T1204 / T1566 (Telephone-Oriented Attack Delivery - TOAD)
    // =========================================================================
    const invoiceKeywords = ['invoice', 'hóa đơn', 'subscription', 'gia hạn', 'membership', 'geek squad', 'norton', 'mcafee', 'paypal order', 'trừ tiền', 'auto-renew'];
    const phoneCallKeywords = ['call us', 'liên hệ hotline', 'gọi ngay', 'toll-free', 'hotline', 'phone support', 'call immediately', 'hủy đơn hàng', 'cancel payment'];
    const hasInvoiceKeywords = invoiceKeywords.some(k => subject.includes(k) || bodyText.includes(k));
    const hasCallKeywords = phoneCallKeywords.some(k => bodyText.includes(k) || aiSummary.toLowerCase().includes(k));
    const phoneRegex = /(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/;
    const hasPhoneNumber = phoneRegex.test(bodyText);

    if (hasInvoiceKeywords && hasCallKeywords && hasPhoneNumber && urls.length === 0) {
        indicators.push('Email thông báo hóa đơn/trừ tiền giả mạo nhưng cố tình không đính kèm liên kết');
        indicators.push('Thúc giục người nhận gọi vào số hotline hỗ trợ khách hàng giả để làm thủ tục hủy giao dịch');

        return {
            id: 'CALLBACK_PHISHING',
            nameVi: 'Lừa Đảo Gọi Lại Tổng Đài (Callback Phishing / TOAD Attack)',
            severity: 'HIGH',
            icon: '📞',
            mitre: {
                id: 'T1204',
                name: 'User Execution: Telephone-Oriented Attack Delivery (TOAD)',
                url: 'https://attack.mitre.org/techniques/T1204/'
            },
            description: 'Kỹ thuật tấn công phối hợp qua điện thoại (TOAD). Email giả mạo biên lai trừ tiền dịch vụ đắt đỏ và yêu cầu gọi vào số hotline trong thư nếu muốn hủy. Khi nạn nhân gọi, kẻ lừa đảo đóng giả nhân viên hỗ trợ để dẫn dụ cài đặt phần mềm điều khiển từ xa (AnyDesk/TeamViewer) và chiếm quyền máy tính.',
            indicators: indicators,
            remediation: 'Vứt thư vào thư mục Spam của Gmail. Tuyệt đối không gọi vào số điện thoại ghi trong email.'
        };
    }

    // =========================================================================
    // 8. URL CLOAKING & DELAYED ACTIVATION (Che giấu URL & Kích hoạt trễ)
    // MITRE ATT&CK: T1566.002 (Conditional Redirection & Cloaking)
    // =========================================================================
    const isSuspiciousEmail = (ruleEvaluation?.totalScore != null && ruleEvaluation.totalScore >= 40) || email.riskLevel === 'HIGH' || email.riskLevel === 'SUSPICIOUS' || email.contentVerdict === 'PHISHING';
    const hasCloakedUrl = isSuspiciousEmail && urls.some(u => {
        const redirects = u.redirect_chain?.total_redirects || 0;
        const domainChanged = u.redirect_chain?.domain_changed || false;
        const isRiskyUrl = u.is_malicious || u.risk_level === 'HIGH' || u.risk_level === 'MEDIUM' || (u.risk?.risk_score && u.risk.risk_score >= 30);
        return (redirects >= 2 || (redirects >= 1 && domainChanged)) && isRiskyUrl;
    });

    if (hasCloakedUrl) {
        urls.forEach(u => {
            if ((u.redirect_chain?.total_redirects || 0) >= 1) {
                indicators.push(`URL '${u.url}' sử dụng chuỗi chuyển hướng ${u.redirect_chain.total_redirects} bước qua nhiều domain trung gian (${u.redirect_chain.initial_domain} -> ${u.redirect_chain.final_domain})`);
            }
        });

        return {
            id: 'URL_CLOAKING',
            nameVi: 'Che Giấu URL & Kích Hoạt Trễ (URL Cloaking & Delayed Activation)',
            severity: 'HIGH',
            icon: '🎭',
            mitre: {
                id: 'T1566.002',
                name: 'Spearphishing Link (URL Cloaking)',
                url: 'https://attack.mitre.org/techniques/T1566/002/'
            },
            description: 'Kẻ tấn công dùng các dịch vụ rút gọn link, trang chuyển tiếp hợp pháp (Canva, Google Docs, SharePoint) hoặc cơ chế kiểm tra User-Agent/IP để ngụy trang. Lúc đầu link trỏ về trang sạch để vượt qua bộ quét của Mail Gateway, sau đó mới đổi hướng sang trang lừa đảo độc hại.',
            indicators: indicators,
            remediation: 'Kích hoạt lệnh xóa thư độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người nhận truy cập chuỗi liên kết ngụy trang.'
        };
    }

    // =========================================================================
    // 9. CEO FRAUD (Giả mạo Lãnh đạo cấp cao)
    // MITRE ATT&CK: T1566 / T1598.002 (Business Email Compromise: CEO Fraud)
    // =========================================================================
    const ceoTitles = ['ceo', 'giám đốc', 'tổng giám đốc', 'cfo', 'president', 'chủ tịch', 'lãnh đạo', 'director'];
    const urgentPaymentKeywords = ['chuyển tiền ngay', 'thanh toán khẩn', 'strictly confidential', 'tuyệt mật', 'urgent wire transfer', 'không được bàn tán', 'tiến hành gấp'];
    const isCeoTitle = ceoTitles.some(t => subject.includes(t) || sender.includes(t) || bodyText.includes(t));
    const isUrgentMoney = urgentPaymentKeywords.some(m => subject.includes(m) || bodyText.includes(m) || aiSummary.toLowerCase().includes(m));

    if (isCeoTitle && (isUrgentMoney || authFailed || (domainAge && domainAge < 60) || tactics.includes('Authority'))) {
        indicators.push('Nội dung thư mạo danh chức danh Lãnh đạo cấp cao (CEO/CFO/Giám đốc)');
        indicators.push('Yêu cầu thực hiện giao dịch tài chính hoặc chuyển tiền khẩn cấp với điều kiện bảo mật tối mật');
        if (authFailed) indicators.push(`Người gửi giả mạo không vượt qua xác thực SPF/DMARC của lãnh đạo`);

        return {
            id: 'CEO_FRAUD',
            nameVi: 'Giả Mạo Lãnh Đạo Cấp Cao (Business Email Compromise: CEO Fraud)',
            severity: 'CRITICAL',
            icon: '👔',
            mitre: {
                id: 'T1566',
                name: 'Phishing for BEC: CEO Fraud',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Kẻ tấn công đóng giả CEO hoặc Lãnh đạo cấp cao trong công ty, gửi email trực tiếp cho nhân viên kế toán/nhân sự yêu cầu chuyển tiền gấp vào tài khoản lạ với lý do "thương vụ mua lại bí mật" và yêu cầu không được trao đổi qua kênh công khai.',
            indicators: indicators,
            remediation: 'Di chuyển thư vào thư mục Spam của Gmail hoặc xóa vào Thùng rác. Bắt buộc gọi điện thoại trực tiếp để đối chất với lãnh đạo trước khi duyệt tiền.'
        };
    }

    // =========================================================================
    // 10. VENDOR & SUPPLY-CHAIN PHISHING (Giả mạo Đối tác & Chuỗi cung ứng)
    // MITRE ATT&CK: T1566 / T1195 (Vendor Email Compromise - Supply Chain Phishing)
    // =========================================================================
    const vendorKeywords = ['nhà cung cấp', 'vendor', 'supplier', 'đối tác', 'đổi tài khoản ngân hàng', 'thay đổi số tài khoản', 'updated bank details', 'new banking account', 'hóa đơn điều chỉnh'];
    const isVendorIssue = vendorKeywords.some(k => subject.includes(k) || bodyText.includes(k) || aiSummary.toLowerCase().includes(k));

    if (isVendorIssue && (authFailed || (domainAge && domainAge < 90) || ruleEvaluation?.typosquatInfo)) {
        indicators.push('Nội dung thư giả danh đối tác / nhà cung cấp thông báo thay đổi thông tin số tài khoản nhận tiền');
        if (ruleEvaluation?.typosquatInfo) indicators.push(`Tên miền đối tác có dấu hiệu Typosquatting giả mạo: ${ruleEvaluation.typosquatInfo.domain}`);
        if (authFailed) indicators.push('Không vượt qua xác thực SPF/DKIM của nhà cung cấp chính thức');

        return {
            id: 'VENDOR_SUPPLY_CHAIN',
            nameVi: 'Lừa Đảo Đối Tác & Chuỗi Cung Ứng (Vendor Email Compromise - VEC)',
            severity: 'CRITICAL',
            icon: '🚚',
            mitre: {
                id: 'T1566',
                name: 'Supply Chain Compromise: Vendor Email Compromise',
                url: 'https://attack.mitre.org/techniques/T1566/'
            },
            description: 'Kẻ tấn công mạo danh nhà cung cấp thân thiết hoặc đối tác chuỗi cung ứng, gửi thông báo kèm hóa đơn giả với lý do "tài khoản ngân hàng cũ đang kiểm toán, vui lòng thanh toán vào số tài khoản mới này".',
            indicators: indicators,
            remediation: 'Di chuyển thư vào thư mục Spam của Gmail. Tuyệt đối không chuyển tiền vào số tài khoản mới khi chưa gọi điện thoại xác nhận độc lập.'
        };
    }

    // =========================================================================
    // 11. ĐÁNH CẮP THÔNG TIN XÁC THỰC (Credential Harvesting Phishing)
    // MITRE ATT&CK: T1566.002 / T1598.003
    // =========================================================================
    let hasCredentialHarvesting = false;
    const credKeywords = ['login', 'signin', 'xác minh', 'mật khẩu', 'password', 'verify', 'account', 'security', 'cập nhật', 'portal', 'webmail', 'auth'];
    const matchesCredKeyword = credKeywords.some(k => subject.includes(k) || aiSummary.toLowerCase().includes(k));

    let maliciousUrlFound = false;
    urls.forEach(u => {
        if (u.is_malicious || u.risk_level === 'HIGH') {
            maliciousUrlFound = true;
            indicators.push(`Liên kết độc hại được phát hiện: ${u.url} (Điểm rủi ro Sandbox: ${u.risk_score || 'High'})`);
        }
        const uDomain = (u.domain || '').toLowerCase();
        const isTrustedAuth = ['google.com', 'accounts.google.com', 'myaccount.google.com', 'microsoft.com', 'apple.com'].some(d => uDomain === d || uDomain.endsWith('.' + d));
        if (credKeywords.some(k => (u.url || '').toLowerCase().includes(k)) && (!isTrustedAuth || u.is_malicious || u.risk_level === 'HIGH')) {
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
            description: 'Kẻ tấn công gửi liên kết dẫn dụ người dùng tới trang web giả mạo (Fake Login Page) có giao diện giống hệt Microsoft 365, Google Workspace, Cổng Webmail hoặc Cổng Ngân hàng nhằm chiếm đoạt tài khoản, mật khẩu.',
            indicators: indicators.length > 0 ? indicators : ['Phát hiện liên kết ngoài kèm yêu cầu đăng nhập tài khoản'],
            remediation: 'Kích hoạt lệnh xóa email độc hại ngay lập tức (di chuyển vào Thùng rác Gmail) để ngăn chặn người nhận nhấp vào liên kết đăng nhập giả mạo.'
        };
    }

    // =========================================================================
    // 12. MẠO DANH THƯƠNG HIỆU UY TÍN (Brand Impersonation)
    // MITRE ATT&CK: T1566.002 (Brand Spoofing)
    // =========================================================================
    const brandNames = ['google', 'microsoft', 'apple', 'netflix', 'paypal', 'vietcombank', 'mbbank', 'techcombank', 'evn', 'viettel', 'vnpt', 'amazon', 'dhl', 'fedex', 'vnpost'];
    const brandMatch = brandNames.find(b => subject.includes(b) || sender.includes(b));
    if (brandMatch || ruleEvaluation?.typosquatInfo) {
        const brandNameDisp = ruleEvaluation?.typosquatInfo?.brand?.toUpperCase() || (brandMatch ? brandMatch.toUpperCase() : 'THƯƠNG HIỆU LỚN');
        indicators.push(`Nội dung email mạo danh tổ chức / thương hiệu lớn: '${brandNameDisp}'`);
        if (ruleEvaluation?.typosquatInfo) indicators.push(`Phát hiện tên miền Typosquatting cố tình viết sai chính tả để lừa người dùng: ${ruleEvaluation.typosquatInfo.domain}`);

        return {
            id: 'BRAND_IMPERSONATION',
            nameVi: `Mạo danh Thương hiệu Uy tín (${brandNameDisp} Impersonation)`,
            severity: 'HIGH',
            icon: '🏢',
            mitre: {
                id: 'T1566.002',
                name: 'Spearphishing Link (Brand Spoofing)',
                url: 'https://attack.mitre.org/techniques/T1566/002/'
            },
            description: `Kẻ tấn công lạm dụng uy tín của thương hiệu ${brandNameDisp} nhằm tạo cảm giác tin cậy giả tạo, lừa nạn nhân tin rằng đây là thông báo hóa đơn, sự cố thanh toán hoặc cập nhật bảo mật chính thức.`,
            indicators: indicators,
            remediation: 'Kích hoạt lệnh xóa thư độc hại (di chuyển vào Thùng rác Gmail) hoặc vứt vào thư mục Spam để ngăn chặn tương tác với thương hiệu bị mạo danh.'
        };
    }

    // =========================================================================
    // 13. ĐE DỌA KHÓA TÀI KHOẢN KHẨN CẤP (Account Suspension Hoax)
    // MITRE ATT&CK: T1204.001 (User Execution: Malicious Link)
    // =========================================================================
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

    // =========================================================================
    // 14. LỪA ĐẢO TÀI CHÍNH / TRÚNG THƯỞNG ẢO (Advance-Fee Fraud / Scam)
    // MITRE ATT&CK: T1566 (Scam Phishing)
    // =========================================================================
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

    // =========================================================================
    // 15. LỪA ĐẢO KỸ THUẬT XÃ HỘI TỔNG QUÁT (Social Engineering Phishing)
    // MITRE ATT&CK: T1566 (Generic Phishing)
    // =========================================================================
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

    // =========================================================================
    // 16. THƯ AN TOÀN / RỦI RO THẤP (Benign / Clean Email)
    // =========================================================================
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

module.exports = {
    classifyPhishingAttack
};
