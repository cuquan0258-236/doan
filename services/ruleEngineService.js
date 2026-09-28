/**
 * Mini SOAR - Rule Engine Service (Bộ Quy Tắc Đánh Giá & Phản Ứng Chống Phishing)
 * 
 * 1. Hard Rule -> MALICIOUS ngay (100 điểm)
 * 2. Chấm điểm mềm có TRẦN từng module & Bonus tương quan
 * 3. Ma trận Ngưỡng & Hành động (Clean, Low, Suspicious, Malicious, Inconclusive)
 * 4. Bộ lọc An toàn (Circuit Breaker 20 mail/h, LLM Guard, Allowlist, Audit Log)
 */

// Bộ đếm Circuit Breaker: Lưu số lượng mail đã xử lý trong 1 giờ gần nhất
const hourlyActionCounter = {
    windowStart: Date.now(),
    count: 0,
    MAX_PER_HOUR: 20
};

// Danh sách Allowlist người gửi tin cậy (chỉ gắn nhãn, không bao giờ tự động cách ly/xóa)
const SENDER_ALLOWLIST = [
    'admin@internal.corp',
    'security@company.com',
    'notification@google.com',
    'no-reply@accounts.google.com'
];

// Danh sách các thương hiệu phổ biến thường xuyên bị giả mạo / typosquatting
const COMMONLY_SPOOFED_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook',
    'instagram', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'dhl',
    'fedex', 'ups', 'adobe', 'dropbox', 'linkedin', 'twitter', 'telegram',
    'binance', 'coinbase', 'metamask', 'vietcombank', 'techcombank', 'mbbank',
    'bidv', 'agribank', 'tpbank', 'vpbank', 'acb', 'outlook', 'office365'
];

/**
 * Tính khoảng cách Levenshtein giữa hai chuỗi ký tự
 */
function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1, // Thay thế
                    matrix[i][j - 1] + 1,     // Chèn
                    matrix[i - 1][j] + 1      // Xóa
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Phát hiện Typosquatting / Giả mạo thương hiệu bằng khoảng cách Levenshtein <= 2
 */
function detectTyposquatting(domain) {
    if (!domain) return null;
    const clean = domain.toLowerCase().replace(/:\d+$/, '').trim();
    const parts = clean.split('.').slice(0, -1).join('.');
    const tokens = new Set([
        ...parts.split(/[-_.]/).filter(t => t.length >= 3),
        parts
    ]);

    for (const token of tokens) {
        for (const brand of COMMONLY_SPOOFED_BRANDS) {
            if (token === brand) continue;
            if (Math.abs(token.length - brand.length) > 2) continue;

            const dist = levenshteinDistance(token, brand);
            if (dist > 0 && dist <= 2) {
                return {
                    brand,
                    matchedToken: token,
                    distance: dist,
                    domain
                };
            }
        }
    }
    return null;
}

/**
 * Kiểm tra và reset bộ đếm Circuit Breaker
 */
function checkCircuitBreaker() {
    const now = Date.now();
    if (now - hourlyActionCounter.windowStart > 3600000) {
        // Hết 1 giờ -> reset lại cửa sổ thời gian
        hourlyActionCounter.windowStart = now;
        hourlyActionCounter.count = 0;
    }
    return hourlyActionCounter.count < hourlyActionCounter.MAX_PER_HOUR;
}

function incrementCircuitBreaker() {
    hourlyActionCounter.count += 1;
}

/**
 * Tạo danh sách các hành động ứng phó tự động theo đúng Playbook của Rule Engine
 * @param {Object} email 
 * @param {string} verdict 'MALICIOUS' | 'SUSPICIOUS' | 'LOW' | 'CLEAN' | 'INCONCLUSIVE'
 * @param {Object} options 
 * @returns {Array} Danh sách các hành động ngăn chặn thực tế
 */
function generatePlaybookActions(email, verdict, options = {}) {
    const executedAt = email.collectedAt || email.receivedAt || email.createdAt || new Date();
    const subject = email.subject || 'No Subject';

    if (verdict === 'MALICIOUS') {
        return [
            {
                target: 'gmail_trash',
                targetName: 'Hộp thư Gmail liên kết',
                title: 'Lệnh xử lý #1 — Xóa thư độc hại (Chuyển vào Thùng rác Gmail)',
                action: 'DELETE_TO_TRASH',
                policy: 'XÓA THƯ KHỎI INBOX / DI CHUYỂN VÀO THÙNG RÁC (TRASH)',
                status: 'SUCCESS',
                executedAt: executedAt,
                summaryText: 'Đối tượng: 1 Email Record | Hành động: XÓA KHỎI HỘP THƯ ĐẾN & CHUYỂN VÀO THÙNG RÁC GMAIL',
                logOutput: `[Gmail Action] Phát hiện email độc hại (${options.totalScore || 100}/100đ - MALICIOUS).\n[Gmail Action] Đã kích hoạt lệnh xóa email '${subject}' khỏi Hộp thư đến (Inbox) và di chuyển vào Thùng rác (Trash) của Gmail.\n[Gmail Action] Đã cô lập thành công, ngăn chặn người nhận đọc thư hoặc bấm vào các liên kết độc hại.`,
                timelineEvent: 'Gmail Action: Xóa thư độc hại (Chuyển vào Thùng rác)',
                timelineDesc: 'Tự động xóa email độc hại khỏi Hộp thư đến và di chuyển vào Thùng rác (Trash) của tài khoản Gmail liên kết.'
            }
        ];
    }

    if (verdict === 'SUSPICIOUS') {
        return [
            {
                target: 'gmail_spam',
                targetName: 'Hộp thư Gmail liên kết',
                title: 'Lệnh xử lý #1 — Vứt thư vào thư mục Spam (Gmail Spam)',
                action: 'MOVE_TO_SPAM',
                policy: 'CHUYỂN VÀO THƯ MỤC SPAM CỦA GMAIL',
                status: 'SUCCESS',
                executedAt: executedAt,
                summaryText: 'Đối tượng: 1 Email Record | Hành động: VỨT THƯ VÀO THƯ MỤC SPAM GMAIL',
                logOutput: `[Gmail Action] Phát hiện email có dấu hiệu nghi ngờ (${options.totalScore || 50}/100đ - SUSPICIOUS).\n[Gmail Action] Đã tự động di chuyển email '${subject}' từ Hộp thư đến vào thư mục Spam của Gmail.\n[Gmail Action] Cách ly thư khỏi hộp thư chính để tránh người dùng mở nhầm.`,
                timelineEvent: 'Gmail Action: Vứt vào thư mục Spam',
                timelineDesc: 'Tự động chuyển email nghi vấn từ Hộp thư đến vào thư mục Spam của tài khoản Gmail liên kết.'
            }
        ];
    }

    return [];
}

/**
 * Động cơ Quy tắc Trung tâm: Đánh giá email theo toàn bộ ma trận quy tắc
 * @param {Object} email Record email đầy đủ các trường từ DB
 * @returns {Object} Kết quả đánh giá chi tiết
 */
function evaluateEmail(email) {
    const hardRuleHits = [];
    const moduleScores = {
        header: 0,
        domainAge: 0,
        llm: 0,
        url: 0,
        attachment: 0,
        ioc: 0
    };
    const correlationBonuses = [];
    const failSafeNotes = [];
    let moduleErrorCount = 0;

    const sender = (email.sender || '').toLowerCase();
    const isAllowlisted = SENDER_ALLOWLIST.some(allowed => sender.includes(allowed.toLowerCase()));

    // ========================================================
    // PHẦN 1: HARD RULES -> MALICIOUS NGAY (100 ĐIỂM)
    // ========================================================

    // 1.1. URL/Domain có trong PhishTank (verified) hoặc URLhaus (online/active)
    const iocs = email.iocAnalysis?.iocs || email.iocAnalysis?.results || [];
    iocs.forEach(ioc => {
        const pt = ioc.sources?.phishtank || (Array.isArray(ioc.sources) && ioc.sources.includes('PhishTank') ? ioc : null);
        if (pt && (pt.verified || pt.verdict === 'MALICIOUS' || pt.is_verified_phish)) {
            hardRuleHits.push(`IOC '${ioc.iocValue || ioc.value}' được xác thực trong cơ sở dữ liệu PhishTank (Verified Phishing)`);
        }

        const uh = ioc.sources?.urlhaus || (Array.isArray(ioc.sources) && ioc.sources.includes('URLhaus') ? ioc : null);
        if (uh && (uh.verdict === 'MALICIOUS' || uh.urlStatus === 'online' || uh.listed)) {
            hardRuleHits.push(`URL '${ioc.iocValue || ioc.value}' đang hoạt động (Online/Active) trên URLhaus Malware/Phishing`);
        }
    });

    // 1.2. File bị VirusTotal >= 5 engines hoặc Hybrid Analysis >= 70
    const attachments = email.attachmentAnalysis?.attachments || email.attachmentAnalysis?.files || [];
    attachments.forEach(f => {
        const vtDetections = f.sandbox_reports?.virustotal?.malicious_count || f.vt_result?.malicious || f.malicious_count || 0;
        const haScore = f.sandbox_reports?.hybrid_analysis?.threat_score || f.hybrid_analysis?.threat_score || f.threat_score || 0;

        if (vtDetections >= 5) {
            hardRuleHits.push(`Tệp đính kèm '${f.filename}' bị phát hiện bởi ${vtDetections} engines trên VirusTotal (>= 5 engines)`);
        }
        if (haScore >= 70) {
            hardRuleHits.push(`Tệp đính kèm '${f.filename}' có điểm đe dọa Sandbox Hybrid Analysis là ${haScore}/100 (>= 70)`);
        }

        // 1.3. Magic Bytes không khớp đuôi và loại thật là file thực thi (exe, dll, scr, lnk, bat, vbs, com)
        const realType = (f.magic_bytes?.type || f.magic_type || '').toLowerCase();
        const declaredType = (f.extension || f.file_type || '').toLowerCase();
        const executableSignatures = ['executable', 'pe32', 'dll', 'msi', 'scr', 'lnk', 'batch', 'script', 'vbs', 'com', 'exe'];
        const isRealExecutable = executableSignatures.some(sig => realType.includes(sig));

        // Kiểm tra ngụy tạo đuôi hoặc double extension thực thi
        const fname = (f.filename || '').toLowerCase();
        const hasDoubleExtExe = fname.includes('.pdf.exe') || fname.includes('.doc.exe') || fname.includes('.xlsx.exe');
        if ((f.is_spoofed && isRealExecutable) || hasDoubleExtExe) {
            hardRuleHits.push(`Magic Bytes / Đuôi mở rộng phát hiện tệp ngụy tạo độc hại: '${f.filename}' (loại thực thi ${realType || 'PE Executable'})`);
        }
    });

    // 1.4. Mạo danh domain nội bộ (SPF/DMARC fail)
    const headerAuth = email.headerAnalysis?.authentication || {};
    const spfStatus = (headerAuth.spf?.status || headerAuth.spf || '').toLowerCase();
    const dmarcStatus = (headerAuth.dmarc?.status || headerAuth.dmarc || '').toLowerCase();
    const recipientDomain = (email.recipient || '').includes('@') ? email.recipient.split('@')[1].replace(/[<>]/g, '').toLowerCase() : '';
    const senderDomain = (email.sender || '').includes('@') ? email.sender.split('@')[1].replace(/[<>]/g, '').toLowerCase() : '';

    if (recipientDomain && senderDomain && recipientDomain === senderDomain) {
        if (dmarcStatus === 'fail' || spfStatus === 'fail' || spfStatus === 'softfail') {
            hardRuleHits.push(`Mạo danh domain nội bộ công ty (${senderDomain}): Gửi từ ngoài nhưng trượt xác thực SPF/DMARC`);
        }
    }

    // NẾU CÓ HARD RULE -> NGẮT MẠCH NGAY VỚI 100 ĐIỂM
    if (hardRuleHits.length > 0) {
        const action = isAllowlisted ? 'LOG_ALLOWLISTED' : 'DELETE_TO_TRASH';
        const actionNameVi = isAllowlisted 
            ? 'Người gửi Tin Cậy (Chỉ Gắn Nhãn / Giữ trong Inbox)' 
            : 'Xóa thư độc hại (Chuyển vào Thùng rác Gmail)';
        const playbookActions = isAllowlisted ? [] : generatePlaybookActions(email, 'MALICIOUS', { totalScore: 100, isHardRule: true, hardRuleHits });
        return {
            totalScore: 100,
            verdict: 'MALICIOUS',
            action: action,
            actionNameVi: actionNameVi,
            isHardRule: true,
            hardRuleHits: hardRuleHits,
            moduleScores: { header: 25, domainAge: 20, llm: 20, url: 35, attachment: 40, ioc: 30 },
            correlationBonuses: [],
            failSafeNotes: isAllowlisted ? ['Người gửi nằm trong Allowlist: Bỏ qua hành động tự xóa'] : [],
            playbookActions: playbookActions,
            evaluatedAt: new Date().toISOString()
        };
    }

    // ========================================================
    // PHẦN 2: CHẤM ĐIỂM MỀM (CÓ TRẦN CHO MỖI MODULE)
    // ========================================================

    // 2.1. Module Header (Trần: 25 điểm)
    // DMARC fail +15, DMARC none +15, SPF fail +8, DKIM fail +5, DKIM none +5, Reply-To/Return-Path lệch +7
    let rawHeader = 0;
    if (dmarcStatus === 'fail' || dmarcStatus === 'none') rawHeader += 15;
    if (spfStatus === 'fail' || spfStatus === 'softfail') rawHeader += 8;
    const dkimStatus = (headerAuth.dkim?.status || headerAuth.dkim || '').toLowerCase();
    if (dkimStatus === 'fail' || dkimStatus === 'none') rawHeader += 5;

    const headers = email.headerAnalysis?.headers || {};
    if (headers.reply_to && headers.return_path && headers.reply_to.toLowerCase() !== headers.return_path.toLowerCase()) {
        rawHeader += 7;
    }
    moduleScores.header = Math.min(25, rawHeader);

    // 2.2. Module Domain & Brand Validation (Trần: 45 điểm)
    // - Domain không tồn tại (DNS + WHOIS xác nhận): +25
    // - Typosquatting/giả thương hiệu (khoảng cách Levenshtein <= 2): +20
    // - Tuổi domain: <7 ngày +20, <30 ngày +12, <90 ngày +6
    let rawDomain = 0;

    // A. Kiểm tra Domain không tồn tại (DNS + WHOIS xác nhận)
    let isDomainNotFound = false;
    const anomalies = email.headerAnalysis?.anomalies || [];
    if (anomalies.some(a => a.type === 'DOMAIN_NOT_FOUND' || (a.detail && (a.detail.includes('không tồn tại') || a.detail.includes('No match'))))) {
        isDomainNotFound = true;
    }
    const whoisErr = (email.headerAnalysis?.domain_analysis?.error || '').toLowerCase();
    if (whoisErr.includes('no match') || whoisErr.includes('not found') || whoisErr.includes('nxdomain') || whoisErr.includes('could not resolve')) {
        isDomainNotFound = true;
    }
    const urlChain = email.urlAnalysis?.urls || [];
    if (urlChain.some(u => (u.urlscan?.reason || '').includes('Could not resolve domain') || (u.redirect_chain?.chain || []).some(c => (c.note || '').includes('không tồn tại')))) {
        isDomainNotFound = true;
    }

    if (isDomainNotFound) {
        rawDomain += 25;
    }

    // B. Kiểm tra Typosquatting / Giả mạo thương hiệu (khoảng cách Levenshtein <= 2)
    const senderEmail = (email.sender || '').toLowerCase();
    const senderDomainFromEmail = senderEmail.includes('@') ? senderEmail.split('@')[1].replace(/[<>]/g, '').trim() : '';
    const domainFromAnalysis = (email.headerAnalysis?.domain_analysis?.sender_domain || '').toLowerCase().trim();
    const testDomain = senderDomainFromEmail || domainFromAnalysis;

    const typosquatInfo = detectTyposquatting(testDomain) || detectTyposquatting(domainFromAnalysis);
    if (typosquatInfo) {
        rawDomain += 20;
    }

    // C. Tuổi domain (Domain Age)
    const domainAge = email.headerAnalysis?.domain_analysis?.domain_age_days;
    if (typeof domainAge === 'number') {
        if (domainAge < 7) rawDomain += 20;
        else if (domainAge < 30) rawDomain += 12;
        else if (domainAge < 90) rawDomain += 6;
    } else if (email.headerAnalysis?.domain_analysis?.error && !isDomainNotFound && !whoisErr.includes('no match')) {
        moduleErrorCount += 1;
    }
    moduleScores.domainAge = Math.min(45, rawDomain);

    // 2.3. Module Nội dung LLM (Trần: 20 điểm)
    // Mỗi đòn tâm lý +5, ép chuyển tiền/xin OTP +8
    let rawLlm = 0;
    const tactics = email.contentAnalysis?.ai_analysis?.data?.tactics || email.contentAnalysis?.tactics || [];
    rawLlm += tactics.length * 5;

    const contentSummary = (email.contentAnalysis?.clean_body || email.contentAnalysis?.summary || '').toLowerCase();
    const subject = (email.subject || '').toLowerCase();
    if (contentSummary.includes('chuyển tiền') || contentSummary.includes('otp') || contentSummary.includes('mật khẩu') || contentSummary.includes('bảng lương') ||
        subject.includes('chuyển tiền') || subject.includes('otp') || subject.includes('mật khẩu') || subject.includes('bảng lương')) {
        rawLlm += 8;
    }
    if (email.contentAnalysis?.ai_analysis?.success === false) moduleErrorCount += 1;
    moduleScores.llm = Math.min(20, rawLlm);

    // 2.4. Module URL (Trần: 35 điểm)
    // Redirect >3 bước +5, href lệch +8, punycode +10, form đăng nhập trên domain mới +15
    let rawUrl = 0;
    const urls = email.urlAnalysis?.urls || email.urlAnalysis?.results || [];
    urls.forEach(u => {
        if (u.redirect_count > 3 || (u.redirect_chain && u.redirect_chain.length > 3)) rawUrl += 5;
        if (u.href_mismatch) rawUrl += 8;
        if ((u.url || '').includes('xn--')) rawUrl += 10; // Punycode
        const isLogin = ['login', 'signin', 'auth', 'verify'].some(k => (u.url || '').toLowerCase().includes(k));
        if (isLogin && typeof domainAge === 'number' && domainAge < 30) {
            rawUrl += 15;
        }
    });
    if (email.urlAnalysis?.error) moduleErrorCount += 1;
    moduleScores.url = Math.min(35, rawUrl);

    // 2.5. Module Tệp đính kèm (Trần: 40 điểm)
    // Đuôi kép +25, đuôi rủi ro +20, VT 1–4 engine +15
    let rawAtt = 0;
    const riskyExts = ['.iso', '.zip', '.rar', '.7z', '.vba', '.vbs', '.js', '.hta', '.docm', '.xlsm'];
    attachments.forEach(f => {
        const fname = (f.filename || '').toLowerCase();
        const parts = fname.split('.');
        if (parts.length > 2) rawAtt += 25;
        if (riskyExts.some(ext => fname.endsWith(ext))) rawAtt += 20;
        const vtCount = f.sandbox_reports?.virustotal?.malicious_count || f.vt_result?.malicious || f.malicious_count || 0;
        if (vtCount >= 1 && vtCount <= 4) rawAtt += 15;
    });
    if (email.attachmentAnalysis?.error) moduleErrorCount += 1;
    moduleScores.attachment = Math.min(40, rawAtt);

    // 2.6. Module IOC Intel (Trần: 30 điểm)
    // AbuseIPDB >= 75 +15, VT >= 3 engine +20
    let rawIoc = 0;
    iocs.forEach(item => {
        const abuseScore = item.abuseConfidenceScore || item.sources?.abuseipdb?.abuseConfidenceScore || 0;
        if (abuseScore >= 75) rawIoc += 15;
        const vtCount = item.positives || item.sources?.virustotal?.maliciousCount || (item.threatIntel?.virustotal?.malicious) || 0;
        if (vtCount >= 3 || item.reputationScore >= 75 || item.verdict === 'MALICIOUS') rawIoc += 20;
    });
    if (email.iocAnalysis?.error) moduleErrorCount += 1;
    moduleScores.ioc = Math.min(30, rawIoc);

    // ========================================================
    // PHẦN 3: BONUS TƯƠNG QUAN (CORRELATION RULES)
    // ========================================================

    // 3.1. DMARC fail + domain mới (<30 ngày) + xin đăng nhập (+15đ)
    const hasLoginRequest = urls.some(u => ['login', 'signin', 'verify'].some(k => (u.url || '').toLowerCase().includes(k))) ||
                            subject.includes('mật khẩu') || subject.includes('xác minh');
    if (dmarcStatus === 'fail' && typeof domainAge === 'number' && domainAge < 30 && hasLoginRequest) {
        correlationBonuses.push({
            rule: 'DMARC Fail + Domain Mới (<30 ngày) + Yêu cầu Đăng nhập',
            points: 15
        });
    }

    // 3.2. Urgency + link domain mới (<30 ngày) (+10đ)
    const hasUrgency = tactics.includes('Urgency') || subject.includes('khẩn cấp') || subject.includes('urgent') ||
                       Boolean(email.contentAnalysis?.keywords_detected?.['Urgency (Khẩn cấp)']);
    const hasNewDomainLink = typeof domainAge === 'number' && domainAge < 30 && urls.length > 0;
    if (hasUrgency && hasNewDomainLink) {
        correlationBonuses.push({
            rule: 'Đòn tâm lý Khẩn cấp (Urgency) + Liên kết trỏ về Domain Mới (<30 ngày)',
            points: 10
        });
    }

    // 3.3. Typosquat brand + DMARC/DKIM none/fail + domain không tồn tại/mới (+15đ)
    const hasTyposquat = Boolean(typosquatInfo);
    const hasDmarcOrDkimNoneOrFail = (dmarcStatus === 'none' || dmarcStatus === 'fail' || dkimStatus === 'none' || dkimStatus === 'fail');
    const hasDomainNonExistentOrNew = (isDomainNotFound || (typeof domainAge === 'number' && domainAge < 30));

    if (hasTyposquat && hasDmarcOrDkimNoneOrFail && hasDomainNonExistentOrNew) {
        correlationBonuses.push({
            rule: `Typosquatting Brand (${typosquatInfo.brand.toUpperCase()}) + DMARC/DKIM None/Fail + Domain Không Tồn Tại hoặc Mới (<30 ngày)`,
            points: 15
        });
    }

    // TỔNG ĐIỂM
    const baseSoftScore = moduleScores.header + moduleScores.domainAge + moduleScores.llm + 
                          moduleScores.url + moduleScores.attachment + moduleScores.ioc;
    const bonusScore = correlationBonuses.reduce((acc, b) => acc + b.points, 0);
    let totalScore = Math.min(100, baseSoftScore + bonusScore);

    // ========================================================
    // PHẦN 4: NGUYÊN TẮC AN TOÀN & FAIL-SAFE CHECKS
    // ========================================================

    // 4.1. Lỗi >= 2 module -> Inconclusive
    if (moduleErrorCount >= 2) {
        return {
            totalScore: totalScore,
            verdict: 'INCONCLUSIVE',
            action: 'FLAG_REVIEW',
            actionNameVi: 'Gắn nhãn SOAR/Review (Chờ chuyên viên SOC kiểm duyệt thủ công)',
            isHardRule: false,
            hardRuleHits: [],
            moduleScores,
            correlationBonuses,
            failSafeNotes: [`Có ${moduleErrorCount} module phân tích gặp lỗi hoặc không có dữ liệu. Kích hoạt Inconclusive.`],
            evaluatedAt: new Date().toISOString()
        };
    }

    // 4.2. Nguyên tắc LLM Guard: Không bao giờ xóa/cách ly nếu điểm CHỦ YẾU đến từ LLM
    const technicalScore = moduleScores.header + moduleScores.domainAge + moduleScores.url + moduleScores.attachment + moduleScores.ioc;
    let safeVerdict = 'CLEAN';
    let safeAction = 'LOG_CLEAN';
    let actionNameVi = 'Lưu Log Kiểm Toán / Thư An Toàn';

    if (totalScore >= 75) {
        safeVerdict = 'MALICIOUS';
        safeAction = 'DELETE_TO_TRASH';
        actionNameVi = 'Xóa thư độc hại (Chuyển vào Thùng rác Gmail)';
        
        // Nếu điểm kỹ thuật = 0 mà điểm LLM cao -> hạ cấp hành động sang Suspicious
        if (technicalScore === 0 && moduleScores.llm > 0) {
            safeVerdict = 'SUSPICIOUS';
            safeAction = 'MOVE_TO_SPAM';
            actionNameVi = 'Vứt thư vào thư mục Spam của Gmail (Hạ cấp vì điểm chỉ đến từ LLM)';
            failSafeNotes.push('LLM Safety Guard: Không kích hoạt Xóa thư vì không có chứng cứ kỹ thuật độc lập.');
        }
    } else if (totalScore >= 50) {
        safeVerdict = 'SUSPICIOUS';
        safeAction = 'MOVE_TO_SPAM';
        actionNameVi = 'Vứt thư vào thư mục Spam của Gmail';
    } else if (totalScore >= 25) {
        safeVerdict = 'LOW';
        safeAction = 'KEEP_INBOX';
        actionNameVi = 'Giữ trong Hộp thư đến (Inbox) — Gắn nhãn rủi ro thấp';
    } else {
        safeVerdict = 'CLEAN';
        safeAction = 'KEEP_INBOX';
        actionNameVi = 'Giữ trong Hộp thư đến (Inbox) — Email an toàn';
    }

    // 4.3. Allowlist Check
    if (isAllowlisted && (safeAction === 'DELETE_TO_TRASH' || safeAction === 'MOVE_TO_SPAM')) {
        safeAction = 'FLAG_ALLOWLISTED';
        actionNameVi = 'Người gửi Tin Cậy (Chỉ Gắn Nhãn / Giữ trong Inbox)';
        failSafeNotes.push('Allowlist Protection: Miễn trừ xóa thư/chuyển Spam đối với người gửi trong danh sách trắng.');
    }

    // 4.4. Circuit Breaker Check
    if (safeAction === 'DELETE_TO_TRASH' || safeAction === 'MOVE_TO_SPAM') {
        if (!checkCircuitBreaker()) {
            safeAction = 'CIRCUIT_BREAKER_HOLD';
            actionNameVi = 'TẠM DỪNG XỬ LÝ (Đạt giới hạn Circuit Breaker: >20 mail/giờ)';
            failSafeNotes.push('Circuit Breaker Triggered: Vượt quá 20 mail bị xử lý/giờ. Hệ thống tự động khóa để bảo vệ hòm thư.');
        } else {
            incrementCircuitBreaker();
        }
    }

    const playbookActions = generatePlaybookActions(email, safeVerdict, { totalScore, hardRuleHits });

    return {
        totalScore,
        verdict: safeVerdict,
        action: safeAction,
        actionNameVi,
        isHardRule: false,
        hardRuleHits: [],
        moduleScores,
        correlationBonuses,
        failSafeNotes,
        typosquatInfo,
        isDomainNotFound,
        playbookActions: playbookActions,
        evaluatedAt: new Date().toISOString()
    };
}

module.exports = {
    evaluateEmail,
    generatePlaybookActions,
    checkCircuitBreaker,
    SENDER_ALLOWLIST
};
