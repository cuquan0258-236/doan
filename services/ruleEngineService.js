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
    'bidv', 'agribank', 'tpbank', 'vpbank', 'acb', 'outlook', 'office365',
    'bradesco', 'livelo', 'santander', 'itau', 'ftx', 'mashreq'
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
 * Phát hiện Giả mạo Tên hiển thị Thương hiệu (Display Name Brand Impersonation)
 * Chuẩn hóa loại bỏ khoảng trắng, dấu gạch ngang (ví dụ "C o i n b a s e" -> "coinbase")
 */
function detectBrandSpoofing(sender, senderDomain) {
    if (!sender) return null;
    let displayName = sender;
    if (sender.includes('<')) {
        displayName = sender.split('<')[0].replace(/['"]/g, '').trim();
    }
    if (!displayName) return null;

    // Chuẩn hóa: loại bỏ khoảng trắng và ký tự đặc biệt (chống bypass kỹ thuật chen khoảng trắng)
    const normalizedName = displayName.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (!normalizedName || normalizedName.length < 3) return null;

    const domain = (senderDomain || '').toLowerCase().replace(/:\d+$/, '').trim();

    for (const brand of COMMONLY_SPOOFED_BRANDS) {
        if (normalizedName.includes(brand) || levenshteinDistance(normalizedName, brand) <= 1) {
            // Kiểm tra xem tên miền gửi thực tế có chứa thương hiệu được bảo vệ không
            const isLegitBrandDomain = domain.includes(brand);
            if (!isLegitBrandDomain) {
                return {
                    brand,
                    displayName,
                    normalizedName,
                    senderDomain: domain
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

    const hasAnyAnalysis = Boolean(
        email.headerAnalysis || 
        email.contentAnalysis || 
        email.urlAnalysis || 
        email.attachmentAnalysis || 
        email.iocAnalysis
    );

    if (!hasAnyAnalysis) {
        return {
            totalScore: null,
            verdict: 'UNANALYZED',
            action: 'NONE',
            actionNameVi: 'Chưa phân tích (Chờ kích hoạt)',
            isHardRule: false,
            hardRuleHits: [],
            moduleScores,
            correlationBonuses: [],
            playbookActions: [],
            failSafeNotes: ['Email chưa thực hiện bất kỳ phân tích nào (Header, AI, URL, Attachment, IOC).'],
            evaluatedAt: new Date().toISOString()
        };
    }

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

    // Hard Rule đã ghi nhận trong hardRuleHits. Tiếp tục tính toán điểm thực tế
    // của từng module để phản ánh chính xác cấu trúc email (không gán bừa điểm tệp đính kèm).

    // ========================================================
    // PHẦN 2: CHẤM ĐIỂM MỀM (CÓ TRẦN CHO MỖI MODULE)
    // ========================================================

    // 2.1. Module Header (Trần: 25 điểm)
    // DMARC fail +15, DMARC none +15, SPF fail +15, DKIM fail +10, DKIM none +5, Reply-To/Return-Path lệch +7, Domain Mismatch +15
    const senderEmail = (email.sender || '').toLowerCase();
    const senderDomainFromEmail = senderEmail.includes('@') ? senderEmail.split('@').pop().replace(/[<>]/g, '').trim() : '';
    const domainFromAnalysis = (email.headerAnalysis?.domain_analysis?.sender_domain || '').toLowerCase().trim();
    const testDomain = senderDomainFromEmail || domainFromAnalysis;
    const anomalies = email.headerAnalysis?.anomalies || [];

    let rawHeader = 0;
    if (dmarcStatus === 'fail' || dmarcStatus === 'none') rawHeader += 15;
    if (spfStatus === 'fail' || spfStatus === 'softfail') rawHeader += 15;
    const dkimStatus = (headerAuth.dkim?.status || headerAuth.dkim || '').toLowerCase();
    if (dkimStatus === 'fail') rawHeader += 10;
    else if (dkimStatus === 'none') rawHeader += 5;

    const headers = email.headerAnalysis?.headers || {};
    if (headers.reply_to && headers.return_path && headers.reply_to.toLowerCase() !== headers.return_path.toLowerCase()) {
        rawHeader += 7;
    }

    // Kiểm tra DOMAIN_MISMATCH từ anomaly header hoặc căn chỉnh định danh DMARC Alignment
    if (anomalies.some(a => a.type === 'DOMAIN_MISMATCH')) {
        rawHeader += 15;
    } else if (testDomain) {
        const spfDom = (headerAuth.spf?.domain || '').toLowerCase();
        const dkimDom = (headerAuth.dkim?.domain || '').toLowerCase();
        const dmarcDom = (headerAuth.dmarc?.domain || '').toLowerCase();
        const isAligned = (spfDom && testDomain.endsWith(spfDom)) || (dkimDom && testDomain.endsWith(dkimDom)) || (dmarcDom && testDomain.endsWith(dmarcDom));
        if (!isAligned && (spfDom || dkimDom || dmarcDom)) {
            rawHeader += 15; // Phá vỡ căn chỉnh định danh (SPF/DKIM/DMARC Alignment Failure)
        }
    }

    moduleScores.header = Math.min(25, rawHeader);

    // 2.2. Module Domain & Brand Validation (Trần: 45 điểm)
    // - Domain không tồn tại (DNS + WHOIS xác nhận): +25
    // - Typosquatting/giả thương hiệu (khoảng cách Levenshtein <= 2): +20
    // - Tuổi domain: <7 ngày +20, <30 ngày +12, <90 ngày +6
    let rawDomain = 0;

    // A. Kiểm tra Domain không tồn tại hoặc không hợp lệ (DNS + WHOIS xác nhận)
    let isDomainNotFound = false;
    if (anomalies.some(a => a.type === 'DOMAIN_NOT_FOUND' || a.type === 'INVALID_DOMAIN' || (a.detail && (a.detail.includes('không tồn tại') || a.detail.includes('No match') || a.detail.includes('không hợp lệ'))))) {
        isDomainNotFound = true;
    }
    const whoisErr = (email.headerAnalysis?.domain_analysis?.error || '').toLowerCase();
    if (whoisErr.includes('no match') || whoisErr.includes('not found') || whoisErr.includes('nxdomain') || whoisErr.includes('could not resolve') || whoisErr.includes('no output') || whoisErr.includes('không hợp lệ')) {
        isDomainNotFound = true;
    }
    const urlChain = email.urlAnalysis?.urls || [];
    if (urlChain.some(u => (u.urlscan?.reason || '').includes('Could not resolve domain') || (u.redirect_chain?.chain || []).some(c => (c.note || '').includes('không tồn tại')))) {
        isDomainNotFound = true;
    }

    // Kiểm tra domain không có chấm (non-FQDN như 'pot')
    if (testDomain && !testDomain.includes('.')) {
        isDomainNotFound = true;
    }

    if (isDomainNotFound) {
        rawDomain += 25;
    }

    const typosquatInfo = detectTyposquatting(testDomain) || detectTyposquatting(domainFromAnalysis);
    if (typosquatInfo) {
        rawDomain += 20;
    }

    // B2. Phát hiện Giả mạo Tên hiển thị Thương hiệu (ví dụ: "C o i n b a s e <noreply@firesonic.ca>")
    const brandSpoofInfo = detectBrandSpoofing(email.sender, testDomain);
    if (brandSpoofInfo) {
        rawDomain += 25;
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

    // 2.3. Module Nội dung LLM (Trần: 35 điểm)
    // AI Verdict: PHISHING +15, SUSPICIOUS +8
    // Social Engineering Score: >=70 +12, >=50 +8
    // Mỗi đòn tâm lý +5, ép chuyển tiền/xin OTP/tài chính +8
    let rawLlm = 0;
    const tactics = email.contentAnalysis?.ai_analysis?.data?.tactics || email.contentAnalysis?.tactics || [];
    rawLlm += tactics.length * 5;

    const contentSummary = (email.contentAnalysis?.clean_body || email.contentAnalysis?.summary || '').toLowerCase();
    const subject = (email.subject || '').toLowerCase();

    // Tính điểm trực tiếp từ AI Verdict
    const aiVerdictRaw = (email.contentAnalysis?.ai_analysis?.data?.verdict || email.contentAnalysis?.contentVerdict || email.contentVerdict || '').toUpperCase();
    if (aiVerdictRaw === 'PHISHING') rawLlm += 15;
    else if (aiVerdictRaw === 'SUSPICIOUS') rawLlm += 8;

    // Tính điểm từ Social Engineering Score
    const seScoreRaw = (email.socialEngineeringScore || email.contentAnalysis?.ai_analysis?.data?.social_engineering_score || 0);
    if (seScoreRaw >= 70) rawLlm += 12;
    else if (seScoreRaw >= 50) rawLlm += 8;

    // Từ khóa tài chính / lừa đảo
    const financialScamKeywords = [
        'chuyển tiền', 'otp', 'mật khẩu', 'bảng lương',
        'withdraw', 'authorized', 'claim your', 'reward', 'prize',
        'investment', 'trading', 'your account', 'verify your', 'confirm your',
        'suspended', 'locked', 'expire', 'expiring'
    ];
    if (financialScamKeywords.some(k => contentSummary.includes(k) || subject.includes(k))) {
        rawLlm += 8;
    }

    if (email.contentAnalysis?.ai_analysis?.success === false) moduleErrorCount += 1;
    moduleScores.llm = Math.min(35, rawLlm);

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
    // AbuseIPDB >= 75 +15, VT >= 2 engine hoặc verdict MALICIOUS +25, VT >= 1 engine +15
    let rawIoc = 0;
    iocs.forEach(item => {
        const abuseScore = item.abuseConfidenceScore || item.sources?.abuseipdb?.abuseConfidenceScore || 0;
        if (abuseScore >= 75) rawIoc += 15;
        const vtCount = item.positives || item.sources?.virustotal?.maliciousCount || (item.threatIntel?.virustotal?.malicious) || 0;
        if (vtCount >= 2 || item.reputationScore >= 75 || item.verdict === 'MALICIOUS') {
            rawIoc += 25;
        } else if (vtCount >= 1 || item.verdict === 'SUSPICIOUS') {
            rawIoc += 15;
        }
    });
    if (email.iocAnalysis?.error) moduleErrorCount += 1;
    moduleScores.ioc = Math.min(30, rawIoc);

    // ========================================================
    // PHẦN 3: QUY TẮC TƯƠNG QUAN NGẦM (CORRELATION RULES)
    // Các quy tắc liên kết chéo hoạt động ngầm để đẩy điểm các
    // module tương ứng lên mức trần tối đa, không cộng điểm rời rạc.
    // ========================================================

    // 3.1. DMARC fail + domain mới (<30 ngày) + xin đăng nhập
    const hasLoginRequest = urls.some(u => ['login', 'signin', 'verify'].some(k => (u.url || '').toLowerCase().includes(k))) ||
                            subject.includes('mật khẩu') || subject.includes('xác minh');
    if (dmarcStatus === 'fail' && typeof domainAge === 'number' && domainAge < 30 && hasLoginRequest) {
        rawHeader += 10;
        rawUrl += 15;
        correlationBonuses.push({
            rule: 'DMARC Fail + Domain Mới (<30 ngày) + Yêu cầu Đăng nhập'
        });
    }

    // 3.2. Urgency + link domain mới (<30 ngày)
    const hasUrgency = tactics.includes('Urgency') || subject.includes('khẩn cấp') || subject.includes('urgent') ||
                       Boolean(email.contentAnalysis?.keywords_detected?.['Urgency (Khẩn cấp)']);
    const hasNewDomainLink = typeof domainAge === 'number' && domainAge < 30 && urls.length > 0;
    if (hasUrgency && hasNewDomainLink) {
        rawLlm += 10;
        rawUrl += 10;
        correlationBonuses.push({
            rule: 'Đòn tâm lý Khẩn cấp (Urgency) + Liên kết trỏ về Domain Mới (<30 ngày)'
        });
    }

    // 3.3. Typosquat brand + DMARC/DKIM none/fail + domain không tồn tại/mới
    const hasTyposquat = Boolean(typosquatInfo);
    const hasBrandSpoof = Boolean(brandSpoofInfo);
    const hasDmarcOrDkimNoneOrFail = (dmarcStatus === 'none' || dmarcStatus === 'fail' || dkimStatus === 'none' || dkimStatus === 'fail');
    const hasDomainNonExistentOrNew = (isDomainNotFound || (typeof domainAge === 'number' && domainAge < 30));

    if (hasTyposquat && hasDmarcOrDkimNoneOrFail && hasDomainNonExistentOrNew) {
        rawDomain += 20;
        rawHeader += 10;
        correlationBonuses.push({
            rule: `Typosquatting Brand (${typosquatInfo.brand.toUpperCase()}) + Trượt DMARC/DKIM + Domain Mới/Không tồn tại`
        });
    }

    // 3.4. Giả mạo Tên hiển thị Thương hiệu + Trượt DMARC/SPF
    if (hasBrandSpoof && (hasDmarcOrDkimNoneOrFail || spfStatus === 'fail' || spfStatus === 'softfail')) {
        rawDomain += 20;
        rawHeader += 15;
        correlationBonuses.push({
            rule: `Giả mạo Tên hiển thị Thương hiệu (${brandSpoofInfo.brand.toUpperCase()}) + Trượt DMARC/SPF`
        });
    }

    // 3.5. IOC Độc hại đã xác thực + Mạo danh Brand / DMARC Bất thường
    const hasMaliciousIoc = iocs.some(i => i.verdict === 'MALICIOUS' || (i.sources?.virustotal?.maliciousCount || 0) >= 2 || (i.positives || 0) >= 2 || (i.reputationScore || 0) >= 75);
    if (hasMaliciousIoc && (hasBrandSpoof || hasTyposquat || hasDmarcOrDkimNoneOrFail || isDomainNotFound)) {
        rawIoc += 15;
        rawDomain += 15;
        correlationBonuses.push({
            rule: 'IOC Độc hại đã xác thực (VirusTotal/Threat Intel) + Mạo danh Brand hoặc DMARC Bất thường'
        });
    }

    // 3.6. Cảnh báo giao dịch Crypto / Sàn tiền mã hóa lừa đảo + Người gửi bất thường
    const cryptoKeywords = ['eth', 'ethereum', 'bitcoin', 'btc', 'usdt', 'crypto', 'wallet', 'coinbase', 'binance', 'metamask', 'ftx', 'withdraw', 'trading platform'];
    const isCryptoAlert = cryptoKeywords.some(k => subject.includes(k) || contentSummary.includes(k));
    const hasDomainMismatchAnomaly = anomalies.some(a => a.type === 'DOMAIN_MISMATCH');
    if (isCryptoAlert && (hasBrandSpoof || hasDmarcOrDkimNoneOrFail || hasMaliciousIoc || hasDomainMismatchAnomaly || isDomainNotFound)) {
        rawLlm += 15;
        rawDomain += 15;
        correlationBonuses.push({
            rule: 'Thông báo Giao dịch / Rút tiền từ Sàn tiền mã hóa (Crypto/FTX Scam) + Người gửi bất thường'
        });
    }

    // 3.7. Xác thực Máy chủ gửi Bất thường + AI phát hiện Phishing / Lừa đảo
    const hasAuthAnomaly = (spfStatus === 'fail' || spfStatus === 'softfail' || dmarcStatus === 'fail' || dmarcStatus === 'none');
    const aiVerdict = (email.contentAnalysis?.ai_analysis?.data?.verdict || email.contentAnalysis?.contentVerdict || '').toUpperCase();
    const seScore = (email.socialEngineeringScore || email.contentAnalysis?.ai_analysis?.data?.social_engineering_score || 0);
    const isAiPhishing = (aiVerdict === 'PHISHING' || aiVerdict === 'SUSPICIOUS' || seScore >= 60 || tactics.length > 0);

    if (hasAuthAnomaly && isAiPhishing) {
        rawHeader += 15;
        rawLlm += 15;
        correlationBonuses.push({
            rule: `Xác thực máy chủ gửi bất thường + AI phát hiện Dấu hiệu Phishing/Thao túng`
        });
    }

    // 3.8. Tên miền không tồn tại trong DNS/WHOIS (NXDOMAIN) + Trượt xác thực SPF/DKIM/DMARC
    if (isDomainNotFound && hasDmarcOrDkimNoneOrFail) {
        rawDomain += 20;
        rawHeader += 10;
        correlationBonuses.push({
            rule: 'Tên miền không tồn tại trong DNS/WHOIS (NXDOMAIN) + Trượt xác thực SPF/DKIM/DMARC'
        });
    }

    // 3.9. Tên miền người gửi không tồn tại/không hợp lệ + AI phát hiện Phishing
    if (isDomainNotFound && (isAiPhishing || aiVerdict === 'PHISHING' || seScore >= 60)) {
        rawDomain += 25;
        rawLlm += 20;
        correlationBonuses.push({
            rule: `Tên miền người gửi không tồn tại/không hợp lệ (${testDomain || 'Không xác định'}) + AI phát hiện Phishing`
        });
    }

    // 3.10. Mạo danh Cảnh báo Khóa tài khoản Ngân hàng (Bank Account Blocked Scam)
    const bankScamKeywords = ['bank account', 'account has been blocked', 'unusual activities', 'tài khoản bị khóa', 'hoạt động bất thường', 'bloqueada', 'desbloqueio', 'cuenta bloqueada'];
    const isBankScam = bankScamKeywords.some(k => subject.includes(k) || contentSummary.includes(k));
    if (isBankScam && (isDomainNotFound || hasBrandSpoof || hasAuthAnomaly || anomalies.length > 0)) {
        rawLlm += 15;
        rawDomain += 15;
        correlationBonuses.push({
            rule: 'Mạo danh Cảnh báo Khóa tài khoản Ngân hàng (Bank Account Blocked Scam) + Bất thường tên miền/người gửi'
        });
    }

    // 3.11. AI phát hiện Phishing/Lừa đảo + Lệch tên miền (Domain Mismatch)
    if (isAiPhishing && hasDomainMismatchAnomaly) {
        rawHeader += 15;
        rawLlm += 15;
        correlationBonuses.push({
            rule: `AI phát hiện Phishing/Lừa đảo + Lệch tên miền người gửi (Domain Mismatch)`
        });
    }

    // 3.12. Lạm dụng dịch vụ hợp pháp để phishing (Google Forms/Docs/SharePoint)
    const legitimateServiceDomains = ['google.com', 'googleapis.com', 'dropbox.com', 'sharepoint.com', 'onedrive.com', 'outlook.com', 'office365.com'];
    const senderIsLegitService = legitimateServiceDomains.some(d => testDomain.endsWith(d));
    const hasGoogleFormsLink = urls.some(u => {
        const urlStr = (u.url || '').toLowerCase();
        return urlStr.includes('docs.google.com/forms') || urlStr.includes('forms.gle') || urlStr.includes('docs.google.com/document') || urlStr.includes('sharepoint.com');
    });
    if (senderIsLegitService && (aiVerdict === 'PHISHING' || seScore >= 70) && hasGoogleFormsLink) {
        rawLlm += 20;
        rawUrl += 15;
        correlationBonuses.push({
            rule: `Lạm dụng dịch vụ hợp pháp (${testDomain}) để phishing qua Google Forms/Docs`
        });
    }

    // 3.13. AI Phishing mạnh + Bất thường kỹ thuật từ Header
    if ((aiVerdict === 'PHISHING' || seScore >= 60) && anomalies.length > 0) {
        rawLlm += 10;
        rawHeader += 10;
        correlationBonuses.push({
            rule: `AI Phishing mạnh + Bất thường kỹ thuật từ Header`
        });
    }

    // TỔNG HỢP ĐIỂM MODULE THEO MỨC TRẦN TỐI ĐA (50 - 60 ĐIỂM)
    moduleScores.header = Math.min(30, rawHeader);
    moduleScores.domainAge = Math.min(60, rawDomain);
    moduleScores.llm = Math.min(50, rawLlm);
    moduleScores.url = Math.min(50, rawUrl);
    moduleScores.attachment = (attachments && attachments.length > 0) ? Math.min(50, rawAtt) : 0;
    moduleScores.ioc = Math.min(50, rawIoc);

    // XỬ LÝ HARD RULE: Đẩy điểm module trực tiếp gây ra vi phạm lên tối đa và ngắt mạch 100đ
    if (hardRuleHits.length > 0) {
        if (hardRuleHits.some(h => h.includes('PhishTank') || h.includes('URLhaus') || h.includes('IOC'))) {
            moduleScores.ioc = 50;
            moduleScores.url = Math.max(moduleScores.url, 35);
        }
        if (hardRuleHits.some(h => h.includes('Tệp đính kèm') || h.includes('Magic Bytes'))) {
            moduleScores.attachment = 50;
        }
        if (hardRuleHits.some(h => h.includes('Mạo danh domain nội bộ'))) {
            moduleScores.header = 30;
            moduleScores.domainAge = 60;
        }

        // Đảm bảo tính trung thực: Nếu email không có file đính kèm thì điểm tệp đính kèm luôn là 0đ!
        if (!attachments || attachments.length === 0) {
            moduleScores.attachment = 0;
        }

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
            moduleScores: moduleScores,
            correlationBonuses: correlationBonuses,
            failSafeNotes: isAllowlisted ? ['Người gửi nằm trong Allowlist: Bỏ qua hành động tự xóa'] : [],
            playbookActions: playbookActions,
            evaluatedAt: new Date().toISOString()
        };
    }

    // TỔNG ĐIỂM = Tổng điểm thực tế từ 6 module (Chuẩn hóa tối đa 100đ, không cộng điểm rời rạc)
    let totalScore = Math.min(100, 
        moduleScores.header + 
        moduleScores.domainAge + 
        moduleScores.llm + 
        moduleScores.url + 
        moduleScores.attachment + 
        moduleScores.ioc
    );

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

    // 4.2. Nguyên tắc LLM Guard & Escalation khi có IOC độc hại
    // Nếu có IOC độc hại đã xác thực trên VirusTotal/Threat Intel -> Bắt buộc điểm tối thiểu >= 65 (SUSPICIOUS)
    if (hasMaliciousIoc && totalScore < 50) {
        totalScore = 65;
        correlationBonuses.push({
            rule: 'Tự động nâng cấp mức cảnh báo (Escalation): Phát hiện IOC Độc hại đã xác thực từ Threat Intel'
        });
    }

    const technicalScore = moduleScores.header + moduleScores.domainAge + moduleScores.url + moduleScores.attachment + moduleScores.ioc;
    let safeVerdict = 'CLEAN';
    let safeAction = 'LOG_CLEAN';
    let actionNameVi = 'Lưu Log Kiểm Toán / Thư An Toàn';

    if (totalScore >= 70) {
        safeVerdict = 'MALICIOUS';
        safeAction = 'DELETE_TO_TRASH';
        actionNameVi = 'Xóa thư độc hại (Chuyển vào Thùng rác Gmail)';
        
        // Nếu điểm kỹ thuật = 0 mà điểm LLM cao -> hạ cấp hành động sang Suspicious
        // NGOẠI TRỪ: Có quy tắc tương quan (đã có bằng chứng liên kết chéo) HOẶC SE score >= 70 + anomaly
        const hasStrongCorrelation = correlationBonuses.length > 0;
        const hasStrongAiWithEvidence = seScore >= 70 && (anomalies.length > 0 || hasGoogleFormsLink);
        if (technicalScore === 0 && moduleScores.llm > 0 && !hasStrongCorrelation && !hasStrongAiWithEvidence) {
            safeVerdict = 'SUSPICIOUS';
            safeAction = 'MOVE_TO_SPAM';
            actionNameVi = 'Vứt thư vào thư mục Spam của Gmail (Hạ cấp vì điểm chỉ đến từ LLM)';
            failSafeNotes.push('LLM Safety Guard: Không kích hoạt Xóa thư vì không có chứng cứ kỹ thuật độc lập.');
        }
    } else if (totalScore >= 40) {
        safeVerdict = 'SUSPICIOUS';
        safeAction = 'MOVE_TO_SPAM';
        actionNameVi = 'Vứt thư vào thư mục Spam của Gmail';
    } else if (totalScore >= 20) {
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
        brandSpoofInfo,
        hasMaliciousIoc,
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
