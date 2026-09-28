/**
 * Mini SOAR - Threat Intelligence Service (Bước 6)
 * 
 * Chức năng:
 * - Kiểm tra Cache trong MongoDB (< 24 giờ) trước khi gọi API để tiết kiệm quota.
 * - Tự động hết hạn cache sau 24h thông qua TTL Index.
 * - Phân phối truy vấn đa nguồn:
 *   + IP: AbuseIPDB API
 *   + File Hash: VirusTotal API v3
 *   + URL / Domain: URLhaus (abuse.ch) & PhishTank / VirusTotal URL
 * - Tổng hợp Điểm uy tín (Reputation Score 0-100) và dán nhãn chuẩn hóa (MALICIOUS, SUSPICIOUS, SAFE).
 */

const IOCCache = require('../models/IOCCache');

// Kiểm tra xem IP có phải là IP nội bộ/loopback không
function isPrivateOrReservedIP(ip) {
    if (!ip) return true;
    const cleanIP = ip.trim();
    if (cleanIP === '127.0.0.1' || cleanIP === '::1' || cleanIP === 'localhost') return true;
    
    // IPv4 private ranges
    if (cleanIP.startsWith('10.') || cleanIP.startsWith('192.168.') || cleanIP.startsWith('169.254.')) return true;
    if (cleanIP.startsWith('172.')) {
        const parts = cleanIP.split('.');
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) return true;
    }
    return false;
}

/**
 * 1. Kiểm tra Cache MongoDB trong vòng 24 giờ qua
 */
async function checkCache(iocValue) {
    try {
        const normalized = String(iocValue).trim().toLowerCase();
        const now = new Date();

        // Kiểm tra bản ghi cache còn hiệu lực theo trường expiresAt động
        const cached = await IOCCache.findOne({
            iocValue: normalized,
            expiresAt: { $gt: now }
        }).lean();

        if (cached) {
            return {
                ...cached,
                fromCache: true,
                cacheAgeMinutes: Math.round((Date.now() - new Date(cached.lastChecked).getTime()) / (60 * 1000))
            };
        }
        return null;
    } catch (err) {
        console.error(`[ThreatIntel] Lỗi kiểm tra cache cho "${iocValue}": ${err.message}`);
        return null;
    }
}

/**
 * 2. Lưu hoặc cập nhật kết quả vào Cache MongoDB (TTL Động theo Verdict)
 */
async function saveToCache(iocValue, iocType, reputationScore, verdict, sources) {
    try {
        const normalized = String(iocValue).trim().toLowerCase();
        const now = new Date();
        const expiresAt = IOCCache.calculateTTL ? IOCCache.calculateTTL(verdict, iocType) : new Date(now.getTime() + 24 * 60 * 60 * 1000);

        const updated = await IOCCache.findOneAndUpdate(
            { iocValue: normalized },
            {
                iocValue: normalized,
                iocType,
                reputationScore,
                verdict,
                sources,
                lastChecked: now,
                expiresAt
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        ).lean();

        return updated;
    } catch (err) {
        console.error(`[ThreatIntel] Lỗi lưu cache cho "${iocValue}": ${err.message}`);
        return null;
    }
}

/**
 * 3. Tra cứu IP qua AbuseIPDB API
 */
async function queryAbuseIPDB(ip) {
    if (isPrivateOrReservedIP(ip)) {
        return {
            status: 'success',
            provider: 'AbuseIPDB',
            isPrivate: true,
            abuseConfidenceScore: 0,
            totalReports: 0,
            countryCode: 'INTERNAL',
            usageType: 'Private / Reserved IP',
            verdict: 'SAFE',
            note: 'Địa chỉ IP nội bộ / Local Loopback, an toàn.'
        };
    }

    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
        return {
            status: 'skipped',
            provider: 'AbuseIPDB',
            reason: 'Chưa cấu hình ABUSEIPDB_API_KEY trong .env (đăng ký miễn phí tại abuseipdb.com)'
        };
    }

    try {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`;
        const resp = await fetch(url, {
            headers: {
                'Key': apiKey,
                'Accept': 'application/json'
            },
            signal: AbortSignal.timeout(10000)
        });

        if (resp.status === 200) {
            const json = await resp.json();
            const d = json.data || {};
            const score = d.abuseConfidenceScore || 0;

            let verdict = 'SAFE';
            if (score >= 50) verdict = 'MALICIOUS';
            else if (score >= 20) verdict = 'SUSPICIOUS';

            return {
                status: 'success',
                provider: 'AbuseIPDB',
                ip: d.ipAddress,
                isPublic: d.isPublic,
                abuseConfidenceScore: score,
                totalReports: d.totalReports || 0,
                countryCode: d.countryCode || 'N/A',
                countryName: d.countryName || 'N/A',
                usageType: d.usageType || 'N/A',
                isp: d.isp || 'N/A',
                domain: d.domain || 'N/A',
                isWhitelisted: d.isWhitelisted || false,
                lastReportedAt: d.lastReportedAt || null,
                verdict
            };
        } else if (resp.status === 429) {
            return {
                status: 'rate_limited',
                provider: 'AbuseIPDB',
                message: 'Vượt quá hạn mức truy vấn AbuseIPDB hôm nay'
            };
        } else {
            return {
                status: 'error',
                provider: 'AbuseIPDB',
                message: `HTTP ${resp.status}`
            };
        }
    } catch (err) {
        return {
            status: 'error',
            provider: 'AbuseIPDB',
            message: err.message
        };
    }
}

/**
 * 4. Tra cứu File Hash qua VirusTotal API v3
 */
async function queryVirusTotalHash(hash) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
        return {
            status: 'skipped',
            provider: 'VirusTotal',
            reason: 'Chưa cấu hình VIRUSTOTAL_API_KEY trong .env'
        };
    }

    try {
        const url = `https://www.virustotal.com/api/v3/files/${hash}`;
        const resp = await fetch(url, {
            headers: {
                'x-apikey': apiKey,
                'Accept': 'application/json'
            },
            signal: AbortSignal.timeout(12000)
        });

        if (resp.status === 200) {
            const json = await resp.json();
            const attr = json.data?.attributes || {};
            const stats = attr.last_analysis_stats || {};
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);

            let verdict = 'SAFE';
            if (malicious >= 3) verdict = 'MALICIOUS';
            else if (malicious >= 1 || suspicious >= 2) verdict = 'SUSPICIOUS';

            const score = total > 0 ? Math.min(100, Math.round(((malicious * 1.0 + suspicious * 0.5) / total) * 100)) : 0;

            return {
                status: 'success',
                provider: 'VirusTotal',
                found: true,
                hash,
                maliciousCount: malicious,
                suspiciousCount: suspicious,
                totalEngines: total,
                detectionRatio: `${malicious}/${total}`,
                reputationScore: score,
                verdict,
                threatLabel: attr.popular_threat_classification?.suggested_threat_label || 'N/A',
                reportUrl: `https://www.virustotal.com/gui/file/${hash}`
            };
        } else if (resp.status === 404) {
            return {
                status: 'not_found',
                provider: 'VirusTotal',
                hash,
                found: false,
                message: 'Không tìm thấy mẫu mã băm này trong cơ sở dữ liệu VirusTotal'
            };
        } else {
            return {
                status: 'error',
                provider: 'VirusTotal',
                message: `HTTP ${resp.status}`
            };
        }
    } catch (err) {
        return {
            status: 'error',
            provider: 'VirusTotal',
            message: err.message
        };
    }
}

/**
 * 5. Tra cứu URL qua URLhaus (abuse.ch) & VirusTotal URL
 */
async function queryURLThreatIntel(rawUrl) {
    const results = {};

    // A. URLhaus API (Miễn phí, Open Source Threat Intelligence)
    try {
        const formData = new URLSearchParams();
        formData.append('url', rawUrl);

        const resp = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
            method: 'POST',
            body: formData,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            signal: AbortSignal.timeout(8000)
        });

        if (resp.status === 200) {
            const data = await resp.json();
            if (data.query_status === 'ok') {
                results.urlhaus = {
                    status: 'success',
                    provider: 'URLhaus (abuse.ch)',
                    listed: true,
                    threat: data.threat || 'Malicious URL',
                    urlStatus: data.url_status,
                    tags: data.tags || [],
                    reporter: data.reporter,
                    dateAdded: data.date_added,
                    verdict: 'MALICIOUS'
                };
            } else {
                results.urlhaus = {
                    status: 'not_found',
                    provider: 'URLhaus',
                    listed: false,
                    message: 'Không nằm trong danh sách đen URLhaus'
                };
            }
        }
    } catch (err) {
        results.urlhaus = { status: 'error', provider: 'URLhaus', message: err.message };
    }

    // B. VirusTotal URL check (nếu có API Key)
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtKey) {
        try {
            // VirusTotal URL identifier: base64 without padding '='
            const urlId = Buffer.from(rawUrl).toString('base64').replace(/=/g, '');
            const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
                headers: { 'x-apikey': vtKey, 'Accept': 'application/json' },
                signal: AbortSignal.timeout(10000)
            });

            if (resp.status === 200) {
                const json = await resp.json();
                const stats = json.data?.attributes?.last_analysis_stats || {};
                const mal = stats.malicious || 0;
                const sus = stats.suspicious || 0;
                const tot = mal + sus + (stats.undetected || 0) + (stats.harmless || 0);

                results.virustotal = {
                    status: 'success',
                    provider: 'VirusTotal URL',
                    maliciousCount: mal,
                    totalEngines: tot,
                    detectionRatio: `${mal}/${tot}`,
                    verdict: mal >= 2 ? 'MALICIOUS' : mal === 1 ? 'SUSPICIOUS' : 'SAFE'
                };
            } else if (resp.status === 404) {
                results.virustotal = { status: 'not_found', provider: 'VirusTotal URL', message: 'URL chưa có báo cáo trên VT' };
            }
        } catch (err) {
            results.virustotal = { status: 'error', provider: 'VirusTotal URL', message: err.message };
        }
    }

    // C. PhishTank API (Chuyên phát hiện lừa đảo Phishing)
    try {
        const formData = new URLSearchParams();
        formData.append('url', rawUrl);
        formData.append('format', 'json');
        if (process.env.PHISHTANK_API_KEY) {
            formData.append('app_key', process.env.PHISHTANK_API_KEY);
        }

        const ptResp = await fetch('https://checkurl.phishtank.com/checkurl/', {
            method: 'POST',
            body: formData,
            headers: { 'User-Agent': 'phishtank/mini-soar' },
            signal: AbortSignal.timeout(8000)
        });

        if (ptResp.status === 200) {
            const ptData = await ptResp.json();
            const res = ptData.results;
            if (res && res.in_database) {
                const isValidPhish = Boolean(res.valid);
                const isVerified = Boolean(res.verified);

                let ptVerdict = 'SAFE';
                let message = 'Đã xác minh: Không phải trang lừa đảo';
                if (isVerified && isValidPhish) {
                    ptVerdict = 'MALICIOUS';
                    message = 'Xác nhận lừa đảo (Phishing Site)';
                } else if (!isVerified) {
                    ptVerdict = 'SUSPICIOUS';
                    message = 'Đang chờ cộng đồng thẩm định';
                }

                results.phishtank = {
                    status: 'success',
                    provider: 'PhishTank',
                    inDatabase: true,
                    phishId: res.phish_id,
                    phishDetailPage: res.phish_detail_page,
                    verified: isVerified,
                    valid: isValidPhish,
                    verdict: ptVerdict,
                    message
                };
            } else {
                results.phishtank = {
                    status: 'not_found',
                    provider: 'PhishTank',
                    inDatabase: false,
                    message: 'Không tìm thấy trong cơ sở dữ liệu lừa đảo PhishTank'
                };
            }
        }
    } catch (err) {
        results.phishtank = { status: 'error', provider: 'PhishTank', message: err.message };
    }

    return results;
}

/**
 * 6. Tra cứu Domain qua URLhaus Host API
 */
async function queryDomainThreatIntel(domain) {
    const results = {};

    try {
        const formData = new URLSearchParams();
        formData.append('host', domain);

        const resp = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
            method: 'POST',
            body: formData,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            signal: AbortSignal.timeout(8000)
        });

        if (resp.status === 200) {
            const data = await resp.json();
            if (data.query_status === 'ok') {
                const count = (data.urls || []).length;
                results.urlhaus = {
                    status: 'success',
                    provider: 'URLhaus (abuse.ch)',
                    listed: count > 0,
                    activeMalwareUrlsCount: count,
                    firstSeen: data.firstseen,
                    verdict: count > 0 ? 'MALICIOUS' : 'SAFE'
                };
            } else {
                results.urlhaus = {
                    status: 'not_found',
                    provider: 'URLhaus Host',
                    listed: false,
                    message: 'Không có dữ liệu malware trên host này'
                };
            }
        }
    } catch (err) {
        results.urlhaus = { status: 'error', provider: 'URLhaus Host', message: err.message };
    }

    return results;
}

/**
 * 7. Hàm Enrich tổng hợp cho một IOC đơn lẻ (với Cache 24h)
 */
async function enrichSingleIOC(iocValue, iocType) {
    const cleanValue = String(iocValue).trim();
    if (!cleanValue) return null;

    // 1. Kiểm tra Cache MongoDB trước
    const cached = await checkCache(cleanValue);
    if (cached) {
        return {
            iocValue: cleanValue,
            iocType: cached.iocType,
            reputationScore: cached.reputationScore,
            verdict: cached.verdict,
            sources: cached.sources,
            lastChecked: cached.lastChecked,
            fromCache: true,
            cacheAgeMinutes: cached.cacheAgeMinutes
        };
    }

    // 2. Không có trong cache -> Gọi các nguồn Threat Intelligence
    let sources = {};
    let reputationScore = 0;
    let verdict = 'SAFE';

    if (iocType === 'ip') {
        const abuseRes = await queryAbuseIPDB(cleanValue);
        sources.abuseipdb = abuseRes;

        if (abuseRes.status === 'success') {
            reputationScore = abuseRes.abuseConfidenceScore || 0;
            verdict = abuseRes.verdict || 'SAFE';
        }
    } else if (iocType === 'hash') {
        const vtRes = await queryVirusTotalHash(cleanValue);
        sources.virustotal = vtRes;

        if (vtRes.status === 'success') {
            reputationScore = vtRes.reputationScore || 0;
            verdict = vtRes.verdict || 'SAFE';
        }
    } else if (iocType === 'url') {
        const urlSources = await queryURLThreatIntel(cleanValue);
        sources = urlSources;

        const uh = urlSources.urlhaus || {};
        const vt = urlSources.virustotal || {};
        const pt = urlSources.phishtank || {};

        if (pt.inDatabase && pt.valid) {
            reputationScore = 95;
            verdict = 'MALICIOUS';
        } else if (uh.listed) {
            reputationScore = 95;
            verdict = 'MALICIOUS';
        } else if (vt.verdict === 'MALICIOUS') {
            reputationScore = 85;
            verdict = 'MALICIOUS';
        } else if (vt.verdict === 'SUSPICIOUS') {
            reputationScore = 50;
            verdict = 'SUSPICIOUS';
        }
    } else if (iocType === 'domain') {
        const domSources = await queryDomainThreatIntel(cleanValue);
        sources = domSources;

        const uh = domSources.urlhaus || {};
        if (uh.listed && uh.activeMalwareUrlsCount > 0) {
            reputationScore = 90;
            verdict = 'MALICIOUS';
        }
    }

    // 3. Lưu vào Cache MongoDB
    await saveToCache(cleanValue, iocType, reputationScore, verdict, sources);

    return {
        iocValue: cleanValue,
        iocType,
        reputationScore,
        verdict,
        sources,
        lastChecked: new Date(),
        fromCache: false
    };
}

/**
 * 8. Tự động trích xuất toàn bộ IOCs từ Email và làm rõ đa nguồn
 */
async function enrichAllIOCsFromEmail(emailRecord) {
    const iocList = [];
    const seenValues = new Set();

    function addIOC(value, type) {
        if (!value) return;
        const v = String(value).trim();
        if (v && !seenValues.has(v.toLowerCase())) {
            seenValues.add(v.toLowerCase());
            iocList.push({ value: v, type });
        }
    }

    // A. Lấy IPs từ Received Chain & SPF
    const chain = emailRecord.headerAnalysis?.headers?.received_chain || [];
    chain.forEach(hop => {
        if (hop.ip) addIOC(hop.ip, 'ip');
    });

    const spfIp = emailRecord.headerAnalysis?.authentication?.spf?.ip;
    if (spfIp) addIOC(spfIp, 'ip');

    // B. Lấy Domains
    const senderDomain = emailRecord.headerAnalysis?.domain_analysis?.sender_domain;
    if (senderDomain) addIOC(senderDomain, 'domain');

    // C. Lấy URLs từ URL Analysis & Content Analysis
    const IGNORABLE_HOSTS = ['w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org', 'xml.org', 'schema.org'];
    const urlsFromScanner = (emailRecord.urlAnalysis?.urls || []).map(u => u.url);
    const urlsFromContent = emailRecord.contentAnalysis?.extracted_urls || [];
    const allUrls = [...new Set([...urlsFromScanner, ...urlsFromContent])];
    allUrls.forEach(u => {
        try {
            const parsed = new URL(u);
            const host = (parsed.hostname || '').toLowerCase();
            // Bỏ qua các đường link định dạng DOCTYPE / XML chuẩn của trang web
            if (IGNORABLE_HOSTS.some(h => host === h || host.endsWith('.' + h))) {
                return;
            }
            addIOC(u, 'url');
            if (host && host !== senderDomain) {
                addIOC(host, 'domain');
            }
        } catch (_) {
            addIOC(u, 'url');
        }
    });

    // D. Lấy Hashes từ File đính kèm
    const attachments = emailRecord.attachmentAnalysis?.attachments || [];
    attachments.forEach(att => {
        if (att.hashes?.sha256) addIOC(att.hashes.sha256, 'hash');
        if (att.hashes?.md5) addIOC(att.hashes.md5, 'hash');
    });

    if (iocList.length === 0) {
        return {
            totalIOCs: 0,
            summary: 'Không phát hiện IOC (IP, Hash, URL) nào trong email để tra cứu.',
            overallVerdict: 'NO_IOCS',
            iocs: [],
            cacheHitRate: '0%',
            cachedCount: 0,
            liveQueriedCount: 0
        };
    }

    // Tiến hành tra cứu Threat Intelligence cho từng IOC (với Cache 24h)
    const enrichedResults = [];
    for (const item of iocList) {
        try {
            const enriched = await enrichSingleIOC(item.value, item.type);
            if (enriched) enrichedResults.push(enriched);
        } catch (err) {
            console.error(`[ThreatIntel] Lỗi enrich IOC ${item.value}: ${err.message}`);
        }
    }

    // Thống kê kết quả
    const cachedCount = enrichedResults.filter(r => r.fromCache).length;
    const liveCount = enrichedResults.length - cachedCount;
    const malCount = enrichedResults.filter(r => r.verdict === 'MALICIOUS').length;
    const susCount = enrichedResults.filter(r => r.verdict === 'SUSPICIOUS').length;

    let overallVerdict = 'SAFE';
    if (malCount > 0) overallVerdict = 'MALICIOUS';
    else if (susCount > 0) overallVerdict = 'SUSPICIOUS';

    const maxScore = enrichedResults.reduce((max, r) => Math.max(max, r.reputationScore || 0), 0);

    return {
        totalIOCs: enrichedResults.length,
        cachedCount,
        liveQueriedCount: liveCount,
        cacheHitRate: enrichedResults.length > 0 ? `${Math.round((cachedCount / enrichedResults.length) * 100)}%` : '0%',
        maliciousCount: malCount,
        suspiciousCount: susCount,
        safeCount: enrichedResults.length - malCount - susCount,
        maxReputationScore: maxScore,
        overallVerdict,
        iocs: enrichedResults,
        analyzedAt: new Date().toISOString()
    };
}

module.exports = {
    checkCache,
    saveToCache,
    queryAbuseIPDB,
    queryVirusTotalHash,
    queryURLThreatIntel,
    queryDomainThreatIntel,
    enrichSingleIOC,
    enrichAllIOCsFromEmail
};
