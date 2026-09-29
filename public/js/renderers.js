/**
 * Mini SOAR - Dashboard UI Component Renderers
 * Quản lý các hàm vẽ giao diện HTML cho từng module phân tích
 */

/**
 * Hiển thị danh sách email trong Inbox
 */
function renderList() {
    const container = document.getElementById('email-list-body');
    if (!emails.length) {
        container.innerHTML = '<div class="loading">Chưa có email nào</div>';
        return;
    }
    container.innerHTML = emails.map(e => {
        const isUnanalyzed = !e.headerAnalysis && !e.contentAnalysis && !e.urlAnalysis && !e.attachmentAnalysis && !e.iocAnalysis;
        const v = isUnanalyzed ? 'UNANALYZED' : (e.riskLevel || (e.riskScore >= 75 ? 'MALICIOUS' : e.riskScore >= 50 ? 'SUSPICIOUS' : (e.riskScore !== null && e.riskScore !== undefined) ? 'CLEAN' : 'none'));
        
        const badgeHtml = isUnanalyzed 
            ? `<span class="tag" style="background:#a4b0be22;color:#a4b0be;border:1px solid #a4b0be44;">⚪ Chưa phân tích</span>`
            : (e.riskLevel || typeof e.riskScore === 'number' 
                ? `<span class="tag" style="background:${riskColor(v)}22;color:${riskColor(v)}">${v} (${e.riskScore ?? e.overallRiskScore ?? 0})</span>` 
                : '');

        return `
        <div class="email-item ${e._id === selectedId ? 'active' : ''}" onclick="selectEmail('${e._id}')">
            <div class="risk-dot ${v}"></div>
            <div class="info">
                <div class="sender">${escHtml(e.sender)}</div>
                <div class="subject">${decodeSubject(e.subject)}</div>
                <div class="meta-row">
                    <span class="tag status-${e.status}">${e.status}</span>
                    ${badgeHtml}
                    <span class="tag" style="background:#ffffff08;color:#666">${formatSize(e.fileSize)}</span>
                </div>
            </div>
        </div>
    `;
    }).join('');
}

/**
 * Cập nhật các khối thống kê tổng số lượng email và phân cấp rủi ro
 */
function updateStats() {
    const elTotal = document.getElementById('stat-total');
    if (elTotal) elTotal.textContent = emails.length;

    const isUnanalyzed = e => !e.headerAnalysis && !e.contentAnalysis && !e.urlAnalysis && !e.attachmentAnalysis && !e.iocAnalysis;

    const pendingCount = emails.filter(isUnanalyzed).length;
    const maliciousCount = emails.filter(e => !isUnanalyzed(e) && (e.riskLevel === 'MALICIOUS' || e.riskLevel === 'HIGH' || (e.riskScore || 0) >= 75)).length;
    const suspiciousCount = emails.filter(e => !isUnanalyzed(e) && (e.riskLevel === 'SUSPICIOUS' || e.riskLevel === 'MEDIUM' || ((e.riskScore || 0) >= 50 && (e.riskScore || 0) < 75))).length;
    const cleanCount = emails.filter(e => !isUnanalyzed(e) && (e.riskLevel === 'CLEAN' || e.riskLevel === 'LOW' || ((e.riskScore || 0) < 50 && e.riskScore !== null && e.riskScore !== undefined))).length;

    const elPending = document.getElementById('stat-pending');
    if (elPending) elPending.textContent = pendingCount;
    const elMal = document.getElementById('stat-malicious');
    if (elMal) elMal.textContent = maliciousCount;
    const elSusp = document.getElementById('stat-suspicious');
    if (elSusp) elSusp.textContent = suspiciousCount;
    const elClean = document.getElementById('stat-clean');
    if (elClean) elClean.textContent = cleanCount;
}

/**
 * Hiển thị kết quả Phân tích Social Engineering & Nội dung AI (Qwen 2.5 Local)
 */
function renderContentAnalysis(ca) {
    const ai = ca.ai_analysis?.data || {};
    const meta = ca.metadata || {};
    const keywords = ca.keywords_detected || {};
    const urls = ca.extracted_urls || [];
    const seScore = ai.social_engineering_score ?? 'N/A';
    const verdict = ai.verdict || 'UNKNOWN';
    const urgency = ai.urgency_level || 'LOW';

    let verdictColor = '#2ed573';
    if (verdict === 'PHISHING') verdictColor = '#ff4757';
    else if (verdict === 'SUSPICIOUS') verdictColor = '#ffa502';

    let urgencyColor = '#2ed573';
    if (urgency === 'CRITICAL' || urgency === 'HIGH') urgencyColor = '#ff4757';
    else if (urgency === 'MEDIUM') urgencyColor = '#ffa502';

    const tacticsHtml = (ai.tactics || []).map(t =>
        `<span style="background:#a55eea22; color:#a55eea; border:1px solid #a55eea55; padding:3px 8px; border-radius:12px; font-size:11px; margin-right:6px; font-weight:600;">🛡️ ${escHtml(t)}</span>`
    ).join('') || '<span style="color:#666;">Không phát hiện</span>';

    const keywordsHtml = Object.keys(keywords).map(cat => `
        <div style="margin-bottom: 6px;">
            <strong style="color: #ffa502; font-size: 12px;">${escHtml(cat)}:</strong>
            ${keywords[cat].map(kw => `<span style="background:#ffa50222; color:#ffa502; padding:2px 6px; border-radius:4px; font-size:11px; margin-left:4px;">"${escHtml(kw)}"</span>`).join('')}
        </div>
    `).join('') || '<div style="color:#2ed573; font-size:12px;">✅ Không phát hiện từ khóa giật gân, đe dọa.</div>';

    return `
        <div class="card" style="border: 1px solid #a55eea55; background: #161b2b; margin-bottom: 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; border-bottom:1px solid #ffffff10; padding-bottom:10px;">
                <h3 style="color:#a55eea; margin:0; font-size:14px; display:flex; align-items:center; gap:8px;">
                    <span>🧠</span> KẾT QUẢ PHÂN TÍCH SOCIAL ENGINEERING (AI QWEN 2.5 LOCAL)
                </h3>
                <span style="font-size:11px; color:#888;">Model: ${escHtml(ca.ai_analysis?.model || 'qwen2.5:3b')}</span>
            </div>

            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
                <!-- SE Assessment -->
                <div style="background:#0f1420; border-radius:8px; padding:14px; text-align:center; border: 1px solid #ffffff0a; display:flex; flex-direction:column; justify-content:center; align-items:center;">
                    <div style="font-size:11px; color:#888; text-transform:uppercase; margin-bottom:8px; font-weight:600; letter-spacing:0.5px;">Đánh Giá Thao Túng Tâm Lý</div>
                    <div style="display:inline-flex; align-items:center; gap:6px; padding:6px 14px; border-radius:6px; font-size:13px; font-weight:bold; background:${verdictColor}22; color:${verdictColor}; border:1px solid ${verdictColor}44; margin-bottom:8px;">
                        <span>${verdict === 'PHISHING' ? '🔴' : verdict === 'SUSPICIOUS' ? '🟡' : '🟢'}</span>
                        <span>${verdict === 'PHISHING' ? 'NGUY CƠ CAO (PHISHING)' : verdict === 'SUSPICIOUS' ? 'ĐÁNG NGỜ (SUSPICIOUS)' : 'AN TOÀN (CLEAN)'}</span>
                    </div>
                    <div style="font-size:11.5px; color:#aaa; line-height:1.4;">
                        ${verdict === 'PHISHING' ? 'Phát hiện hành vi dẫn dụ / thao túng tâm lý rõ rệt' : verdict === 'SUSPICIOUS' ? 'Có yếu tố nghi vấn về đòn tâm lý trong thư' : 'Nội dung thư thông thường, không phát hiện dẫn dụ'}
                    </div>
                </div>

                <!-- Urgency & Target -->
                <div style="background:#0f1420; border-radius:8px; padding:14px; border: 1px solid #ffffff0a;">
                    <div style="font-size:11px; color:#888; text-transform:uppercase; margin-bottom:6px;">Mức Độ Khẩn Cấp (Urgency)</div>
                    <span style="display:inline-block; padding:4px 10px; border-radius:4px; font-size:12px; font-weight:bold; background:${urgencyColor}22; color:${urgencyColor}; margin-bottom:10px;">
                        🚨 ${urgency}
                    </span>
                    <div style="font-size:11px; color:#888; text-transform:uppercase; margin-bottom:4px;">Mục tiêu nghi vấn:</div>
                    <div style="font-size:12px; color:#ddd; line-height:1.4;">${escHtml(ai.primary_target || 'N/A')}</div>
                </div>

                <!-- Tactics -->
                <div style="background:#0f1420; border-radius:8px; padding:14px; border: 1px solid #ffffff0a;">
                    <div style="font-size:11px; color:#888; text-transform:uppercase; margin-bottom:8px;">Chiến thuật Social Engineering</div>
                    <div style="display:flex; flex-wrap:wrap; gap:6px;">${tacticsHtml}</div>
                </div>
            </div>

            <!-- AI Explanation -->
            <div style="background:#0f1420; border-left:3px solid #a55eea; border-radius:6px; padding:12px 16px; margin-bottom:16px;">
                <div style="font-size:12px; color:#a55eea; font-weight:bold; margin-bottom:4px;">💡 Chuyên gia AI nhận xét:</div>
                <div style="font-size:13px; color:#e0e0e0; line-height:1.5;">${escHtml(ai.explanation || 'Không có nhận xét')}</div>
            </div>

            <!-- Detected Keywords -->
            <div style="background:#0f1420; border-radius:8px; padding:12px 16px; margin-bottom:16px;">
                <div style="font-size:12px; color:#888; font-weight:bold; margin-bottom:8px;">🎯 Từ khóa kích động tâm lý phát hiện được:</div>
                ${keywordsHtml}
            </div>

            <!-- Clean Text Content -->
            <div style="background:#0f1420; border-radius:8px; padding:12px 16px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                    <span style="font-size:12px; color:#888; font-weight:bold;">📄 Văn bản thuần túy (đã bóc sạch HTML):</span>
                    <span style="font-size:11px; color:#666;">${meta.body_length_chars || 0} ký tự | ${urls.length} links</span>
                </div>
                <pre style="background:#090d15; color:#aaa; padding:10px; border-radius:6px; font-family:'Consolas',monospace; font-size:11px; white-space:pre-wrap; max-height:140px; overflow-y:auto;">${escHtml(ca.clean_body || '')}</pre>
                ${urls.length > 0 ? `
                    <div style="margin-top:8px; font-size:11px; color:#ff4757;">
                        🔗 <strong>Links cào được:</strong> ${urls.map(u => `<code style="background:#ff475715; color:#ff6b6b; padding:1px 4px; border-radius:3px;">${escHtml(u)}</code>`).join(', ')}
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Hiển thị kết quả Truy vết URL & Chuỗi Chuyển hướng Redirect Chain
 */
function renderUrlAnalysis(ua) {
    const urls = ua.urls || [];
    const verdict = ua.overall_verdict || 'CLEAN';
    let verdictColor = verdict === 'DANGEROUS' ? '#ff4757' : verdict === 'CAUTION' ? '#ffa502' : '#2ed573';
    let verdictIcon = verdict === 'DANGEROUS' ? '🚨' : verdict === 'CAUTION' ? '⚠️' : '✅';

    if (urls.length === 0) {
        return `<div class="card" style="border:1px solid #2ed57355; text-align:center; padding:20px; color:#2ed573;">✅ Không tìm thấy URL nào trong email.</div>`;
    }

    const urlCards = urls.map(u => {
        const r = u.risk || {};
        const rc = u.redirect_chain || {};
        const chain = rc.chain || [];
        const rColor = r.risk_level === 'HIGH' ? '#ff4757' : r.risk_level === 'MEDIUM' ? '#ffa502' : '#2ed573';
        const us = u.urlscan || {};

        return `
            <div style="background:#0f1420; border-radius:8px; padding:14px; margin-bottom:12px; border: 1px solid ${rColor}44; border-left: 3px solid ${rColor};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <code style="font-size:12px; color:#00d4ff; word-break:break-all;">${escHtml(u.url)}</code>
                    <span style="padding:3px 10px; border-radius:4px; font-size:11px; font-weight:bold; background:${rColor}22; color:${rColor}; white-space:nowrap; margin-left:8px;">
                        ${r.risk_level || 'N/A'} (${r.risk_score || 0})
                    </span>
                </div>

                <!-- Redirect Chain -->
                <div style="margin-bottom:8px;">
                    <div style="font-size:11px; color:#888; margin-bottom:4px; font-weight:bold;">🔀 Redirect Chain (${rc.total_redirects || 0} lần redirect):</div>
                    <div style="display:flex; flex-wrap:wrap; align-items:center; gap:4px; font-size:11px;">
                        ${chain.map((h, i) => `
                            <span style="background:#1a2836; padding:3px 8px; border-radius:4px; color:${h.is_final ? '#2ed573' : h.status_code >= 300 ? '#ffa502' : '#ddd'};">
                                ${h.status || h.status_code || '?'} ${escHtml((h.url || '').replace(/^https?:\/\//i, '').substring(0, 40))}${(h.url||'').length > 47 ? '...' : ''}
                            </span>
                            ${h.redirect_to ? '<span style="color:#666;">→</span>' : ''}
                        `).join('')}
                    </div>
                </div>

                <!-- Flags -->
                ${(r.flags || []).length > 0 ? `
                    <div style="margin-top:6px;">
                        ${r.flags.map(f => `<div style="font-size:11px; color:#ddd; padding:2px 0;">${f}</div>`).join('')}
                    </div>
                ` : ''}

                <!-- URLScan -->
                ${us.status === 'success' ? `
                    <div style="margin-top:8px; padding:8px 12px; background:#1a2836; border-radius:6px;">
                        <div style="font-size:11px; color:#888; font-weight:bold; margin-bottom:4px;">🌐 URLScan.io Sandbox:</div>
                        <div style="display:flex; gap:12px; flex-wrap:wrap; font-size:11px;">
                            <span>📄 ${escHtml(us.page?.title || 'N/A')}</span>
                            <span>🌍 ${escHtml(us.page?.country || 'N/A')}</span>
                            <span>🖥️ ${escHtml(us.page?.ip || 'N/A')}</span>
                            ${us.verdicts?.overall_malicious ? '<span style="color:#ff4757; font-weight:bold;">🚨 MALICIOUS</span>' : '<span style="color:#2ed573;">✅ Clean</span>'}
                        </div>
                        <a href="${us.scan_url}" target="_blank" style="font-size:11px; color:#00d4ff; text-decoration:none;">🔍 Xem chi tiết trên URLScan.io →</a>
                        ${us.screenshot_url ? `<div style="margin-top:6px;"><img src="${us.screenshot_url}" style="max-width:100%; border-radius:6px; border:1px solid #ffffff15;" onerror="this.style.display='none'"></div>` : ''}
                    </div>
                ` : us.status === 'skipped' ? `<div style="font-size:11px; color:#666; margin-top:4px;">ℹ️ URLScan.io: ${escHtml(us.reason || 'Không có API key')}</div>` : ''}
            </div>
        `;
    }).join('');

    return `
        <div class="card" style="border: 1px solid #ff634755; background: #161b2b; margin-bottom: 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; border-bottom:1px solid #ffffff10; padding-bottom:10px;">
                <h3 style="color:#ff6347; margin:0; font-size:14px; display:flex; align-items:center; gap:8px;">
                    <span>🔗</span> TRUY VẾT URL & REDIRECT CHAIN
                </h3>
                <span style="padding:4px 12px; border-radius:4px; font-size:12px; font-weight:bold; background:${verdictColor}22; color:${verdictColor};">
                    ${verdictIcon} ${verdict} (${ua.total_urls} URLs)
                </span>
            </div>
            ${urlCards}
        </div>
    `;
}

/**
 * Hiển thị kết quả Phân tích Tệp đính kèm & Cloud Sandbox
 */
function renderAttachmentAnalysis(aa) {
    const atts = aa.attachments || [];
    const verdict = aa.overall_verdict || 'CLEAN';
    const total = aa.total_attachments || 0;

    if (!aa.has_attachments || total === 0) {
        return `
            <div class="card" style="border: 1px solid #20bf6b55; background: #161b2b; margin-bottom: 20px;">
                <div style="display:flex; align-items:center; gap:10px; color:#2ed573;">
                    <span style="font-size:20px;">📎</span>
                    <span><strong>File đính kèm:</strong> Email này không có file đính kèm.</span>
                </div>
            </div>
        `;
    }

    let verdictColor = '#2ed573';
    let verdictIcon = '✅';
    if (verdict === 'DANGEROUS') {
        verdictColor = '#ff4757';
        verdictIcon = '🚨';
    } else if (verdict === 'SUSPICIOUS') {
        verdictColor = '#ffa502';
        verdictIcon = '⚠️';
    }

    const cardsHtml = atts.map((att, i) => {
        const h = att.heuristics || {};
        const hashes = att.hashes || {};
        const magic = att.magic_bytes || {};
        const sandbox = att.sandbox_reports || {};
        const ha = sandbox.hybrid_analysis || {};
        const vt = sandbox.virustotal || {};

        let rColor = '#2ed573';
        if (h.risk_level === 'HIGH') rColor = '#ff4757';
        else if (h.risk_level === 'MEDIUM') rColor = '#ffa502';

        return `
            <div style="background:#0f1420; border-radius:8px; padding:14px; margin-bottom:12px; border: 1px solid ${rColor}44; border-left: 3px solid ${rColor};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:18px;">📁</span>
                        <strong style="font-size:13px; color:#00d4ff; word-break:break-all;">${escHtml(att.filename)}</strong>
                        <span style="background:#ffffff15; color:#aaa; padding:2px 6px; border-radius:4px; font-size:11px;">${att.file_size_formatted}</span>
                    </div>
                    <span style="padding:3px 10px; border-radius:4px; font-size:11px; font-weight:bold; background:${rColor}22; color:${rColor}; white-space:nowrap; margin-left:8px;">
                        ${h.risk_level || 'LOW'} (${h.risk_score || 0}/100)
                    </span>
                </div>

                <!-- Magic bytes & type -->
                <div style="font-size:11px; color:#ddd; margin-bottom:8px; background:#161d2d; padding:8px 10px; border-radius:6px;">
                    <div><strong>MIME Type:</strong> ${escHtml(att.content_type || 'N/A')}</div>
                    <div><strong>Magic Bytes:</strong> ${escHtml(magic.description || 'Unknown')} <code style="color:#ffa502; margin-left:6px;">[${escHtml(magic.first_16_hex || '')}]</code></div>
                    <div style="color:#888; font-size:10px; margin-top:2px;">Quarantine: <code>${escHtml(att.quarantine_path || '')}</code></div>
                </div>

                <!-- Hashes -->
                <div style="margin-bottom:8px; font-family:'Consolas',monospace; font-size:11px;">
                    <div style="color:#aaa; display:flex; gap:6px; margin-bottom:2px;"><strong style="color:#888; width:60px;">MD5:</strong> <span>${hashes.md5 || ''}</span></div>
                    <div style="color:#aaa; display:flex; gap:6px; margin-bottom:2px;"><strong style="color:#888; width:60px;">SHA-1:</strong> <span>${hashes.sha1 || ''}</span></div>
                    <div style="color:#00d4ff; display:flex; gap:6px;"><strong style="color:#888; width:60px;">SHA-256:</strong> <span>${hashes.sha256 || ''}</span></div>
                </div>

                <!-- Flags -->
                ${(h.flags || []).length > 0 ? `
                    <div style="margin-top:8px; border-top:1px solid #ffffff0a; padding-top:6px;">
                        ${h.flags.map(f => `<div style="font-size:11px; color:#ff6b6b; padding:2px 0;">${escHtml(f)}</div>`).join('')}
                    </div>
                ` : ''}

                <!-- Cloud Sandbox Report -->
                <div style="margin-top:8px; padding:8px 10px; background:#1a2836; border-radius:6px; font-size:11px;">
                    <strong style="color:#2bcbba;">☁️ Cloud Sandbox & Threat Intelligence:</strong>
                    ${ha.status === 'success' ? `
                        <div style="margin-top:4px;">
                            <span style="color:#ffa502;">Falcon Sandbox:</span> <strong>${escHtml(ha.verdict)}</strong> (Threat score: ${ha.threat_score}) | AV Detect: ${ha.av_detect}
                            <br><a href="${ha.report_url}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem báo cáo hành vi đầy đủ trên Hybrid Analysis →</a>
                        </div>
                    ` : `
                        <div style="color:#888; margin-top:3px;">
                            ${escHtml(ha.reason || ha.message || 'Chưa có dữ liệu')}
                        </div>
                    `}
                    ${vt.status === 'success' ? `
                        <div style="margin-top:4px;">
                            <span style="color:#ffa502;">VirusTotal:</span> <strong>${vt.detection_ratio}</strong> động cơ phát hiện | 
                            <a href="${vt.report_url}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem chi tiết trên VirusTotal →</a>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');

    return `
        <div class="card" style="border: 1px solid #20bf6b55; background: #161b2b; margin-bottom: 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; border-bottom:1px solid #ffffff10; padding-bottom:10px;">
                <h3 style="color:#2bcbba; margin:0; font-size:14px; display:flex; align-items:center; gap:8px;">
                    <span>📎</span> PHÂN TÍCH ATTACHMENT & PAYLOAD (${total} FILES)
                </h3>
                <span style="padding:4px 12px; border-radius:4px; font-size:12px; font-weight:bold; background:${verdictColor}22; color:${verdictColor};">
                    ${verdictIcon} ${verdict}
                </span>
            </div>
            ${cardsHtml}
        </div>
    `;
}

/**
 * Hiển thị kết quả Phân tích Tình báo Đe dọa (Threat Intelligence & IOCs)
 */
function renderIOCAnalysis(data) {
    const iocs = data.iocs || [];
    const total = data.totalIOCs || 0;
    const cachedCount = data.cachedCount || 0;
    const hitRate = data.cacheHitRate || '0%';
    const verdict = data.overallVerdict || 'SAFE';

    if (total === 0) {
        return `
            <div class="card" style="border: 1px solid #45aaf255; background: #161b2b; margin-bottom: 20px;">
                <div style="display:flex; align-items:center; gap:10px; color:#45aaf2;">
                    <span style="font-size:20px;">🌐</span>
                    <span><strong>Threat Intelligence:</strong> ${escHtml(data.summary || 'Không phát hiện IOC nào.')}</span>
                </div>
            </div>
        `;
    }

    let verdictColor = '#2ed573';
    let verdictIcon = '✅';
    if (verdict === 'MALICIOUS') {
        verdictColor = '#ff4757';
        verdictIcon = '🚨';
    } else if (verdict === 'SUSPICIOUS') {
        verdictColor = '#ffa502';
        verdictIcon = '⚠️';
    }

    const iocCards = iocs.map(ioc => {
        const s = ioc.sources || {};
        const score = ioc.reputationScore || 0;
        let itemColor = '#2ed573';
        if (ioc.verdict === 'MALICIOUS') itemColor = '#ff4757';
        else if (ioc.verdict === 'SUSPICIOUS') itemColor = '#ffa502';

        let typeBadgeColor = '#4b7bec';
        if (ioc.iocType === 'ip') typeBadgeColor = '#26de81';
        else if (ioc.iocType === 'hash') typeBadgeColor = '#fd9644';
        else if (ioc.iocType === 'url') typeBadgeColor = '#a55eea';
        else if (ioc.iocType === 'domain') typeBadgeColor = '#2bcbba';

        let detailsHtml = '';

        // Chi tiết nguồn AbuseIPDB (cho IP)
        if (s.abuseipdb) {
            const ab = s.abuseipdb;
            if (ab.status === 'success') {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#ddd; background:#1a2334; padding:6px 10px; border-radius:4px;">
                        <strong style="color:#2bcbba;">🛡️ AbuseIPDB:</strong> 
                        Confidence: <strong style="color:${ab.abuseConfidenceScore > 20 ? '#ff4757' : '#2ed573'};">${ab.abuseConfidenceScore}%</strong> | 
                        Báo cáo: <strong>${ab.totalReports}</strong> lần | 
                        Quốc gia: <strong>${escHtml(ab.countryCode || 'N/A')}</strong> | 
                        ISP: <strong>${escHtml(ab.isp || 'N/A')}</strong>
                        ${ab.usageType ? ` | <span>${escHtml(ab.usageType)}</span>` : ''}
                    </div>
                `;
            } else if (ab.isPrivate) {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#aaa; background:#1a2334; padding:6px 10px; border-radius:4px;">
                        🛡️ <strong>AbuseIPDB:</strong> ${escHtml(ab.note)}
                    </div>
                `;
            } else {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#888;">
                        AbuseIPDB: ${escHtml(ab.reason || ab.message || 'Chưa có dữ liệu')}
                    </div>
                `;
            }
        }

        // Chi tiết nguồn VirusTotal (cho Hash/URL)
        if (s.virustotal) {
            const vt = s.virustotal;
            if (vt.status === 'success') {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#ddd; background:#1a2334; padding:6px 10px; border-radius:4px;">
                        <strong style="color:#00d4ff;">🦠 VirusTotal:</strong> 
                        Phát hiện: <strong style="color:${vt.maliciousCount > 0 ? '#ff4757' : '#2ed573'};">${vt.detectionRatio || (vt.maliciousCount + '/' + vt.totalEngines)}</strong> Antivirus | 
                        ${vt.threatLabel ? `Nhãn: <code style="color:#ffa502;">${escHtml(vt.threatLabel)}</code> | ` : ''}
                        ${vt.reportUrl ? `<a href="${vt.reportUrl}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem báo cáo VT →</a>` : ''}
                    </div>
                `;
            } else if (vt.status === 'not_found') {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#888;">
                        VirusTotal: ${escHtml(vt.message || 'Không tìm thấy mẫu')}
                    </div>
                `;
            }
        }

        // Chi tiết nguồn URLhaus (cho URL/Domain)
        if (s.urlhaus) {
            const uh = s.urlhaus;
            if (uh.status === 'success') {
                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#ddd; background:#1a2334; padding:6px 10px; border-radius:4px;">
                        <strong style="color:#ff6b6b;">🚨 URLhaus (abuse.ch):</strong> 
                        ${uh.listed ? `<span style="color:#ff4757; font-weight:bold;">ĐÃ BỊ LIỆT VÀO DANH SÁCH ĐEN!</span> (${escHtml(uh.threat || 'Malware')} - Trạng thái: ${escHtml(uh.urlStatus || 'Online')})` : '<span style="color:#2ed573;">Clean (Không nằm trong blacklist)</span>'}
                    </div>
                `;
            }
        }

        // Chi tiết nguồn PhishTank (cho URL)
        if (s.phishtank) {
            const pt = s.phishtank;
            if (pt.status === 'success') {
                let ptHtml = '';
                if (pt.inDatabase && pt.valid) {
                    ptHtml = `<span style="color:#ff4757; font-weight:bold;">🚨 XÁC NHẬN LỪA ĐẢO (Phishing Site - ID: ${pt.phishId})</span> | <a href="${escHtml(pt.phishDetailPage || '')}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem bằng chứng trên PhishTank →</a>`;
                } else if (pt.inDatabase && pt.verified && !pt.valid) {
                    ptHtml = `<span style="color:#2ed573; font-weight:bold;">✅ ĐÃ XÁC MINH AN TOÀN</span> (Bài nộp #${pt.phishId} đã được cộng đồng PhishTank xác nhận <span style="color:#2ed573;">KHÔNG PHẢI</span> lừa đảo) | <a href="${escHtml(pt.phishDetailPage || '')}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem chi tiết →</a>`;
                } else if (pt.inDatabase && !pt.verified) {
                    ptHtml = `<span style="color:#ffa502; font-weight:bold;">⚠️ ĐANG CHỜ XÁC MINH</span> (Bài nộp #${pt.phishId} đang chờ cộng đồng thẩm định) | <a href="${escHtml(pt.phishDetailPage || '')}" target="_blank" style="color:#00d4ff; text-decoration:none;">Xem chi tiết →</a>`;
                } else {
                    ptHtml = '<span style="color:#2ed573;">Không có trong cơ sở dữ liệu lừa đảo PhishTank</span>';
                }

                detailsHtml += `
                    <div style="margin-top:6px; font-size:11px; color:#ddd; background:#1a2334; padding:6px 10px; border-radius:4px;">
                        <strong style="color:#ffa502;">🎣 PhishTank:</strong> ${ptHtml}
                    </div>
                `;
            }
        }

        return `
            <div style="background:#0f1420; border-radius:8px; padding:12px 14px; margin-bottom:10px; border:1px solid ${itemColor}44; border-left:3px solid ${itemColor};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <div style="display:flex; align-items:center; gap:8px; min-width:0;">
                        <span style="background:${typeBadgeColor}22; color:${typeBadgeColor}; border:1px solid ${typeBadgeColor}55; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:bold; text-transform:uppercase;">
                            ${ioc.iocType}
                        </span>
                        <code style="font-size:12px; color:#fff; word-break:break-all;">${escHtml(ioc.iocValue)}</code>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px; white-space:nowrap; margin-left:12px;">
                        ${ioc.fromCache ? `
                            <span style="font-size:10px; background:#2ed57315; color:#2ed573; border:1px solid #2ed57344; padding:2px 6px; border-radius:4px;" title="Lấy từ Cache MongoDB trong vòng 24h">
                                ⚡ Cache (${ioc.cacheAgeMinutes ? ioc.cacheAgeMinutes + 'p' : '<24h'})
                            </span>
                        ` : `
                            <span style="font-size:10px; background:#00d4ff15; color:#00d4ff; border:1px solid #00d4ff44; padding:2px 6px; border-radius:4px;">
                                🌐 API Live
                            </span>
                        `}
                        <span style="padding:2px 8px; border-radius:4px; font-size:11px; font-weight:bold; background:${itemColor}22; color:${itemColor};">
                            ${ioc.verdict} (${score}/100)
                        </span>
                    </div>
                </div>
                ${detailsHtml}
            </div>
        `;
    }).join('');

    return `
        <div class="card" style="border: 1px solid #45aaf255; background: #161b2b; margin-bottom: 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid #ffffff10; padding-bottom:10px;">
                <h3 style="color:#45aaf2; margin:0; font-size:14px; display:flex; align-items:center; gap:8px;">
                    <span>🌐</span> THREAT INTELLIGENCE & IOC REPUTATION (${total} IOCS)
                </h3>
                <span style="padding:4px 12px; border-radius:4px; font-size:12px; font-weight:bold; background:${verdictColor}22; color:${verdictColor};">
                    ${verdictIcon} ${verdict}
                </span>
            </div>

            <!-- Stats Bar -->
            <div style="display:flex; justify-content:space-between; align-items:center; background:#0f1420; padding:10px 14px; border-radius:6px; margin-bottom:14px; font-size:11px; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; gap:16px;">
                    <span>🚨 <strong style="color:#ff4757;">${data.maliciousCount || 0}</strong> Malicious</span>
                    <span>⚠️ <strong style="color:#ffa502;">${data.suspiciousCount || 0}</strong> Suspicious</span>
                    <span>🟢 <strong style="color:#2ed573;">${data.safeCount || 0}</strong> Safe</span>
                </div>
                <div style="color:#aaa;">
                    ⚡ <strong>${cachedCount}/${total}</strong> IOCs từ Cache MongoDB (<24h) | Tỷ lệ trúng cache: <strong style="color:#2ed573;">${hitRate}</strong>
                </div>
            </div>

            ${iocCards}
        </div>
    `;
}

/**
 * Hiển thị kết quả Phân tích Header, Xác thực SPF/DKIM/DMARC, Tuổi Domain & Received Chain
 */
function renderAnalysis(a) {
    const riskLevel = a.risk_level || 'LOW';
    const riskScore = a.risk_score || 0;
    const auth = a.authentication || {};
    const domain = a.domain_analysis || {};
    const anomalies = a.anomalies || [];
    const headers = a.headers || {};
    const chain = headers.received_chain || [];

    // Phân cấp nhãn hiển thị trực quan và chuẩn xác
    let circleClass = 'CLEAN';
    let labelText = '🟢 AN TOÀN';

    if (riskScore >= 75 || riskLevel === 'HIGH') {
        circleClass = 'HIGH';
        labelText = '🔴 NGUY CƠ CAO';
    } else if (riskScore >= 25 || riskLevel === 'MEDIUM' || anomalies.some(an => an.severity === 'HIGH' || an.severity === 'CRITICAL')) {
        circleClass = 'MEDIUM';
        labelText = '🟡 CẦN KIỂM TRA (CÓ BẤT THƯỜNG)';
    } else if (riskScore > 0 || anomalies.length > 0 || riskLevel === 'LOW') {
        circleClass = 'LOW';
        labelText = '🟡 CẢNH BÁO RỦI RO THẤP';
    } else {
        circleClass = 'CLEAN';
        labelText = '🟢 AN TOÀN';
    }

    return `
        <div class="cards-grid">
            <!-- Risk Level Assessment -->
            <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
                <h3>⚡ Đánh Giá Kỹ Thuật Header</h3>
                <div style="text-align:center; padding:14px 10px; background:#0f1420; border-radius:8px; border:1px solid #ffffff0d; margin-top:6px;">
                    <div style="display:inline-flex; align-items:center; gap:6px; padding:6px 14px; border-radius:6px; font-size:13px; font-weight:bold; background:${labelText.includes('🔴') ? '#ff475722' : labelText.includes('🟡') ? '#ffa50222' : '#2ed57322'}; color:${labelText.includes('🔴') ? '#ff4757' : labelText.includes('🟡') ? '#ffa502' : '#2ed573'}; border:1px solid ${labelText.includes('🔴') ? '#ff475744' : labelText.includes('🟡') ? '#ffa50244' : '#2ed57344'}; margin-bottom:8px;">
                        <span>${labelText}</span>
                    </div>
                    <div style="font-size:11.5px; color:#aaa; line-height:1.4;">
                        ${anomalies.length > 0 ? `Phát hiện ${anomalies.length} bất thường cấu hình xác thực máy chủ gửi` : 'Toàn bộ cơ chế xác thực máy chủ gửi (SPF/DKIM/DMARC) đạt chuẩn'}
                    </div>
                </div>
            </div>

            <!-- Authentication -->
            <div class="card">
                <h3>🛡️ Xác thực Email</h3>
                <div class="auth-grid">
                    <div class="auth-badge ${auth.spf?.status || 'none'}">
                        <div class="protocol">SPF</div>
                        <div class="status">${(auth.spf?.status || 'N/A').toUpperCase()}</div>
                    </div>
                    <div class="auth-badge ${auth.dkim?.status || 'none'}">
                        <div class="protocol">DKIM</div>
                        <div class="status">${(auth.dkim?.status || 'N/A').toUpperCase()}</div>
                    </div>
                    <div class="auth-badge ${auth.dmarc?.status || 'none'}">
                        <div class="protocol">DMARC</div>
                        <div class="status" style="${auth.dmarc?.status === 'bestguesspass' ? 'font-size:12px;' : ''}">${auth.dmarc?.status === 'bestguesspass' ? 'BEST GUESS' : (auth.dmarc?.status || 'N/A').toUpperCase()}</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="cards-grid">
            <!-- Domain Analysis -->
            <div class="card">
                <h3>🌐 Phân tích Domain</h3>
                <div class="domain-info">
                    <div class="row"><span class="label">Domain</span><span class="value">${domain.sender_domain || 'N/A'}</span></div>
                    <div class="row"><span class="label">Tuổi domain</span><span class="value ${domain.is_suspicious ? 'suspicious' : ''}">${domain.domain_age_days != null ? domain.domain_age_days + ' ngày' : 'N/A'}</span></div>
                    <div class="row"><span class="label">Ngày đăng ký</span><span class="value">${domain.created_date || 'N/A'}</span></div>
                    <div class="row"><span class="label">Ngày hết hạn</span><span class="value">${domain.expiry_date || 'N/A'}</span></div>
                    <div class="row"><span class="label">Registrar</span><span class="value">${domain.registrar || 'N/A'}</span></div>
                    ${domain.error && domain.error.includes('No match') ? '<div class="row"><span class="label">Trạng thái</span><span class="value suspicious">⚠️ KHÔNG TỒN TẠI</span></div>' : ''}
                </div>
            </div>

            <!-- Anomalies -->
            <div class="card">
                <h3>⚠️ Bất thường (${anomalies.length})</h3>
                ${anomalies.length === 0 ? '<div style="color:#2ed573;text-align:center;padding:20px">✅ Không phát hiện bất thường</div>' : `
                    <ul class="anomaly-list">
                        ${anomalies.map(a => `
                            <li class="anomaly-item ${a.severity}">
                                <span class="icon">${a.severity === 'CRITICAL' ? '🚨' : a.severity === 'HIGH' ? '🔴' : '🟡'}</span>
                                <span><strong>${a.type}</strong><br>${a.detail}</span>
                            </li>
                        `).join('')}
                    </ul>
                `}
            </div>
        </div>

        <!-- Headers Detail -->
        <div class="card">
            <h3>📋 Chi tiết Header</h3>
            <div class="domain-info">
                <div class="row"><span class="label">From</span><span class="value">${escHtml(headers.from || 'N/A')}</span></div>
                <div class="row"><span class="label">Return-Path</span><span class="value">${escHtml(headers.return_path || 'N/A')}</span></div>
                <div class="row"><span class="label">Reply-To</span><span class="value">${escHtml(headers.reply_to || 'N/A')}</span></div>
                <div class="row"><span class="label">Message-ID</span><span class="value" style="font-size:11px">${escHtml(headers.message_id || 'N/A')}</span></div>
                <div class="row"><span class="label">Date</span><span class="value">${escHtml(headers.date || 'N/A')}</span></div>
                <div class="row"><span class="label">X-Mailer</span><span class="value">${escHtml(headers.x_mailer || 'N/A')}</span></div>
            </div>
        </div>
    `;
}

/**
 * Hiển thị khối Phản ứng (Response) Hộp thư Gmail & Ma Trận Đánh Giá SOAR Rule Engine
 */
function renderResponseSection(email) {
    if (!email) return '';
    const id = email._id;

    const hasAnyAnalysis = Boolean(email.headerAnalysis || email.contentAnalysis || email.urlAnalysis || email.attachmentAnalysis || email.iocAnalysis);
    if (!hasAnyAnalysis) {
        return `
            <div class="card" style="border: 1px dashed #747d8c88; background: #131826;">
                <!-- Header -->
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid #ffffff15; padding-bottom:12px; flex-wrap:wrap; gap:10px;">
                    <div>
                        <h3 style="color:#a4b0be; margin:0; font-size:15px; display:flex; align-items:center; gap:8px;">
                            <span>⚪</span> PHẢN ỨNG (RESPONSE) &amp; XUẤT BÁO CÁO SỰ CỐ SOC
                        </h3>
                        <div style="color:#888; font-size:11px; margin-top:2px;">Email này chưa được phân tích kỹ thuật. Hãy bấm các nút phân tích phía trên để bắt đầu điều tra.</div>
                    </div>
                </div>

                <!-- Unanalyzed Banner -->
                <div style="display:flex; justify-content:space-between; align-items:center; background:#0b0f19; padding:14px 18px; border-radius:8px; border:1px dashed #747d8c55;">
                    <div>
                        <div style="font-size:11px; text-transform:uppercase; color:#888; letter-spacing:0.5px; margin-bottom:4px;">Tổng hợp phân cấp Rule Engine (Verdict &amp; Risk Score)</div>
                        <div style="font-size:15px; font-weight:bold; color:#a4b0be; display:flex; align-items:center; gap:6px;">
                            <span>⚪</span> CHƯA XÁC ĐỊNH — CHỜ PHÂN TÍCH (CHƯA ĐÁNH GIÁ NGUY HIỂM / AN TOÀN)
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <span style="font-size:24px; font-weight:bold; color:#a4b0be;">—</span>
                        <span style="color:#666; font-size:12px;">/100</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Overall Risk synthesis
    const scores = [];
    if (typeof email.riskScore === 'number') scores.push(email.riskScore);
    if (typeof email.socialEngineeringScore === 'number') scores.push(email.socialEngineeringScore);
    if (email.urlAnalysis && typeof email.urlAnalysis.risk_score === 'number') scores.push(email.urlAnalysis.risk_score);
    if (email.attachmentAnalysis && typeof email.attachmentAnalysis.risk_score === 'number') scores.push(email.attachmentAnalysis.risk_score);
    if (email.iocAnalysis && typeof email.iocAnalysis.overallRiskScore === 'number') scores.push(email.iocAnalysis.overallRiskScore);

    const ruleEval = email.ruleEvaluation;
    const overallScore = ruleEval?.totalScore ?? (scores.length > 0 
        ? Math.round(Math.max(...scores) * 0.7 + (scores.reduce((a, b) => a + b, 0) / scores.length) * 0.3)
        : (email.riskScore || 0));

    const overallLevel = ruleEval?.verdict ?? (overallScore >= 75 ? 'MALICIOUS' : overallScore >= 50 ? 'SUSPICIOUS' : 'CLEAN');
    const statusColor = riskColor(overallLevel);

    return `
        <div class="card" style="border: 1px solid #eb3b5a66; background: #131826;">
            <!-- Header -->
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid #ffffff15; padding-bottom:12px; flex-wrap:wrap; gap:10px;">
                <div>
                    <h3 style="color:#fc5c65; margin:0; font-size:15px; display:flex; align-items:center; gap:8px;">
                        <span>🚨</span> PHẢN ỨNG (RESPONSE) & XUẤT BÁO CÁO SỰ CỐ SOC
                    </h3>
                    <div style="color:#888; font-size:11px; margin-top:2px;">Tự động hóa Xử lý Hộp thư Gmail (Vứt vào Spam / Xóa Thư) &amp; Xuất Báo Cáo Chuẩn</div>
                </div>
                <div style="display:flex; gap:8px;">
                    <button onclick="openReportPDF('${id}')" style="background:#2ed57322; border:1px solid #2ed573; color:#2ed573; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:bold; display:inline-flex; align-items:center; gap:6px;">
                        📄 Mở / In Báo Cáo PDF
                    </button>
                </div>
            </div>

            <!-- Overall Risk Assessment Banner -->
            <div style="display:flex; justify-content:space-between; align-items:center; background:#0b0f19; padding:12px 16px; border-radius:8px; margin-bottom:16px; border:1px solid ${statusColor}33;">
                <div>
                    <div style="font-size:11px; text-transform:uppercase; color:#888; letter-spacing:0.5px; margin-bottom:2px;">Tổng hợp phân cấp Rule Engine (Verdict & Risk Score)</div>
                    <div style="font-size:15px; font-weight:bold; color:${statusColor};">
                        ${overallLevel === 'MALICIOUS' ? '🔴 NGUY HIỂM (MALICIOUS) — XÓA KHỎI HỘP THƯ ĐẾN' : overallLevel === 'SUSPICIOUS' ? '🟡 ĐÁNG NGỜ (SUSPICIOUS) — VỨT VÀO THƯ MỤC SPAM' : overallLevel === 'LOW' ? '🟡 RỦI RO THẤP (LOW RISK) — GIỮ TRONG INBOX' : '🟢 AN TOÀN (CLEAN) — GIỮ TRONG INBOX'}
                    </div>
                </div>
                <div style="text-align:right;">
                    <span style="font-size:24px; font-weight:bold; color:${statusColor};">${overallScore}</span>
                    <span style="color:#888; font-size:12px;">/100</span>
                </div>
            </div>

            ${ruleEval ? `
            <!-- Rule Engine Matrix Card -->
            <div style="background:#0f1422; border-radius:8px; padding:14px 16px; margin-bottom:16px; border:1px solid #ffffff15; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom: 1px solid #ffffff10; padding-bottom: 8px;">
                    <div style="font-size:12px; font-weight:bold; color:#00d4ff; text-transform:uppercase; display:flex; align-items:center; gap:6px;">
                        <span>⚙️</span> MA TRẬN QUY TẮC ĐÁNH GIÁ (SOAR RULE ENGINE)
                    </div>
                    <span style="font-size:11px; padding:3px 10px; border-radius:12px; font-weight:bold; background:${statusColor}22; color:${statusColor}; border:1px solid ${statusColor}44;">
                        ${ruleEval.verdict} (${ruleEval.totalScore}/100đ)
                    </span>
                </div>

                <div style="font-size:11px; color:#aaa; margin-bottom:12px;">
                    <div style="margin-bottom:6px; font-weight:bold; color:#888; text-transform:uppercase; font-size:10px; letter-spacing:0.5px;">HÀNH ĐỘNG QUY ĐỊNH (SOAR PLAYBOOK):</div>
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        ${(ruleEval.actionNameVi || '').split(' | ').map(act => {
                            const isTrash = act.includes('Xóa') || act.includes('Thùng rác');
                            const isSpam = act.includes('Spam') || act.includes('Vứt');
                            const isAllow = act.includes('Tin Cậy') || act.includes('Allowlist');
                            const borderCol = isTrash ? '#ff4757' : isSpam ? '#ffa502' : isAllow ? '#5352ed' : '#2bcbba';
                            const bgCol = isTrash ? '#ff475715' : isSpam ? '#ffa50215' : isAllow ? '#5352ed15' : '#2bcbba15';
                            const icon = isTrash ? '🗑️' : isSpam ? '📦' : isAllow ? '🛡️' : '⚡';
                            return `
                                <div style="background:${bgCol}; padding:7px 12px; border-radius:6px; border-left:3px solid ${borderCol}; color:${borderCol}; font-size:11px; font-weight:500; display:flex; align-items:center; gap:8px;">
                                    <span>${icon}</span> <span>${escHtml(act)}</span>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>



                <!-- 6 Modules Capped Grid -->
                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px; margin-bottom:10px;">
                    ${[
                        { key: 'header', label: 'Header Auth', max: 30, icon: '🛡️' },
                        { key: 'domainAge', label: 'Domain & Typosquat', max: 60, icon: '🌐' },
                        { key: 'llm', label: 'AI LLM', max: 50, icon: '🧠' },
                        { key: 'url', label: 'URL Scanner', max: 50, icon: '🔗' },
                        { key: 'attachment', label: 'Tệp đính kèm', max: 50, icon: '📎' },
                        { key: 'ioc', label: 'Threat Intel', max: 50, icon: '📡' },
                    ].map(mod => {
                        const score = ruleEval.moduleScores?.[mod.key] || 0;
                        const pct = Math.min(100, Math.round((score / mod.max) * 100));
                        const hasScore = score > 0;
                        const barColor = score >= mod.max * 0.7 ? '#ff4757' : score >= mod.max * 0.4 ? '#ffa502' : '#2ed573';
                        const scoreColor = hasScore ? (score >= mod.max * 0.7 ? '#ff6b81' : '#ffa502') : '#ffffff';
                        const borderStyle = hasScore ? `1px solid ${barColor}44` : '1px solid #ffffff0d';
                        const bgStyle = hasScore ? `${barColor}0a` : '#161d2d';

                        return `
                            <div style="background:${bgStyle}; border:${borderStyle}; padding:8px 10px; border-radius:6px; display:flex; flex-direction:column; justify-content:space-between;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                                    <span style="color:#aaa; font-size:11px; display:flex; align-items:center; gap:4px;">
                                        <span>${mod.icon}</span> <span>${mod.label}</span>
                                    </span>
                                    <span style="font-size:12px;">
                                        <strong style="color:${scoreColor}; font-size:13px;">${score}</strong><span style="color:#666; font-size:10px;">/${mod.max}đ</span>
                                    </span>
                                </div>
                                <div style="height:3px; background:#1e293b; border-radius:2px; overflow:hidden;">
                                    <div style="width:${pct}%; height:100%; background:${barColor}; border-radius:2px; transition:width 0.3s ease;"></div>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>

                ${ruleEval.isHardRule ? `
                    <div style="background:#ff475722; color:#ff4757; border:1px solid #ff475744; padding:8px 12px; border-radius:6px; font-size:11px; font-weight:bold; margin-top:6px;">
                        🚨 KÍCH HOẠT HARD RULE (100đ): ${escHtml(ruleEval.hardRuleHits?.join('; ') || '')}
                    </div>
                ` : ''}

                ${ruleEval.correlationBonuses && ruleEval.correlationBonuses.length > 0 ? `
                    <div style="background:#0f1420; border:1px solid #ffffff15; padding:10px 12px; border-radius:6px; font-size:11px; margin-top:8px;">
                        <div style="color:#00d4ff; font-weight:bold; margin-bottom:6px; display:flex; align-items:center; gap:6px;">
                            <span>🔗</span> QUY TẮC TƯƠNG QUAN PHÁT HIỆN:
                        </div>
                        <div style="display:flex; flex-direction:column; gap:4px;">
                            ${ruleEval.correlationBonuses.map(b => `<div style="font-size:11px; color:#bbb; display:flex; align-items:flex-start; gap:6px;"><span>•</span> <span>${escHtml(b.rule || b)}</span></div>`).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
            ` : ''}
        </div>
    `;
}
