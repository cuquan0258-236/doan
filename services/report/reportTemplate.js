/**
 * Mini SOAR - Incident Report HTML Template Generator (Mẫu Báo Cáo Sự Cố SOC)
 * Tạo chuỗi HTML hoàn chỉnh, chuẩn in ấn A4 (PDF) cho Báo cáo Sự cố An ninh
 */

function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Render toàn bộ trang HTML Báo cáo Sự cố SOC
 * @param {Object} data Dữ liệu sự cố tổng hợp từ buildIncidentData
 * @returns {string} Mã HTML hoàn chỉnh
 */
function renderReportHtml(data) {
    const isMalicious = data.riskAssessment.verdict === 'MALICIOUS' || data.riskAssessment.severity === 'MALICIOUS' || data.riskAssessment.severity === 'CRITICAL' || data.riskAssessment.overallScore >= 75;
    const isSuspicious = data.riskAssessment.verdict === 'SUSPICIOUS' || data.riskAssessment.severity === 'SUSPICIOUS' || data.riskAssessment.severity === 'HIGH' || (data.riskAssessment.overallScore >= 50 && data.riskAssessment.overallScore < 75);
    const isLowRisk = data.riskAssessment.verdict === 'LOW' || data.riskAssessment.severity === 'LOW' || data.riskAssessment.severity === 'MEDIUM' || (data.riskAssessment.overallScore >= 25 && data.riskAssessment.overallScore < 50);

    const severityColor = isMalicious ? '#eb3b5a'    // Đỏ nếu là nguy hiểm (MALICIOUS >= 75đ hoặc Hard Rule)
        : isSuspicious ? '#fa8231'                  // Vàng cam nếu là đáng ngờ (SUSPICIOUS 50-74đ)
        : isLowRisk ? '#f7b731'                     // Vàng nếu rủi ro thấp (LOW 25-49đ)
        : '#20bf6b';                                // Xanh lá nếu an toàn (CLEAN / SAFE < 25đ)

    const threatColor = data.threatClassification.id === 'BENIGN_CLEAN' ? '#20bf6b'
        : (data.threatClassification.severity === 'CRITICAL' || isMalicious) ? '#eb3b5a'
        : (data.threatClassification.severity === 'HIGH' || isSuspicious) ? '#fa8231'
        : (data.threatClassification.severity === 'MEDIUM') ? '#f7b731' : '#20bf6b';

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

    return `<!DOCTYPE html>
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
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; gap: 16px; border-bottom: 1px solid #f1f2f6; padding-bottom: 12px;">
                <div style="flex: 1; min-width: 0;">
                    <div style="font-size: 11px; text-transform: uppercase; color: #7f8fa6; font-weight: bold; letter-spacing: 0.5px;">Loại hình chiến dịch tấn công xác định (Classified Attack Type)</div>
                    <div style="font-size: 17px; font-weight: bold; color: ${threatColor}; margin-top: 3px; display: flex; align-items: center; gap: 8px;">
                        <span>${data.threatClassification.icon}</span> ${data.threatClassification.nameVi}
                    </div>
                </div>
                <div style="text-align: right; flex-shrink: 0;">
                    <div style="font-size: 11px; text-transform: uppercase; color: #7f8fa6; font-weight: bold; margin-bottom: 3px;">Ánh xạ Kỹ thuật MITRE ATT&CK&reg;</div>
                    <div>
                        <span class="badge" style="background: ${data.threatClassification.id === 'BENIGN_CLEAN' ? '#e8f5e9' : '#2f3542'}; color: ${data.threatClassification.id === 'BENIGN_CLEAN' ? '#2e7d32' : '#00d2d3'}; font-size: 11px; font-family: monospace; white-space: nowrap; padding: 4px 10px; border-radius: 4px; border: 1px solid ${data.threatClassification.id === 'BENIGN_CLEAN' ? '#c8e6c9' : '#2f3542'};">
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
</html>`;
}

module.exports = {
    renderReportHtml,
    escapeHtml
};
