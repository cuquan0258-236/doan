/**
 * Mini SOAR - Dashboard Application Controller (State & Event Handlers)
 * Quản lý trạng thái và tương tác người dùng trên giao diện
 */

// State toàn cục
var emails = [];
var selectedId = null;

/**
 * Chọn xem chi tiết một email
 * @param {string} id ID của email record
 */
async function selectEmail(id) {
    selectedId = id;
    renderList();
    const email = emails.find(e => e._id === id);
    const panel = document.getElementById('detail-panel');
    if (!email || !panel) return;

    panel.innerHTML = `
        <div class="detail-header">
            <h2>${decodeSubject(email.subject)}</h2>
            <div class="detail-meta">
                <span>👤 ${escHtml(email.sender)}</span>
                <span>📩 ${escHtml(email.recipient)}</span>
                <span>📅 ${new Date(email.collectedAt).toLocaleString('vi-VN')}</span>
            </div>
        </div>
        <div class="actions-bar">
            <button class="btn-analyze" onclick="analyzeHeader('${id}')">🔍 Phân tích Header</button>
            <button class="btn-analyze" style="background: linear-gradient(135deg, #a55eea33, #8854d033); border-color: #a55eea88; color: #d1d8e0;" onclick="analyzeContent('${id}')">🧠 Phân tích AI</button>
            <button class="btn-analyze" style="background: linear-gradient(135deg, #e6770033, #ff634733); border-color: #ff634788; color: #ff9f7f;" onclick="analyzeUrls('${id}')">🔗 Truy vết URL</button>
            <button class="btn-analyze" style="background: linear-gradient(135deg, #20bf6b33, #0fb9b133); border-color: #20bf6b88; color: #2bcbba;" onclick="analyzeAttachments('${id}')">📎 Phân tích Attachment</button>
            <button class="btn-analyze" style="background: linear-gradient(135deg, #3867d633, #4b7bec33); border-color: #4b7bec88; color: #45aaf2;" onclick="analyzeIOC('${id}')">🌐 Làm rõ IOC (Threat Intel)</button>
            <button class="btn-verify" onclick="verifyHash('${id}')">🔒 Xác minh SHA-256</button>
        </div>
        <!-- Step 8: Response & Reporting Section -->
        <div id="response-reporting-section" style="margin-bottom: 20px;">
            ${renderResponseSection(email)}
        </div>
        <div class="card" style="margin-bottom:16px">
            <h3>🔐 SHA-256 Hash</h3>
            <div class="hash-display">${email.sha256Hash}</div>
            <div id="verify-result-${id}"></div>
        </div>
        <!-- AI Content Analysis Section -->
        <div id="ai-content-section" style="margin-bottom: 20px;">
            ${email.contentAnalysis ? renderContentAnalysis(email.contentAnalysis) : `
                <div class="card" style="border: 1px dashed #a55eea66; text-align: center; padding: 20px;">
                    <div style="font-size: 24px; margin-bottom: 6px;">🧠 Phân tích Social Engineering bằng AI (Qwen 2.5 Local)</div>
                    <p style="color: #888; font-size: 13px; margin-bottom: 12px;">Bóc tách nội dung HTML và nhờ AI phân tích mức độ thao túng tâm lý, đe dọa, lừa đảo.</p>
                    <button class="btn-analyze" style="background: #a55eea33; border-color: #a55eea; color: #fff;" onclick="analyzeContent('${id}')">⚡ Bắt đầu phân tích AI</button>
                </div>
            `}
        </div>
        <!-- URL Analysis Section -->
        <div id="url-analysis-section" style="margin-bottom: 20px;">
            ${email.urlAnalysis ? renderUrlAnalysis(email.urlAnalysis) : ''}
        </div>
        <!-- Attachment Analysis Section -->
        <div id="attachment-analysis-section" style="margin-bottom: 20px;">
            ${email.attachmentAnalysis ? renderAttachmentAnalysis(email.attachmentAnalysis) : ''}
        </div>
        <!-- IOC Threat Intelligence Section (Step 6) -->
        <div id="ioc-analysis-section" style="margin-bottom: 20px;">
            ${email.iocAnalysis ? renderIOCAnalysis(email.iocAnalysis) : ''}
        </div>
        <!-- Header Analysis Section -->
        <div id="analysis-section">
            ${(email.headerAnalysis && email.headerAnalysis.authentication) ? renderAnalysis(email.headerAnalysis) : `
                <div class="no-analysis">
                    <p>Chưa phân tích header. Nhấn <strong>🔍 Phân tích Header</strong> để bắt đầu.</p>
                </div>
            `}
        </div>
    `;
}

// Khởi tạo Dashboard khi nạp trang
document.addEventListener('DOMContentLoaded', () => {
    loadEmails();
    // Tự động kiểm tra cập nhật email mỗi 30 giây
    setInterval(loadEmails, 30000);
});
