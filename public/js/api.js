/**
 * Mini SOAR - Dashboard API Client & Network Requests
 * Xử lý toàn bộ các lệnh gọi API gửi lên Server backend
 */

const API = window.location.origin + '/api';

/**
 * Tải danh sách email từ Inbox API
 */
async function loadEmails() {
    try {
        const res = await fetch(`${API}/inbox?limit=50`);
        const data = await res.json();
        emails = data.data.emails;
        renderList();
        updateStats();
    } catch (err) {
        document.getElementById('email-list-body').innerHTML =
            '<div class="loading">❌ Không kết nối được server<br><small>Chạy <code>npm start</code> trước</small></div>';
    }
}

/**
 * Kích hoạt quét và thu thập email thủ công từ IMAP
 */
async function collectEmails() {
    const btn = document.getElementById('btn-collect');
    btn.disabled = true;
    btn.textContent = 'Đang thu...';
    try {
        const res = await fetch(`${API}/inbox/collect`, { method: 'POST' });
        const data = await res.json();
        await loadEmails();
        btn.textContent = `✅ +${(data.data?.collected || []).length}`;
        setTimeout(() => { btn.textContent = 'Thu thập'; btn.disabled = false; }, 2000);
    } catch (err) {
        btn.textContent = '❌ Lỗi';
        setTimeout(() => { btn.textContent = 'Thu thập'; btn.disabled = false; }, 2000);
    }
}

/**
 * Đồng bộ kết quả đánh giá Rule Engine & cập nhật toàn bộ Dashboard tức thì
 */
function syncEvaluationAndUI(id, data) {
    const idx = emails.findIndex(e => e._id === id);
    if (idx >= 0 && data) {
        if (data.ruleEvaluation) {
            emails[idx].ruleEvaluation = data.ruleEvaluation;
            emails[idx].overallRiskScore = data.overallRiskScore ?? data.ruleEvaluation.totalScore;
            emails[idx].riskLevel = data.riskLevel ?? data.ruleEvaluation.verdict;
            emails[idx].riskScore = emails[idx].overallRiskScore;
            emails[idx].responseActions = data.responseActions || data.ruleEvaluation.playbookActions || [];
        }
        if (selectedId === id) {
            const respSection = document.getElementById('response-reporting-section');
            if (respSection) {
                respSection.innerHTML = renderResponseSection(emails[idx]);
            }
        }
        renderList();
        updateStats();
    }
}

/**
 * Phân tích Header: SPF, DKIM, DMARC, Domain Age, Received Chain
 */
async function analyzeHeader(id) {
    const section = document.getElementById('analysis-section');
    section.innerHTML = '<div class="loading"><div class="spinner"></div><p>Đang phân tích header... (tra cứu WHOIS có thể mất vài giây)</p></div>';

    try {
        const res = await fetch(`${API}/analyze/header`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emailId: id })
        });
        const data = await res.json();

        if (data.status === 'success') {
            section.innerHTML = renderAnalysis(data.data);
            const idx = emails.findIndex(e => e._id === id);
            if (idx >= 0) {
                emails[idx].headerAnalysis = data.data;
            }
            syncEvaluationAndUI(id, data);
        } else {
            section.innerHTML = `<div class="no-analysis">❌ Lỗi: ${data.error}</div>`;
        }
    } catch (err) {
        section.innerHTML = `<div class="no-analysis">❌ Lỗi kết nối: ${err.message}</div>`;
    }
}

/**
 * Phân tích Social Engineering & Nội dung bằng AI Ollama (Qwen 2.5 Local)
 */
async function analyzeContent(id) {
    const section = document.getElementById('ai-content-section');
    section.innerHTML = '<div class="loading"><div class="spinner" style="border-top-color:#a55eea;"></div><p style="color:#d1d8e0;">🧠 Đang kích hoạt AI (Qwen 2.5:3b Local) để bóc tách nội dung & chấm điểm Social Engineering...</p></div>';

    try {
        const res = await fetch(`${API}/analyze/content`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emailId: id })
        });
        const data = await res.json();

        if (data.status === 'success') {
            section.innerHTML = renderContentAnalysis(data.data);
            const idx = emails.findIndex(e => e._id === id);
            if (idx >= 0) {
                emails[idx].contentAnalysis = data.data;
                emails[idx].socialEngineeringScore = data.data.ai_analysis?.data?.social_engineering_score;
                emails[idx].contentVerdict = data.data.ai_analysis?.data?.verdict;
            }
            syncEvaluationAndUI(id, data);
        } else {
            section.innerHTML = `<div class="card" style="border-left: 3px solid #ff4757; color: #ff6b6b;">❌ Lỗi AI: ${data.error}</div>`;
        }
    } catch (err) {
        section.innerHTML = `<div class="card" style="border-left: 3px solid #ff4757; color: #ff6b6b;">❌ Lỗi kết nối: ${err.message}</div>`;
    }
}

/**
 * Phân tích URL Scanner & Redirect Chain
 */
async function analyzeUrls(id) {
    const section = document.getElementById('url-analysis-section');
    section.innerHTML = '<div class="loading"><div class="spinner" style="border-top-color:#ff6347;"></div><p style="color:#ff9f7f;">🔗 Đang truy vết URL & Redirect Chain... (tuyệt đối không click trực tiếp)</p></div>';

    try {
        const res = await fetch(`${API}/analyze/urls`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emailId: id })
        });
        const data = await res.json();

        if (data.status === 'success') {
            section.innerHTML = renderUrlAnalysis(data.data);
            const idx = emails.findIndex(e => e._id === id);
            if (idx >= 0) emails[idx].urlAnalysis = data.data;
            syncEvaluationAndUI(id, data);
        } else {
            section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi URL scanner: ${data.error}</div>`;
        }
    } catch (err) {
        section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi: ${err.message}</div>`;
    }
}

/**
 * Phân tích File đính kèm & Cloud Sandbox
 */
async function analyzeAttachments(id) {
    const section = document.getElementById('attachment-analysis-section');
    section.innerHTML = '<div class="loading"><div class="spinner" style="border-top-color:#2bcbba;"></div><p style="color:#2bcbba;">📎 Đang giải mã Base64, bóc tách file đính kèm, tính MD5/SHA256 & tra cứu Cloud Sandbox...</p></div>';

    try {
        const res = await fetch(`${API}/analyze/attachments`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emailId: id })
        });
        const data = await res.json();

        if (data.status === 'success') {
            section.innerHTML = renderAttachmentAnalysis(data.data);
            const idx = emails.findIndex(e => e._id === id);
            if (idx >= 0) emails[idx].attachmentAnalysis = data.data;
            syncEvaluationAndUI(id, data);
        } else {
            section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi phân tích file đính kèm: ${data.error}</div>`;
        }
    } catch (err) {
        section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi: ${err.message}</div>`;
    }
}

/**
 * Làm rõ IOC bằng Threat Intelligence đa nguồn (AbuseIPDB, VirusTotal, PhishTank, URLhaus)
 */
async function analyzeIOC(id) {
    const section = document.getElementById('ioc-analysis-section');
    section.innerHTML = '<div class="loading"><div class="spinner" style="border-top-color:#45aaf2;"></div><p style="color:#45aaf2;">🌐 Đang kiểm tra Cache MongoDB (<24h) & truy vấn Threat Intelligence (AbuseIPDB, VirusTotal, URLhaus)...</p></div>';

    try {
        const res = await fetch(`${API}/analyze/ioc`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ emailId: id })
        });
        const data = await res.json();

        if (data.status === 'success') {
            section.innerHTML = renderIOCAnalysis(data.data);
            const idx = emails.findIndex(e => e._id === id);
            if (idx >= 0) emails[idx].iocAnalysis = data.data;
            syncEvaluationAndUI(id, data);
        } else {
            section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi làm rõ IOC: ${data.error}</div>`;
        }
    } catch (err) {
        section.innerHTML = `<div class="card" style="border-left:3px solid #ff4757; color:#ff6b6b;">❌ Lỗi: ${err.message}</div>`;
    }
}

/**
 * Xác minh tính toàn vẹn mã băm SHA-256 của file .eml gốc
 */
async function verifyHash(id) {
    const container = document.getElementById(`verify-result-${id}`);
    if (!container) return;
    container.innerHTML = '<div style="color:#888;font-size:12px;margin-top:8px">Đang xác minh...</div>';

    try {
        const res = await fetch(`${API}/inbox/${id}/verify`);
        const data = await res.json();
        const d = data.data;
        container.innerHTML = `
            <div class="verify-result ${d.integrity}">
                ${d.integrity === 'INTACT' ? '✅ INTACT — File chưa bị chỉnh sửa' : '❌ TAMPERED — File đã bị thay đổi!'}
            </div>
        `;
    } catch (err) {
        container.innerHTML = '<div class="verify-result TAMPERED">❌ Lỗi xác minh</div>';
    }
}
