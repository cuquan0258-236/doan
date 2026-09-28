require('dotenv').config();
const express = require('express');
const cron = require('node-cron');
const path = require('path');
const app = express();

const { connectDB } = require('./config/db');
const emailController = require('./controllers/emailController');
const inboxController = require('./controllers/inboxController');
const { runCollector } = require('./workers/emailWorker');

app.use(express.json());

// Serve Dashboard UI
app.use(express.static(path.join(__dirname, 'public')));

// ========================
// API Routes
// ========================

// Endpoint phân tích email (tương thích ngược + hỗ trợ emailId từ DB)
app.post('/api/analyze', emailController.analyzeEmail);

// Endpoint phân tích header: SPF, DKIM, DMARC, Domain Age
app.post('/api/analyze/header', emailController.analyzeHeader);

// Endpoint phân tích nội dung & Social Engineering AI (Ollama Local)
app.post('/api/analyze/content', emailController.analyzeContent);

// Endpoint truy vết URL & Redirect Chain
app.post('/api/analyze/urls', emailController.analyzeUrls);

// Endpoint phân tích file đính kèm & Cloud Sandbox
app.post('/api/analyze/attachments', emailController.analyzeAttachments);

// Endpoint làm rõ IOC bằng Threat Intelligence đa nguồn (Cache 24h)
app.post('/api/analyze/ioc', emailController.analyzeIOC);

// Inbox API — Quản lý email đã thu thập
app.get('/api/inbox', inboxController.listEmails);
app.get('/api/inbox/:id', inboxController.getEmailDetail);
app.post('/api/inbox/collect', inboxController.triggerCollect);
app.get('/api/inbox/:id/verify', inboxController.verifyIntegrity);

// Bước 8: Phản ứng (Response) & Xuất Báo Cáo
app.post('/api/response/block', emailController.executeBlockResponse);
app.get('/api/reports/:id/html', emailController.exportReportHTML);

// ========================
// Khởi động Server
// ========================

const PORT = process.env.PORT || 3000;
const POLL_INTERVAL = process.env.IMAP_POLL_INTERVAL || 60;

async function startServer() {
    // Kết nối MongoDB
    await connectDB();

    // Lập lịch Worker thu thập email tự động
    // Chạy mỗi POLL_INTERVAL giây (chuyển sang cron expression phút)
    const cronMinutes = Math.max(1, Math.ceil(POLL_INTERVAL / 60));
    const cronExpression = `*/${cronMinutes} * * * *`;

    cron.schedule(cronExpression, async () => {
        console.log(`[SOAR Cron] Bắt đầu quét hòm thư (mỗi ${cronMinutes} phút)...`);
        try {
            const result = await runCollector('imap');
            const count = (result.collected || []).length;
            if (count > 0) {
                console.log(`[SOAR Cron] Thu thập được ${count} email mới`);
            } else {
                console.log('[SOAR Cron] Không có email mới');
            }
        } catch (error) {
            console.error(`[SOAR Cron] Lỗi: ${error.error || error.message}`);
        }
    });

    console.log(`[SOAR Cron] Đã lập lịch quét hòm thư: ${cronExpression}`);

    app.listen(PORT, () => {
        console.log(`[SOAR] Hệ thống đang chạy tại http://localhost:${PORT}`);
        console.log(`[SOAR] API Endpoints:`);
        console.log(`  POST /api/analyze          - Phân tích email (URL extraction)`);
        console.log(`  POST /api/analyze/header    - Phân tích header (SPF/DKIM/DMARC/Domain Age)`);
        console.log(`  POST /api/analyze/content   - Phân tích nội dung & Social Engineering (AI Ollama)`);
        console.log(`  POST /api/analyze/urls      - Truy vết URL & Redirect Chain`);
        console.log(`  POST /api/analyze/attachments - Phân tích file đính kèm & Cloud Sandbox`);
        console.log(`  POST /api/analyze/ioc       - Làm rõ IOC bằng Threat Intelligence (Cache 24h)`);
        console.log(`  POST /api/response/block   - Phản ứng & Chặn IOC (pfSense / Wazuh / Host)`);
        console.log(`  GET  /api/reports/:id/html - Báo cáo sự cố SOC chuẩn in PDF A4`);
        console.log(`  GET  /api/inbox            - Liệt kê email đã thu thập`);
        console.log(`  GET  /api/inbox/:id        - Chi tiết email record`);
        console.log(`  POST /api/inbox/collect     - Trigger thu thập thủ công`);
        console.log(`  GET  /api/inbox/:id/verify  - Xác minh SHA-256`);
    });
}

startServer().catch(err => {
    console.error('[SOAR] Lỗi khởi động:', err);
    process.exit(1);
});