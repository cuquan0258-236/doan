const express = require('express');
const router = express.Router();
const emailController = require('../controllers/emailController');

// Phân tích Email & Các thành phần chuyên sâu
router.post('/analyze', emailController.analyzeEmail);
router.post('/analyze/header', emailController.analyzeHeader);
router.post('/analyze/content', emailController.analyzeContent);
router.post('/analyze/urls', emailController.analyzeUrls);
router.post('/analyze/attachments', emailController.analyzeAttachments);
router.post('/analyze/ioc', emailController.analyzeIOC);

// Phản ứng ngăn chặn & Xuất báo cáo sự cố SOC
router.post('/response/block', emailController.executeBlockResponse);
router.get('/reports/:id/html', emailController.exportReportHTML);

module.exports = router;
