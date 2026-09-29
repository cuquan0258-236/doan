const express = require('express');
const router = express.Router();
const inboxController = require('../controllers/inboxController');

// Quản lý và duyệt email trong hòm thư
router.get('/', inboxController.listEmails);
router.get('/:id', inboxController.getEmailDetail);
router.post('/collect', inboxController.triggerCollect);
router.get('/:id/verify', inboxController.verifyIntegrity);

module.exports = router;
