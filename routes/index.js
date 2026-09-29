const express = require('express');
const router = express.Router();
const emailRoutes = require('./emailRoutes');
const inboxRoutes = require('./inboxRoutes');

// Định tuyến API cho hệ thống SOAR
router.use('/inbox', inboxRoutes);
router.use('/', emailRoutes);

module.exports = router;
