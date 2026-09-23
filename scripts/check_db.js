require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { connectDB } = require('../config/db');
const EmailRecord = require('../models/EmailRecord');

async function checkDB() {
    await connectDB();
    const records = await EmailRecord.find().sort({ collectedAt: -1 }).lean();
    
    console.log('\n======================================');
    console.log('  TONG SO EMAIL DA THU THAP: ' + records.length);
    console.log('======================================\n');
    
    records.forEach((r, i) => {
        console.log('[' + (i + 1) + '] ' + (r.subject || 'No Subject'));
        console.log('    Sender:   ' + r.sender);
        console.log('    To:       ' + r.recipient);
        console.log('    SHA-256:  ' + r.sha256Hash);
        console.log('    File:     ' + r.emlFilePath + ' (' + r.fileSize + ' bytes)');
        console.log('    Status:   ' + r.status);
        console.log('    Auth:     ' + (r.authResults || 'N/A').substring(0, 80));
        console.log('    Thu thap: ' + r.collectedAt);
        console.log('');
    });
    
    process.exit(0);
}

checkDB();
