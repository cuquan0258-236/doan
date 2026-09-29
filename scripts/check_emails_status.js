const mongoose = require('mongoose');

async function check() {
    await mongoose.connect('mongodb://localhost:27017/mini_soar');
    const docs = await mongoose.connection.collection('emailrecords').find({}).toArray();
    console.log(`Total: ${docs.length}`);
    docs.forEach((d, idx) => {
        const hasHeader = !!d.headerAnalysis;
        const hasContent = !!d.contentAnalysis;
        const hasUrl = !!d.urlAnalysis;
        const hasAtt = !!d.attachmentAnalysis;
        const hasIoc = !!d.iocAnalysis;
        const anyAnalysis = hasHeader || hasContent || hasUrl || hasAtt || hasIoc;
        console.log(`[${idx + 1}] ID: ${d._id} | Sender: ${d.sender} | Recipient: ${d.recipient}`);
        console.log(`    Status: ${d.status} | RiskLevel: ${d.riskLevel} | RiskScore: ${d.riskScore} | AnyAnalysis: ${anyAnalysis} (H:${hasHeader}, C:${hasContent}, U:${hasUrl}, A:${hasAtt}, I:${hasIoc})`);
    });
    process.exit(0);
}

check().catch(console.error);
