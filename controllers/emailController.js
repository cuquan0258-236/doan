const { exec } = require('child_process');
const path = require('path');
const EmailRecord = require('../models/EmailRecord');

/**
 * POST /api/analyze
 * Phân tích email từ DB (theo emailId) hoặc file cứng (fallback)
 */
exports.analyzeEmail = async (req, res) => {
    const { emailId } = req.body;
    let emlFilePath;

    try {
        if (emailId) {
            // Truy vấn MongoDB lấy đường dẫn file
            const record = await EmailRecord.findById(emailId);
            if (!record) {
                return res.status(404).json({ error: 'Không tìm thấy email record trong DB' });
            }
            emlFilePath = record.emlFilePath;

            // Cập nhật trạng thái sang "analyzing"
            record.status = 'analyzing';
            await record.save();
        } else {
            // Fallback: dùng sample.eml (tương thích ngược)
            emlFilePath = path.join(__dirname, '../uploads/sample.eml');
        }

        const pythonScriptPath = path.join(__dirname, '../scripts/eml_parser.py');

        console.log(`[SOAR] Bắt đầu kích hoạt luồng bóc tách Python cho: ${emlFilePath}`);

        exec(`python "${pythonScriptPath}" "${emlFilePath}"`, async (error, stdout, stderr) => {
            if (error) {
                console.error(`Lỗi thực thi: ${stderr}`);

                // Cập nhật trạng thái lỗi nếu có emailId
                if (emailId) {
                    await EmailRecord.findByIdAndUpdate(emailId, { status: 'error' });
                }

                return res.status(500).json({ error: "Lỗi khi chạy Python", details: stderr });
            }

            try {
                const extractedData = JSON.parse(stdout);
                console.log(`[SOAR] Đã cào được ${extractedData.extracted_urls.length} URLs từ email.`);

                // Cập nhật trạng thái "analyzed" nếu có emailId
                if (emailId) {
                    await EmailRecord.findByIdAndUpdate(emailId, { status: 'analyzed' });
                }

                // Trả kết quả về client
                return res.status(200).json({
                    status: "success",
                    message: "Phân tích hoàn tất",
                    emailId: emailId || null,
                    data: extractedData
                });
            } catch (parseError) {
                return res.status(500).json({ error: "Lỗi Parse JSON từ Python" });
            }
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi analyzeEmail: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống', details: error.message });
    }
};

/**
 * POST /api/analyze/header
 * Phân tích header email: SPF, DKIM, DMARC, Domain Age, Risk Score
 */
exports.analyzeHeader = async (req, res) => {
    const { emailId } = req.body;
    let emlFilePath;

    try {
        if (emailId) {
            const record = await EmailRecord.findById(emailId);
            if (!record) {
                return res.status(404).json({ error: 'Không tìm thấy email record trong DB' });
            }
            emlFilePath = record.emlFilePath;
        } else {
            emlFilePath = path.join(__dirname, '../uploads/sample.eml');
        }

        const pythonScriptPath = path.join(__dirname, '../scripts/header_analyzer.py');

        console.log(`[SOAR] Bắt đầu phân tích header: ${emlFilePath}`);

        exec(`python "${pythonScriptPath}" "${emlFilePath}"`, { maxBuffer: 1024 * 1024 * 5 }, async (error, stdout, stderr) => {
            if (error) {
                console.error(`[SOAR] Lỗi phân tích header: ${stderr}`);
                return res.status(500).json({ error: 'Lỗi khi chạy header analyzer', details: stderr });
            }

            try {
                const analysisResult = JSON.parse(stdout);

                if (analysisResult.error) {
                    return res.status(500).json({ error: analysisResult.error });
                }

                // Lưu kết quả vào MongoDB
                if (emailId) {
                    await EmailRecord.findByIdAndUpdate(emailId, {
                        headerAnalysis: analysisResult,
                        riskScore: analysisResult.risk_score,
                        riskLevel: analysisResult.risk_level
                    });
                    console.log(`[SOAR] Đã lưu header analysis vào DB (risk: ${analysisResult.risk_level} - ${analysisResult.risk_score})`);
                }

                const riskEmoji = analysisResult.risk_level === 'HIGH' ? '🔴' :
                                  analysisResult.risk_level === 'MEDIUM' ? '🟡' : '🟢';

                console.log(`[SOAR] Header analysis hoàn tất: ${riskEmoji} ${analysisResult.risk_level} (score: ${analysisResult.risk_score})`);
                console.log(`[SOAR]   SPF: ${analysisResult.authentication.spf.status} | DKIM: ${analysisResult.authentication.dkim.status} | DMARC: ${analysisResult.authentication.dmarc.status}`);

                return res.status(200).json({
                    status: 'success',
                    message: 'Phân tích header hoàn tất',
                    emailId: emailId || null,
                    data: analysisResult
                });
            } catch (parseError) {
                console.error(`[SOAR] Lỗi parse JSON: ${stdout}`);
                return res.status(500).json({ error: 'Lỗi parse JSON từ header analyzer' });
            }
        });
    } catch (error) {
        console.error(`[SOAR] Lỗi analyzeHeader: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống', details: error.message });
    }
};

/**
 * POST /api/analyze/content
 * Phân tích nội dung & Social Engineering bằng AI (Ollama Local)
 */
exports.analyzeContent = async (req, res) => {
    const { emailId } = req.body;
    let emlFilePath;

    try {
        if (emailId) {
            const record = await EmailRecord.findById(emailId);
            if (!record) {
                return res.status(404).json({ error: 'Không tìm thấy email record trong DB' });
            }
            emlFilePath = record.emlFilePath;
        } else {
            emlFilePath = path.join(__dirname, '../uploads/sample.eml');
        }

        const pythonScriptPath = path.join(__dirname, '../scripts/content_analyzer.py');
        console.log(`[SOAR AI] Bắt đầu phân tích Social Engineering cho: ${emlFilePath}`);

        exec(`python "${pythonScriptPath}" "${emlFilePath}"`, { maxBuffer: 1024 * 1024 * 5 }, async (error, stdout, stderr) => {
            if (error) {
                console.error(`[SOAR AI] Lỗi chạy content analyzer: ${stderr}`);
                return res.status(500).json({ error: 'Lỗi khi chạy AI analyzer', details: stderr });
            }

            try {
                const analysisResult = JSON.parse(stdout);

                if (analysisResult.error) {
                    return res.status(500).json({ error: analysisResult.error });
                }

                // Cập nhật kết quả vào MongoDB
                if (emailId) {
                    const aiData = analysisResult.ai_analysis?.data || {};
                    await EmailRecord.findByIdAndUpdate(emailId, {
                        contentAnalysis: analysisResult,
                        socialEngineeringScore: aiData.social_engineering_score || null,
                        contentVerdict: aiData.verdict || null
                    });
                    console.log(`[SOAR AI] Đã lưu kết quả phân tích nội dung vào DB (Điểm: ${aiData.social_engineering_score}, Verdict: ${aiData.verdict})`);
                }

                return res.status(200).json({
                    status: 'success',
                    message: 'Phân tích nội dung AI hoàn tất',
                    emailId: emailId || null,
                    data: analysisResult
                });
            } catch (parseError) {
                console.error(`[SOAR AI] Lỗi parse JSON: ${stdout}`);
                return res.status(500).json({ error: 'Lỗi parse JSON từ content analyzer' });
            }
        });
    } catch (error) {
        console.error(`[SOAR AI] Lỗi analyzeContent: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống', details: error.message });
    }
};

/**
 * POST /api/analyze/urls
 * Truy vết URL: Redirect Chain + URLScan.io Sandbox + Risk Assessment
 */
exports.analyzeUrls = async (req, res) => {
    const { emailId } = req.body;
    let emlFilePath;

    try {
        if (emailId) {
            const record = await EmailRecord.findById(emailId);
            if (!record) {
                return res.status(404).json({ error: 'Không tìm thấy email record trong DB' });
            }
            emlFilePath = record.emlFilePath;
        } else {
            emlFilePath = path.join(__dirname, '../uploads/sample.eml');
        }

        const pythonScriptPath = path.join(__dirname, '../scripts/url_scanner.py');
        console.log(`[SOAR URL] Bắt đầu truy vết URL cho: ${emlFilePath}`);

        exec(`python "${pythonScriptPath}" "${emlFilePath}"`, { maxBuffer: 1024 * 1024 * 10, timeout: 120000 }, async (error, stdout, stderr) => {
            if (error) {
                console.error(`[SOAR URL] Lỗi chạy URL scanner: ${stderr}`);
                return res.status(500).json({ error: 'Lỗi khi chạy URL scanner', details: stderr });
            }

            try {
                const analysisResult = JSON.parse(stdout);

                if (analysisResult.error) {
                    return res.status(500).json({ error: analysisResult.error });
                }

                // Lưu kết quả vào MongoDB
                if (emailId) {
                    await EmailRecord.findByIdAndUpdate(emailId, {
                        urlAnalysis: analysisResult
                    });
                    console.log(`[SOAR URL] Đã lưu URL analysis vào DB (${analysisResult.total_urls} URLs, verdict: ${analysisResult.overall_verdict})`);
                }

                return res.status(200).json({
                    status: 'success',
                    message: `Phân tích ${analysisResult.total_urls} URL hoàn tất`,
                    emailId: emailId || null,
                    data: analysisResult
                });
            } catch (parseError) {
                console.error(`[SOAR URL] Lỗi parse JSON: ${stdout.substring(0, 500)}`);
                return res.status(500).json({ error: 'Lỗi parse JSON từ URL scanner' });
            }
        });
    } catch (error) {
        console.error(`[SOAR URL] Lỗi analyzeUrls: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống', details: error.message });
    }
};