const { exec } = require('child_process');
const path = require('path');
const EmailRecord = require('../models/EmailRecord');
const threatIntelService = require('../services/threatIntelService');
const responseService = require('../services/responseService');
const reportService = require('../services/reportService');

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

/**
 * POST /api/analyze/attachments
 * Bước 5: Bóc tách file đính kèm, tính MD5/SHA256, kiểm tra Magic Bytes và tra cứu Cloud Sandbox
 */
exports.analyzeAttachments = async (req, res) => {
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

        const pythonScriptPath = path.join(__dirname, '../scripts/attachment_analyzer.py');
        console.log(`[SOAR Attachment] Bắt đầu phân tích file đính kèm cho: ${emlFilePath}`);

        exec(`python "${pythonScriptPath}" "${emlFilePath}"`, { maxBuffer: 1024 * 1024 * 10, timeout: 60000 }, async (error, stdout, stderr) => {
            if (error) {
                console.error(`[SOAR Attachment] Lỗi chạy attachment analyzer: ${stderr}`);
                return res.status(500).json({ error: 'Lỗi khi chạy attachment analyzer', details: stderr });
            }

            try {
                const analysisResult = JSON.parse(stdout);

                if (analysisResult.error) {
                    return res.status(500).json({ error: analysisResult.error });
                }

                // Lưu kết quả vào MongoDB
                if (emailId) {
                    await EmailRecord.findByIdAndUpdate(emailId, {
                        attachmentAnalysis: analysisResult
                    });
                    console.log(`[SOAR Attachment] Đã lưu Attachment analysis vào DB (${analysisResult.total_attachments} files, verdict: ${analysisResult.overall_verdict})`);
                }

                return res.status(200).json({
                    status: 'success',
                    message: `Phân tích ${analysisResult.total_attachments} file đính kèm hoàn tất`,
                    emailId: emailId || null,
                    data: analysisResult
                });
            } catch (parseError) {
                console.error(`[SOAR Attachment] Lỗi parse JSON: ${stdout.substring(0, 500)}`);
                return res.status(500).json({ error: 'Lỗi parse JSON từ attachment analyzer' });
            }
        });
    } catch (error) {
        console.error(`[SOAR Attachment] Lỗi analyzeAttachments: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống', details: error.message });
    }
};

/**
 * POST /api/analyze/ioc
 * Bước 6: Làm rõ IOC bằng Threat Intelligence đa nguồn (AbuseIPDB, VirusTotal, URLhaus, PhishTank)
 * Có cơ chế Cache MongoDB trong vòng 24 giờ để tiết kiệm quota API.
 */
exports.analyzeIOC = async (req, res) => {
    const { emailId, iocs } = req.body;

    try {
        // Trường hợp 1: Truy vấn danh sách IOCs thủ công được gửi lên
        if (Array.isArray(iocs) && iocs.length > 0) {
            const results = [];
            for (const item of iocs) {
                if (item.value && item.type) {
                    const enriched = await threatIntelService.enrichSingleIOC(item.value, item.type);
                    if (enriched) results.push(enriched);
                }
            }
            return res.status(200).json({
                status: 'success',
                message: `Đã làm rõ ${results.length} IOCs`,
                data: {
                    totalIOCs: results.length,
                    cachedCount: results.filter(r => r.fromCache).length,
                    iocs: results
                }
            });
        }

        // Trường hợp 2: Truy vấn toàn bộ IOCs của một Email Record
        if (!emailId) {
            return res.status(400).json({ error: 'Vui lòng cung cấp emailId hoặc danh sách iocs' });
        }

        const record = await EmailRecord.findById(emailId);
        if (!record) {
            return res.status(404).json({ error: 'Không tìm thấy email record trong DB' });
        }

        console.log(`[SOAR ThreatIntel] Bắt đầu làm rõ IOCs cho Email: ${record._id} (${record.subject})`);

        // Đảm bảo có tối thiểu thông tin IOCs từ file .eml nếu chưa chạy các bước trước
        if (!record.headerAnalysis && record.emlFilePath) {
            try {
                const fs = require('fs');
                if (fs.existsSync(record.emlFilePath)) {
                    const rawContent = fs.readFileSync(record.emlFilePath, 'utf8');
                    // Trích xuất IPs từ Received headers
                    const ipMatches = rawContent.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g) || [];
                    const urlMatches = rawContent.match(/https?:\/\/[^\s<>"')]+/gi) || [];

                    if (!record.headerAnalysis) {
                        record.headerAnalysis = {
                            headers: {
                                received_chain: [...new Set(ipMatches)].slice(0, 5).map(ip => ({ ip }))
                            }
                        };
                    }
                    if (!record.urlAnalysis) {
                        record.urlAnalysis = {
                            urls: [...new Set(urlMatches)].slice(0, 10).map(u => ({ url: u }))
                        };
                    }
                }
            } catch (readErr) {
                console.warn(`[SOAR ThreatIntel] Cảnh báo đọc fallback file: ${readErr.message}`);
            }
        }

        // Thực hiện làm rõ IOCs (với Cache 24h)
        const iocAnalysis = await threatIntelService.enrichAllIOCsFromEmail(record);

        // Lưu vào MongoDB
        record.iocAnalysis = iocAnalysis;
        await record.save();

        console.log(`[SOAR ThreatIntel] Hoàn tất làm rõ IOC: ${iocAnalysis.totalIOCs} IOCs (${iocAnalysis.cachedCount} từ cache, ${iocAnalysis.liveQueriedCount} gọi API mới) - Verdict: ${iocAnalysis.overallVerdict}`);

        return res.status(200).json({
            status: 'success',
            message: `Làm rõ ${iocAnalysis.totalIOCs} IOCs thành công`,
            emailId: record._id,
            data: iocAnalysis
        });
    } catch (error) {
        console.error(`[SOAR ThreatIntel] Lỗi analyzeIOC: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi hệ thống khi làm rõ IOC', details: error.message });
    }
};

/**
 * POST /api/response/block
 * Bước 8: Gửi lệnh ngăn chặn IOC độc hại tới Tường lửa pfSense hoặc Wazuh EDR
 */
exports.executeBlockResponse = async (req, res) => {
    const { emailId, target, iocs } = req.body;
    if (!emailId) {
        return res.status(400).json({ error: 'Thiếu emailId trong request body' });
    }

    try {
        console.log(`[SOAR Response] Nhận yêu cầu chặn IOCs trên ${target || 'pfsense'} cho emailId: ${emailId}`);
        const result = await responseService.executeResponse({
            emailId,
            target: target || 'pfsense',
            customIocs: iocs
        });

        return res.status(200).json({
            status: 'success',
            message: result.summary,
            data: result.action
        });
    } catch (error) {
        console.error(`[SOAR Response] Lỗi executeBlockResponse: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi khi thực thi lệnh chặn', details: error.message });
    }
};

/**
 * GET /api/reports/:id/html
 * Bước 8: Hiển thị báo cáo sự cố chuẩn SOC, định dạng in PDF A4
 */
exports.exportReportHTML = async (req, res) => {
    const { id } = req.params;
    try {
        const html = await reportService.generateHTMLReport(id);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(200).send(html);
    } catch (error) {
        console.error(`[SOAR Report] Lỗi exportReportHTML: ${error.message}`);
        return res.status(500).json({ error: 'Lỗi tạo giao diện báo cáo HTML/PDF', details: error.message });
    }
};