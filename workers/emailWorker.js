const { exec } = require('child_process');
const path = require('path');

const PYTHON_SCRIPT = path.join(__dirname, '../scripts/email_collector.py');

/**
 * Chạy Python email collector worker
 * @param {string} mode - 'imap' hoặc 'test-local'
 * @param {string} [localFile] - Đường dẫn file .eml (chỉ dùng với mode test-local)
 * @returns {Promise<object>} Kết quả thu thập dạng JSON
 */
function runCollector(mode = 'imap', localFile = null) {
    return new Promise((resolve, reject) => {
        let command;

        if (mode === 'test-local' && localFile) {
            command = `python "${PYTHON_SCRIPT}" --test-local "${localFile}"`;
        } else {
            command = `python "${PYTHON_SCRIPT}" --imap`;
        }

        console.log(`[SOAR Worker] Bắt đầu thu thập email (mode: ${mode})...`);

        exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
            if (error) {
                console.error(`[SOAR Worker] Lỗi thực thi: ${stderr}`);
                reject({ error: 'Lỗi chạy Python collector', details: stderr });
                return;
            }

            try {
                const result = JSON.parse(stdout);

                if (result.error) {
                    console.error(`[SOAR Worker] Lỗi từ Python: ${result.error}`);
                } else {
                    const collected = result.collected || [];
                    console.log(`[SOAR Worker] Thu thập thành công: ${collected.length} email mới`);

                    // Log chi tiết từng email
                    collected.forEach((item, index) => {
                        console.log(`  [${index + 1}] ${item.sender} - "${item.subject}"`);
                        console.log(`      SHA-256: ${item.sha256}`);
                        console.log(`      File: ${item.filename} (${item.fileSize} bytes)`);
                        console.log(`      Lưu DB: ${item.savedToDb ? 'OK' : 'FAIL'}`);
                    });

                    if (result.errors && result.errors.length > 0) {
                        console.warn(`[SOAR Worker] Có ${result.errors.length} lỗi:`);
                        result.errors.forEach(err => console.warn(`  - ${err}`));
                    }
                }

                resolve(result);
            } catch (parseError) {
                console.error(`[SOAR Worker] Lỗi parse JSON: ${stdout}`);
                reject({ error: 'Lỗi parse JSON từ Python', raw: stdout });
            }
        });
    });
}

module.exports = { runCollector };
