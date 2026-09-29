/**
 * Mini SOAR - Dashboard UI Utilities & Helpers
 */

/**
 * Escape HTML để ngăn ngừa tấn công XSS
 */
function escHtml(s) {
    if (s == null) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

/**
 * Trả về mã màu theo phân cấp rủi ro
 */
function riskColor(level) {
    if (level === 'MALICIOUS' || level === 'HIGH') return '#ff4757';
    if (level === 'SUSPICIOUS' || level === 'MEDIUM') return '#ffa502';
    if (level === 'LOW') return '#eccc68';
    if (level === 'CLEAN') return '#2ed573';
    if (level === 'INCONCLUSIVE') return '#70a1ff';
    return '#888';
}

/**
 * Định dạng kích thước tệp (Byte / KB)
 */
function formatSize(bytes) {
    if (bytes == null) return '0 B';
    return bytes > 1024 ? (bytes / 1024).toFixed(1) + ' KB' : bytes + ' B';
}

/**
 * Giải mã tiêu đề email (hỗ trợ RFC 2047 Base64 encoded subjects)
 */
function decodeSubject(s) {
    if (!s) return 'No Subject';
    const decoded = s.replace(/=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=/gi, (_, b64) => {
        try {
            return atob(b64).split('').map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        } catch (e) {
            return _;
        }
    });
    try {
        return decodeURIComponent(decoded).replace(/\r?\n\t?/g, '');
    } catch (e) {
        return s.replace(/=\?UTF-8\?B\?[^?]+\?=/gi, '[Encoded]').replace(/\r?\n\t?/g, '');
    }
}

/**
 * Cuộn mượt đến một phần tử chỉ định theo ID
 */
function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Mở Báo cáo sự cố dạng HTML/PDF in ấn sang tab mới
 */
function openReportPDF(id) {
    window.open(`${API}/reports/${id}/html`, '_blank');
}
