"""
Mini SOAR - Attachment & Payload Analyzer
Bước 5: Phân tích file đính kèm và payload mã độc

Nguyên tắc an toàn:
- TUYỆT ĐỐI KHÔNG tự thực thi file đính kèm trên máy thật.
- Tách và lưu trữ an toàn trong thư mục cách ly (Quarantine).
- Tính mã băm cryptographic (MD5, SHA-1, SHA-256).
- Nhận diện định dạng thật qua Magic Bytes (phát hiện mạo danh extension như .pdf.exe).
- Kết nối Cloud Sandbox (Hybrid Analysis / VirusTotal) để tra cứu và lấy Báo cáo Hành vi (Behavior Report).
"""

import sys
import os
import email
import re
import json
import hashlib
import time
import requests
from datetime import datetime

# Đảm bảo UTF-8 trên Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Thư mục gốc dự án
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, '.env'))
except ImportError:
    pass

# Thư mục cách ly file đính kèm
QUARANTINE_DIR = os.path.join(BASE_DIR, 'uploads', 'attachments')
os.makedirs(QUARANTINE_DIR, exist_ok=True)


# ==============================================================
# 1. NHẬN DIỆN MAGIC BYTES & PHÁT HIỆN EXTENSION SPOOFING
# ==============================================================

MAGIC_SIGNATURES = [
    (b'MZ', 'Windows Executable / DLL (.exe, .dll, .scr)', 'exe'),
    (b'%PDF', 'PDF Document (.pdf)', 'pdf'),
    (b'PK\x03\x04', 'ZIP Archive / Office Open XML (.zip, .docx, .xlsx, .pptx, .jar)', 'zip'),
    (b'\xd0\xcf\x11\xe0', 'Microsoft Office Legacy Compound File (.doc, .xls, .ppt, .msi)', 'ole'),
    (b'Rar!\x1a\x07', 'RAR Archive (.rar)', 'rar'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip Archive (.7z)', '7z'),
    (b'\x1f\x8b\x08', 'GZIP Archive (.gz)', 'gz'),
    (b'{\\rtf', 'Rich Text Format (.rtf)', 'rtf'),
    (b'#!/bin/', 'Unix Shell Script (.sh)', 'sh')
]

DANGEROUS_EXTENSIONS = {
    'HIGH': ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.scr', '.pif', '.hta', '.cpl', '.msi', '.jar', '.reg', '.iso', '.img', '.vhd'],
    'MEDIUM': ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.zip', '.rar', '.7z', '.tar', '.gz', '.ace', '.cab', '.iso', '.rtf', '.chm', '.htm', '.html', '.svg']
}


def detect_file_type_magic(data):
    """Xác định loại file thực tế bằng cách đọc bytes đầu (Magic bytes)."""
    for sig, desc, short_type in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return desc, short_type
    return 'Unknown Binary / Plain Text', 'unknown'


def decode_mime_header(header_val):
    """Giải mã an toàn tên file từ MIME header (hỗ trợ UTF-8, base64)."""
    if not header_val:
        return ""
    try:
        decoded_fragments = email.header.decode_header(header_val)
        parts = []
        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                try:
                    parts.append(fragment.decode(encoding or 'utf-8', errors='replace'))
                except Exception:
                    parts.append(fragment.decode('latin-1', errors='replace'))
            else:
                parts.append(str(fragment))
        return "".join(parts)
    except Exception:
        return str(header_val)


# ==============================================================
# 2. GIẢI MÃ BASE64 VÀ BÓC TÁCH FILE ĐÍNH KÈM TỪ .EML
# ==============================================================

def extract_attachments_from_eml(eml_path):
    """Trích xuất tất cả các file đính kèm từ file .eml và lưu cách ly."""
    if not os.path.exists(eml_path):
        return [], f"Không tìm thấy file: {eml_path}"

    try:
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
    except Exception as e:
        return [], f"Lỗi đọc email: {str(e)}"

    attachments = []
    part_idx = 0

    for part in msg.walk():
        part_idx += 1
        content_disposition = str(part.get('Content-Disposition', ''))
        raw_filename = part.get_filename()
        content_type = part.get_content_type()

        # Kiểm tra xem part này có phải là file đính kèm không
        is_attachment = ('attachment' in content_disposition.lower() or 
                         bool(raw_filename) or 
                         ('inline' in content_disposition.lower() and content_type.startswith(('image/', 'application/', 'audio/'))))

        # Bỏ qua thân email text thuần hoặc html không có filename
        if not is_attachment or (not raw_filename and content_type in ['text/plain', 'text/html']):
            continue

        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            # Tên file đã chuẩn hóa
            filename = decode_mime_header(raw_filename) if raw_filename else f"attachment_{part_idx}.bin"
            # Làm sạch tên file để tránh Path Traversal
            safe_filename = os.path.basename(filename).replace(" ", "_")
            if not safe_filename:
                safe_filename = f"attachment_{part_idx}.bin"

            # Tính các mã băm
            md5_hash = hashlib.md5(payload).hexdigest()
            sha1_hash = hashlib.sha1(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            # Lưu an toàn vào thư mục cách ly Quarantined
            saved_filename = f"{sha256_hash[:16]}_{safe_filename}"
            saved_path = os.path.join(QUARANTINE_DIR, saved_filename)
            with open(saved_path, 'wb') as out_f:
                out_f.write(payload)

            # Phân tích Magic bytes
            magic_desc, short_type = detect_file_type_magic(payload)

            file_ext = os.path.splitext(safe_filename)[1].lower()

            attachments.append({
                'filename': safe_filename,
                'content_type': content_type,
                'file_size_bytes': len(payload),
                'file_size_formatted': format_file_size(len(payload)),
                'extension': file_ext,
                'quarantine_path': saved_path,
                'hashes': {
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash
                },
                'magic_bytes': {
                    'description': magic_desc,
                    'type': short_type,
                    'first_16_hex': payload[:16].hex()
                }
            })
        except Exception as err:
            continue

    return attachments, None


def format_file_size(size_bytes):
    """Định dạng dung lượng file dễ đọc."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


# ==============================================================
# 3. PHÂN TÍCH TĨNH & PHÁT HIỆN KỸ THUẬT LỪA ĐẢO EXTENSION
# ==============================================================

def analyze_attachment_heuristics(att):
    """Phân tích các đặc điểm tĩnh đáng ngờ của file đính kèm."""
    filename = att['filename'].lower()
    ext = att['extension'].lower()
    magic_type = att['magic_bytes']['type']
    flags = []
    risk_score = 0

    # 1. Phát hiện kỹ thuật Double Extension (ví dụ: Invoice_2026.pdf.exe)
    double_ext_pattern = r'\.(pdf|docx|xlsx|doc|xls|txt|jpg|png|csv)\.(exe|bat|vbs|js|scr|pif|ps1|hta|cmd|cpl|wsf)$'
    if re.search(double_ext_pattern, filename):
        risk_score += 45
        flags.append('🚨 NGUY HIỂM CAO: Phát hiện kỹ thuật Double Extension (giả dạng tài liệu văn phòng nhưng là file thực thi độc hại)')

    # 2. Định dạng file thực thi trực tiếp
    if ext in DANGEROUS_EXTENSIONS['HIGH']:
        risk_score += 40
        flags.append(f'🔴 ĐỊNH DẠNG NGUY HIỂM: Phần mở rộng có thể thực thi mã độc trực tiếp ({ext})')
    elif ext in DANGEROUS_EXTENSIONS['MEDIUM']:
        risk_score += 20
        if ext in ['.docm', '.xlsm', '.pptm']:
            flags.append(f'🟡 Macro-Enabled Document: Tệp văn phòng chứa Macro VBA ({ext}), có nguy cơ tự chạy mã độc khi mở')
        elif ext in ['.zip', '.rar', '.7z', '.iso']:
            flags.append(f'🟡 Tệp nén/Ảnh đĩa ({ext}): Hacker thường dùng để ẩn giấu payload vượt mặt bộ lọc email')
        else:
            flags.append(f'🟡 Định dạng tệp cần lưu ý ({ext})')

    # 3. Phát hiện Extension Spoofing qua Magic Bytes
    # Ví dụ: file đuôi .pdf hoặc .docx nhưng magic byte lại là 'MZ' (Windows Executable)
    if magic_type == 'exe' and ext not in ['.exe', '.dll', '.scr', '.cpl']:
        risk_score += 50
        flags.append(f'🚨 CỰC KỲ NGUY HIỂM (Extension Spoofing): Tên file là "{ext}" nhưng nội dung bên trong thực chất là FILE THỰC THI WINDOWS (PE/EXE)!')
    elif magic_type == 'zip' and ext not in ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk']:
        risk_score += 25
        flags.append(f'🟡 Magic Byte Mismatch: Tên file là "{ext}" nhưng ruột file là cấu trúc ZIP/Archive')

    # 4. Tên file chứa từ khóa mồi nhử thường gặp
    phishing_keywords = ['invoice', 'receipt', 'payment', 'salary', 'bonus', 'bank', 'xac_minh', 'hoa_don', 'thanh_toan', 'luong']
    if any(kw in filename for kw in phishing_keywords) and (risk_score > 0):
        risk_score += 10
        flags.append('🟡 Tên file dùng mồi nhử tài chính/lương bổng để kích thích người nhận mở tệp')

    # Xác định mức độ rủi ro
    if risk_score >= 50:
        level = 'HIGH'
    elif risk_score >= 20:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return {
        'risk_score': min(risk_score, 100),
        'risk_level': level,
        'flags': flags
    }


# ==============================================================
# 4. TÍCH HỢP CLOUD SANDBOX & THREAT INTELLIGENCE (HYBRID ANALYSIS / VIRUSTOTAL)
# ==============================================================

def query_hybrid_analysis(sha256_hash, api_key):
    """
    Tra cứu báo cáo hành vi từ Hybrid Analysis (Falcon Sandbox) bằng mã băm SHA-256.
    Không cần upload file, cho kết quả tức thì nếu mẫu đã từng được phân tích.
    """
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256_hash}/summary"
    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            rep = resp.json()
            verdict = rep.get("verdict", "no specific threat")
            threat_score = rep.get("threat_score", 0)
            multiscan = rep.get("multiscan_result", 0)

            return {
                "status": "success",
                "provider": "Hybrid Analysis (Falcon Sandbox)",
                "found": True,
                "verdict": verdict,
                "threat_score": threat_score,
                "multiscan_result": multiscan,
                "report_url": f"https://www.hybrid-analysis.com/sample/{sha256_hash}"
            }
        elif resp.status_code == 404:
            return {
                "status": "not_found",
                "provider": "Hybrid Analysis",
                "message": "Mẫu mã băm này chưa có trong cơ sở dữ liệu của Hybrid Analysis"
            }
        elif resp.status_code == 403:
            return {"status": "error", "provider": "Hybrid Analysis", "message": "API Key không hợp lệ hoặc hết hạn"}
        elif resp.status_code == 429:
            return {"status": "rate_limited", "provider": "Hybrid Analysis", "message": "Vượt quá giới hạn gọi API"}
        else:
            return {"status": "error", "provider": "Hybrid Analysis", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "provider": "Hybrid Analysis", "message": str(e)[:200]}


def query_virustotal(sha256_hash, api_key):
    """Tra cứu kết quả quét từ VirusTotal API v3 bằng SHA-256."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total_engines = sum(stats.values()) if stats else 0

            return {
                "status": "success",
                "provider": "VirusTotal",
                "found": True,
                "malicious_count": malicious_count,
                "total_engines": total_engines,
                "detection_ratio": f"{malicious_count}/{total_engines}",
                "verdict": "MALICIOUS" if malicious_count >= 3 else "SUSPICIOUS" if malicious_count >= 1 else "CLEAN",
                "suggested_threat_label": data.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A"),
                "report_url": f"https://www.virustotal.com/gui/file/{sha256_hash}"
            }
        elif resp.status_code == 404:
            return {
                "status": "not_found",
                "provider": "VirusTotal",
                "message": "Chưa có báo cáo trên VirusTotal cho mã băm này"
            }
        else:
            return {"status": "error", "provider": "VirusTotal", "message": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "provider": "VirusTotal", "message": str(e)[:200]}


def fetch_sandbox_reports(sha256_hash):
    """
    Tổng hợp tra cứu Cloud Sandbox:
    Ưu tiên Hybrid Analysis, hỗ trợ VirusTotal nếu cấu hình trong .env.
    """
    ha_key = os.getenv('HYBRID_ANALYSIS_API_KEY', '').strip()
    vt_key = os.getenv('VIRUSTOTAL_API_KEY', '').strip()

    reports = {}

    if ha_key:
        reports['hybrid_analysis'] = query_hybrid_analysis(sha256_hash, ha_key)
    else:
        reports['hybrid_analysis'] = {
            'status': 'skipped',
            'reason': 'Chưa cấu hình HYBRID_ANALYSIS_API_KEY trong .env (đăng ký miễn phí tại hybrid-analysis.com)'
        }

    if vt_key:
        reports['virustotal'] = query_virustotal(sha256_hash, vt_key)
    else:
        reports['virustotal'] = {
            'status': 'skipped',
            'reason': 'Chưa cấu hình VIRUSTOTAL_API_KEY trong .env'
        }

    return reports


# ==============================================================
# 5. HÀM ĐIỀU PHỐI CHÍNH
# ==============================================================

def analyze_email_attachments(eml_path):
    """Điều phối toàn bộ quy trình bóc tách và phân tích file đính kèm."""
    raw_attachments, err = extract_attachments_from_eml(eml_path)
    if err:
        return {"error": err}

    if not raw_attachments:
        return {
            "file": eml_path,
            "total_attachments": 0,
            "has_attachments": False,
            "attachments": [],
            "summary": "Email không có file đính kèm.",
            "overall_verdict": "NO_ATTACHMENTS",
            "analyzed_at": datetime.now().isoformat()
        }

    processed_attachments = []
    high_count = 0
    medium_count = 0

    for att in raw_attachments:
        sha256 = att['hashes']['sha256']

        # 1. Phân tích tĩnh & Heuristics
        heuristics = analyze_attachment_heuristics(att)
        att['heuristics'] = heuristics

        if heuristics['risk_level'] == 'HIGH':
            high_count += 1
        elif heuristics['risk_level'] == 'MEDIUM':
            medium_count += 1

        # 2. Truy vấn Cloud Sandbox / Threat Intelligence
        sandbox_res = fetch_sandbox_reports(sha256)
        att['sandbox_reports'] = sandbox_res

        # Nếu Cloud Sandbox báo Malicious, nâng điểm rủi ro
        ha_rep = sandbox_res.get('hybrid_analysis', {})
        if ha_rep.get('status') == 'success' and ha_rep.get('verdict') in ['malicious', 'suspicious']:
            heuristics['risk_score'] = max(heuristics['risk_score'], ha_rep.get('threat_score', 80))
            heuristics['risk_level'] = 'HIGH'
            heuristics['flags'].append(f"🚨 Hybrid Analysis xác nhận: {ha_rep.get('verdict').upper()} (Threat score: {ha_rep.get('threat_score')})")

        vt_rep = sandbox_res.get('virustotal', {})
        if vt_rep.get('status') == 'success' and vt_rep.get('verdict') == 'MALICIOUS':
            heuristics['risk_score'] = max(heuristics['risk_score'], 85)
            heuristics['risk_level'] = 'HIGH'
            heuristics['flags'].append(f"🚨 VirusTotal xác nhận: {vt_rep.get('detection_ratio')} Antivirus nhận diện là MÃ ĐỘC")

        processed_attachments.append(att)

    # Đánh giá tổng quan
    overall_verdict = 'DANGEROUS' if high_count > 0 else 'SUSPICIOUS' if medium_count > 0 else 'CLEAN'

    return {
        "file": eml_path,
        "total_attachments": len(processed_attachments),
        "has_attachments": True,
        "high_risk_count": high_count,
        "medium_risk_count": medium_count,
        "overall_verdict": overall_verdict,
        "attachments": processed_attachments,
        "analyzed_at": datetime.now().isoformat()
    }


if __name__ == '__main__':
    if len(sys.argv) > 1:
        result = analyze_email_attachments(sys.argv[1])
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps({"error": "Vui lòng cung cấp đường dẫn file .eml"}))
