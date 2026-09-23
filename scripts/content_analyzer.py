"""
Mini SOAR - Content & Social Engineering Analyzer
Bước 3: Phân tích nội dung và kỹ thuật thao túng tâm lý (Social Engineering) bằng AI (Ollama Local)

Chức năng:
- Làm sạch nội dung email: dùng BeautifulSoup bóc tách HTML, chuẩn hóa text
- Quét nhanh từ khóa thao túng tâm lý (Urgency / Fear / Authority)
- Gọi Ollama (mô hình Qwen 2.5:3b chạy offline trên máy) với prompt chuyên gia SOC
- Đánh giá Social Engineering Score (1-100), nhận diện chiến thuật và kết luận PHISHING / SAFE
"""

import sys
import os
import email
import re
import json
import requests
from datetime import datetime

# Đảm bảo UTF-8 trên Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Thêm thư mục gốc để đọc file .env
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


def extract_and_clean_body(msg):
    """
    Trích xuất toàn bộ nội dung text và html của email,
    sau đó dùng BeautifulSoup làm sạch triệt để HTML.
    """
    text_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))

            # Bỏ qua attachment file đính kèm
            if 'attachment' in content_disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                # Thử decode UTF-8 trước, fallback latin-1
                try:
                    decoded_str = payload.decode('utf-8', errors='replace')
                except Exception:
                    decoded_str = payload.decode('latin-1', errors='replace')

                if content_type == 'text/plain':
                    text_parts.append(decoded_str)
                elif content_type == 'text/html':
                    html_parts.append(decoded_str)
            except Exception:
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            content_type = msg.get_content_type()
            try:
                decoded_str = payload.decode('utf-8', errors='replace')
            except Exception:
                decoded_str = payload.decode('latin-1', errors='replace')

            if content_type == 'text/html':
                html_parts.append(decoded_str)
            else:
                text_parts.append(decoded_str)

    # Ưu tiên làm sạch text_plain nếu có, nếu không thì lấy HTML bóc thẻ
    raw_text = "\n".join(text_parts).strip()
    raw_html = "\n".join(html_parts).strip()

    cleaned_text = ""
    if raw_text:
        cleaned_text = raw_text
    elif raw_html:
        if HAS_BS4:
            soup = BeautifulSoup(raw_html, 'html.parser')
            # Xóa các thẻ style, script không cần thiết
            for tag in soup(['script', 'style', 'head', 'title', 'meta', 'link']):
                tag.decompose()
            cleaned_text = soup.get_text(separator=' ', strip=True)
        else:
            # Fallback regex nếu chưa có BeautifulSoup
            cleaned_text = re.sub(r'<[^>]+>', ' ', raw_html)

    # Chuẩn hóa khoảng trắng dư thừa
    cleaned_text = re.sub(r'[ \t]+', ' ', cleaned_text)
    cleaned_text = re.sub(r'\n\s*\n', '\n', cleaned_text).strip()

    return cleaned_text, raw_html


def scan_social_engineering_keywords(text):
    """Quét các từ khóa tâm lý chiến (áp lực thời gian, đe dọa, tiền bạc, tài khoản)."""
    patterns = {
        'Urgency (Khẩn cấp)': [
            r'khẩn cấp', r'khan cap', r'ngay lập tức', r'ngay lap tuc', r'trong vòng \d+ giờ',
            r'urgent', r'immediate', r'asap', r'action required', r'within \d+ hours', r'hết hạn', r'expire'
        ],
        'Fear & Threat (Đe dọa/Khóa)': [
            r'bị khóa', r'bi khoa', r'tạm ngưng', r'tam ngung', r'xóa tài khoản', r'xoa tai khoan',
            r'chặn', r'suspended', r'locked', r'terminated', r'unauthorized', r'đăng nhập lạ'
        ],
        'Credential Harvesting (Đòi mật khẩu/Xác minh)': [
            r'xác minh', r'xac minh', r'verify', r'xác thực', r'cập nhật thông tin',
            r'mật khẩu', r'password', r'click here', r'bấm vào đây', r'nhấp vào link'
        ],
        'Financial (Tài chính/Phần thưởng)': [
            r'thanh toán', r'payment', r'hóa đơn', r'invoice', r'hoàn tiền', r'refund',
            r'trúng thưởng', r'bonus', r'số dư', r'giao dịch đáng ngờ'
        ]
    }

    detected_keywords = {}
    lower_text = text.lower()

    for category, regex_list in patterns.items():
        found = []
        for pat in regex_list:
            matches = re.findall(pat, lower_text)
            if matches:
                found.append(matches[0])
        if found:
            detected_keywords[category] = list(set(found))

    return detected_keywords


def analyze_with_ollama(subject, sender, body_text):
    """
    Gửi nội dung email tới Ollama API cục bộ (http://127.0.0.1:11434).
    Mặc định sử dụng model được cấu hình trong .env (qwen2.5:3b).
    """
    ollama_host = os.getenv('OLLAMA_HOST', 'http://127.0.0.1:11434').rstrip('/')
    ollama_model = os.getenv('OLLAMA_MODEL', 'qwen2.5:3b')

    # Rút gọn body nếu quá dài để tránh vượt context và tăng tốc độ suy luận
    truncated_body = body_text[:2500] if len(body_text) > 2500 else body_text

    system_prompt = (
        "Bạn là Chuyên gia An ninh mạng (SOC/Security Analyst) chuyên sâu về phát hiện tấn công Phishing và Social Engineering (Thao túng tâm lý).\n"
        "Nhiệm vụ của bạn là phân tích tiêu đề, người gửi và nội dung email được cung cấp, đánh giá mức độ thao túng tâm lý và trả về kết quả BẮT BUỘC dạng JSON thuần túy (không kèm markdown ```json).\n\n"
        "Cấu trúc JSON yêu cầu:\n"
        "{\n"
        '  "social_engineering_score": <số nguyên từ 1 đến 100>,\n'
        '  "urgency_level": "<CRITICAL | HIGH | MEDIUM | LOW>",\n'
        '  "verdict": "<PHISHING | SUSPICIOUS | SAFE>",\n'
        '  "tactics": ["<Chiến thuật 1>", "<Chiến thuật 2>"],\n'
        '  "primary_target": "<Mục tiêu kẻ tấn công nhắm tới: ví dụ chiếm tài khoản, lừa click link, mã độc>",\n'
        '  "explanation": "<Nhận xét, phân tích ngắn gọn bằng tiếng Việt (2-3 câu)>"\n'
        "}"
    )

    user_prompt = f"""
TIÊU ĐỀ: {subject}
NGƯỜI GỬI: {sender}

NỘI DUNG EMAIL:
{truncated_body}
"""

    endpoint = f"{ollama_host}/api/generate"
    payload = {
        "model": ollama_model,
        "prompt": f"{system_prompt}\n\n{user_prompt}",
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=60)
        if response.status_code != 200:
            return {
                "error": f"Lỗi gọi Ollama: HTTP {response.status_code}",
                "details": response.text
            }

        res_data = response.json()
        raw_output = res_data.get('response', '{}').strip()

        # Dọn dẹp nếu model trả về bọc trong code block
        if raw_output.startswith("```json"):
            raw_output = raw_output[7:]
        elif raw_output.startswith("```"):
            raw_output = raw_output[3:]
        if raw_output.endswith("```"):
            raw_output = raw_output[:-3]
        raw_output = raw_output.strip()

        parsed_ai = json.loads(raw_output)
        return {
            "success": True,
            "model": ollama_model,
            "provider": "ollama (local)",
            "data": parsed_ai
        }
    except requests.exceptions.ConnectionError:
        return {
            "error": "Không thể kết nối tới Ollama. Hãy đảm bảo Ollama đang chạy trên máy (http://127.0.0.1:11434).",
            "provider": "ollama (local)"
        }
    except json.JSONDecodeError as je:
        return {
            "error": f"Lỗi parse JSON từ phản hồi của AI: {str(je)}",
            "raw_response": raw_output
        }
    except Exception as e:
        return {
            "error": f"Lỗi không xác định khi gọi AI: {str(e)}"
        }


def analyze_email_content(file_path):
    """Hàm điều phối phân tích nội dung email."""
    if not os.path.exists(file_path):
        return {"error": f"File không tồn tại: {file_path}"}

    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
    except Exception as e:
        return {"error": f"Không thể đọc file .eml: {str(e)}"}

    subject = msg.get('Subject', 'No Subject')
    sender = msg.get('From', 'Unknown')

    # 1. Trích xuất và làm sạch nội dung văn bản
    cleaned_body, raw_html = extract_and_clean_body(msg)

    # 2. Cào danh sách link/URL có trong email
    url_pattern = re.compile(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+')
    urls = list(set(re.findall(url_pattern, cleaned_body + " " + raw_html)))

    # 3. Quét từ khóa thao túng tâm lý
    keywords_detected = scan_social_engineering_keywords(f"{subject} {cleaned_body}")

    # 4. Gửi AI (Ollama Local) phân tích chuyên sâu
    ai_result = analyze_with_ollama(subject, sender, cleaned_body)

    # Tổng hợp kết quả
    result = {
        "file": file_path,
        "metadata": {
            "subject": subject,
            "sender": sender,
            "body_length_chars": len(cleaned_body),
            "urls_count": len(urls)
        },
        "clean_body": cleaned_body[:1000] + ("..." if len(cleaned_body) > 1000 else ""),
        "extracted_urls": urls,
        "keywords_detected": keywords_detected,
        "ai_analysis": ai_result,
        "analyzed_at": datetime.now().isoformat()
    }

    return result


if __name__ == '__main__':
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        analysis = analyze_email_content(target_file)
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    else:
        print(json.dumps({"error": "Vui lòng cung cấp đường dẫn file .eml"}))
