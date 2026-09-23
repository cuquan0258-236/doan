import sys
import email
import re
import json

def parse_eml(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return

    # Lấy nội dung thân email
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                break
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    # Dùng Regex cào URL
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    urls = list(set(re.findall(url_pattern, body)))

    result = {
        "metadata": {
            "sender": msg.get('From', 'Unknown'),
            "subject": msg.get('Subject', 'No Subject'),
            "auth_results": msg.get('Authentication-Results', 'Not Found')
        },
        "extracted_urls": urls
    }
    
    # In ra JSON chuẩn để Node.js bắt luồng
    print(json.dumps(result))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_eml(sys.argv[1])
    else:
        print(json.dumps({"error": "Thiếu đường dẫn file .eml"}))
