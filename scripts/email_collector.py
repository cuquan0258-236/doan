"""
Mini SOAR - Email Collector Worker
Bước 1: Tiếp nhận, Thu thập & Bảo toàn Email Gốc

Chức năng:
- Kết nối IMAP để kéo email thô (.eml)
- Băm SHA-256 để bảo toàn bằng chứng số
- Trích xuất metadata
- Lưu vào MongoDB
"""

import sys
import os
import imaplib
import email
import hashlib
import json
import ssl
from datetime import datetime
from email.utils import parsedate_to_datetime

# Đảm bảo UTF-8 trên Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Thêm thư mục gốc dự án vào path để đọc .env
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
except ImportError:
    pass

try:
    from pymongo import MongoClient
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False


def compute_sha256(file_path):
    """Tính mã băm SHA-256 của file để đảm bảo tính toàn vẹn bằng chứng số."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_metadata(msg):
    """Trích xuất metadata từ email message object."""
    # Parse ngày nhận
    date_str = msg.get('Date', '')
    received_at = None
    if date_str:
        try:
            received_at = parsedate_to_datetime(date_str).isoformat()
        except Exception:
            received_at = date_str

    return {
        'messageId': msg.get('Message-ID', f'<no-id-{datetime.now().timestamp()}>'),
        'sender': msg.get('From', 'Unknown'),
        'recipient': msg.get('To', 'Unknown'),
        'subject': msg.get('Subject', 'No Subject'),
        'receivedAt': received_at,
        'authResults': msg.get('Authentication-Results', 'Not Found')
    }


def save_eml_file(raw_email_bytes, uploads_dir, metadata):
    """Lưu file .eml vào thư mục uploads với tên an toàn."""
    # Tạo tên file an toàn: timestamp_hash-of-messageId.eml
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    msg_id_hash = hashlib.md5(metadata['messageId'].encode()).hexdigest()[:12]
    filename = f"{timestamp}_{msg_id_hash}.eml"
    file_path = os.path.join(uploads_dir, filename)

    # Đảm bảo thư mục tồn tại
    os.makedirs(uploads_dir, exist_ok=True)

    # Lưu file
    with open(file_path, 'wb') as f:
        if isinstance(raw_email_bytes, str):
            f.write(raw_email_bytes.encode('utf-8'))
        else:
            f.write(raw_email_bytes)

    return file_path, filename


def save_to_mongodb(metadata, sha256_hash, file_path, file_size):
    """Lưu metadata email vào MongoDB."""
    if not HAS_PYMONGO:
        return False, "pymongo chưa được cài đặt"

    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/mini_soar')

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        db = client.get_default_database() if '/' in mongo_uri.split('://')[-1] else client['mini_soar']
        collection = db['emailrecords']

        document = {
            'messageId': metadata['messageId'],
            'sender': metadata['sender'],
            'recipient': metadata['recipient'],
            'subject': metadata['subject'],
            'receivedAt': metadata['receivedAt'],
            'collectedAt': datetime.now().isoformat(),
            'sha256Hash': sha256_hash,
            'emlFilePath': file_path,
            'fileSize': file_size,
            'status': 'collected',
            'authResults': metadata['authResults']
        }

        # Upsert: cập nhật nếu messageId đã tồn tại, insert nếu chưa
        result = collection.update_one(
            {'messageId': metadata['messageId']},
            {'$set': document},
            upsert=True
        )

        client.close()
        return True, str(result.upserted_id or 'updated')
    except Exception as e:
        return False, str(e)


def collect_from_imap():
    """Kết nối IMAP và thu thập email chưa đọc."""
    host = os.getenv('IMAP_HOST', 'imap.gmail.com')
    port = int(os.getenv('IMAP_PORT', '993'))
    user = os.getenv('IMAP_USER', '')
    password = os.getenv('IMAP_PASS', '')
    folder = os.getenv('IMAP_FOLDER', 'INBOX')
    uploads_dir = os.getenv('UPLOADS_DIR', os.path.join(os.path.dirname(__file__), '..', 'uploads'))

    if not user or not password:
        return {"error": "Chưa cấu hình IMAP_USER và IMAP_PASS trong .env"}

    results = {
        "source": "imap",
        "host": host,
        "collected": [],
        "errors": [],
        "total_new": 0
    }

    try:
        # Kết nối IMAP với SSL
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(host, port, ssl_context=context)
        mail.login(user, password)
        mail.select(folder, readonly=False)

        # Tìm email chưa đọc
        status, message_ids = mail.search(None, 'UNSEEN')
        if status != 'OK' or not message_ids[0]:
            mail.logout()
            results["total_new"] = 0
            return results

        id_list = message_ids[0].split()
        results["total_new"] = len(id_list)

        for msg_id in id_list:
            try:
                # Tải email thô
                status, msg_data = mail.fetch(msg_id, '(RFC822)')
                if status != 'OK':
                    results["errors"].append(f"Không tải được email ID {msg_id}")
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Trích xuất metadata
                metadata = extract_metadata(msg)

                # Lưu file .eml
                file_path, filename = save_eml_file(raw_email, uploads_dir, metadata)

                # Băm SHA-256 ngay sau khi lưu
                sha256_hash = compute_sha256(file_path)
                file_size = os.path.getsize(file_path)

                # Lưu vào MongoDB
                db_success, db_info = save_to_mongodb(metadata, sha256_hash, file_path, file_size)

                # Đánh dấu đã đọc trên IMAP
                mail.store(msg_id, '+FLAGS', '\\Seen')

                results["collected"].append({
                    "messageId": metadata['messageId'],
                    "sender": metadata['sender'],
                    "subject": metadata['subject'],
                    "sha256": sha256_hash,
                    "filename": filename,
                    "fileSize": file_size,
                    "savedToDb": db_success
                })

            except Exception as e:
                results["errors"].append(f"Lỗi xử lý email {msg_id}: {str(e)}")

        mail.logout()

    except imaplib.IMAP4.error as e:
        results["error"] = f"Lỗi IMAP: {str(e)}"
    except Exception as e:
        results["error"] = f"Lỗi kết nối: {str(e)}"

    return results


def collect_from_local(file_path):
    """Thu thập và bảo toàn 1 file .eml local (dùng để test hoặc import thủ công)."""
    uploads_dir = os.getenv('UPLOADS_DIR', os.path.join(os.path.dirname(__file__), '..', 'uploads'))

    if not os.path.exists(file_path):
        return {"error": f"File không tồn tại: {file_path}"}

    try:
        # Đọc file
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)

        with open(file_path, 'rb') as f:
            raw_bytes = f.read()

        # Trích xuất metadata
        metadata = extract_metadata(msg)

        # Băm SHA-256 trực tiếp từ file gốc
        sha256_hash = compute_sha256(file_path)
        file_size = os.path.getsize(file_path)

        # Lưu vào MongoDB
        db_success, db_info = save_to_mongodb(metadata, sha256_hash, file_path, file_size)

        return {
            "source": "local",
            "total_new": 1,
            "collected": [{
                "messageId": metadata['messageId'],
                "sender": metadata['sender'],
                "subject": metadata['subject'],
                "sha256": sha256_hash,
                "filename": os.path.basename(file_path),
                "fileSize": file_size,
                "savedToDb": db_success,
                "dbInfo": db_info
            }],
            "errors": []
        }

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--test-local':
        # Chế độ test: xử lý file .eml local
        if len(sys.argv) > 2:
            result = collect_from_local(sys.argv[2])
        else:
            result = {"error": "Thiếu đường dẫn file .eml. Dùng: --test-local <path>"}
    elif len(sys.argv) > 1 and sys.argv[1] == '--imap':
        # Chế độ IMAP: kết nối và thu thập
        result = collect_from_imap()
    else:
        # Mặc định: IMAP mode
        result = collect_from_imap()

    # Output JSON cho Node.js bắt luồng
    print(json.dumps(result, ensure_ascii=False, indent=2))
