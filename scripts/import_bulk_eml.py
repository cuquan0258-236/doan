"""
Mini SOAR - Bulk EML Import Tool (Công Cụ Nhập Hàng Loạt Email .eml)
Dành cho việc nạp các tập dữ liệu lớn (dataset từ 100 đến 10.000+ file .eml) vào hệ thống

Tính năng:
- Quét toàn bộ file .eml trong thư mục chỉ định
- Tự động bóc tách Message-ID, Sender, Recipient, Subject, ReceivedAt
- Tính toán mã băm SHA-256 bảo toàn chứng cứ số
- Tối ưu hiệu năng cao bằng MongoDB Bulk Insert (chèn hàng ngàn email trong vài giây)
- Tự động bỏ qua các email đã tồn tại (chống trùng lặp theo SHA-256 / Message-ID)
- Hỗ trợ tham số --limit để nhập thử nghiệm số lượng mong muốn (ví dụ: 50, 100, 500)
"""

import sys
import os
import argparse
import hashlib
import email
from email import policy
from datetime import datetime
from email.utils import parsedate_to_datetime

# Đảm bảo UTF-8 trên Windows console
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Đọc cấu hình từ .env
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
except ImportError:
    pass

try:
    from pymongo import MongoClient, UpdateOne
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False


def compute_sha256(file_path):
    """Tính mã băm SHA-256 của file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_eml_header(file_path):
    """Bóc tách nhanh metadata cơ bản từ file .eml."""
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    subject = str(msg.get('Subject', 'No Subject'))
    sender = str(msg.get('From', 'Unknown'))
    recipient = str(msg.get('To', 'Unknown'))
    message_id = msg.get('Message-ID', None)

    date_str = msg.get('Date', None)
    received_at = None
    if date_str:
        try:
            received_at = parsedate_to_datetime(str(date_str))
        except Exception:
            received_at = None

    auth_results = str(msg.get('Authentication-Results', 'Not Found'))

    return {
        'message_id': message_id,
        'sender': sender,
        'recipient': recipient,
        'subject': subject,
        'received_at': received_at,
        'auth_results': auth_results
    }


def main():
    parser = argparse.ArgumentParser(description="Nhập hàng loạt file .eml vào Mini-SOAR MongoDB")
    parser.add_argument('--dir', required=True, help="Đường dẫn thư mục chứa các file .eml")
    parser.add_argument('--limit', type=int, default=0, help="Giới hạn số lượng email cần nhập (0 = nhập tất cả)")
    parser.add_argument('--copy-to-uploads', action='store_true', help="Tự động copy file vào thư mục uploads/ của dự án")
    args = parser.parse_args()

    if not HAS_PYMONGO:
        print("[LỖI] Chưa cài đặt pymongo. Hãy chạy: pip install pymongo")
        sys.exit(1)

    source_dir = os.path.abspath(args.dir)
    if not os.path.exists(source_dir):
        print(f"[LỖI] Thư mục không tồn tại: {source_dir}")
        sys.exit(1)

    # Kết nối MongoDB
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/mini_soar')
    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    emails_collection = db['emailrecords']

    print(f"[*] Đang quét thư mục: {source_dir}")
    eml_files = []
    for root, _, files in os.walk(source_dir):
        for f in files:
            if f.lower().endswith('.eml'):
                eml_files.append(os.path.join(root, f))

    total_found = len(eml_files)
    print(f"[*] Tìm thấy tổng cộng: {total_found} file .eml")

    if total_found == 0:
        print("[!] Không tìm thấy file .eml nào trong thư mục.")
        return

    if args.limit > 0 and args.limit < total_found:
        eml_files = eml_files[:args.limit]
        print(f"[*] Đang thực hiện giới hạn: Nhập {len(eml_files)} file")

    uploads_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'uploads'))
    os.makedirs(uploads_dir, exist_ok=True)

    # Lấy danh sách SHA-256 đã tồn tại trong DB để tránh query nhiều lần
    print("[*] Đang kiểm tra các email đã có trong database...")
    existing_hashes = set(emails_collection.distinct('sha256Hash'))
    print(f"[*] Đã có sẵn {len(existing_hashes)} email trong database.")

    batch_operations = []
    inserted_count = 0
    skipped_count = 0
    error_count = 0

    print("[*] Bắt đầu xử lý và chuẩn hóa dữ liệu...")

    for i, file_path in enumerate(eml_files, 1):
        try:
            file_size = os.path.getsize(file_path)
            sha256_hash = compute_sha256(file_path)

            # Bỏ qua nếu trùng SHA-256
            if sha256_hash in existing_hashes:
                skipped_count += 1
                continue

            # Bóc tách header
            meta = parse_eml_header(file_path)

            # Đảm bảo Message-ID là duy nhất
            msg_id = meta['message_id']
            if not msg_id or msg_id.strip() == '':
                msg_id = f"<soar-import-{sha256_hash[:16]}@local>"

            target_file_path = file_path
            if args.copy_to_uploads:
                # Copy file vào thư mục uploads
                dest_filename = f"imported_{sha256_hash[:12]}_{os.path.basename(file_path)}"
                target_file_path = os.path.join(uploads_dir, dest_filename)
                if not os.path.exists(target_file_path):
                    import shutil
                    shutil.copy2(file_path, target_file_path)

            doc = {
                'messageId': msg_id,
                'sender': meta['sender'],
                'recipient': meta['recipient'],
                'subject': meta['subject'],
                'receivedAt': meta['received_at'],
                'collectedAt': datetime.utcnow(),
                'sha256Hash': sha256_hash,
                'emlFilePath': target_file_path,
                'fileSize': file_size,
                'status': 'collected',
                'authResults': meta['auth_results'],
                'headerAnalysis': None,
                'contentAnalysis': None,
                'urlAnalysis': None,
                'attachmentAnalysis': None,
                'iocAnalysis': None,
                'ruleEvaluation': None,
                'riskScore': None,
                'riskLevel': None,
                'overallRiskScore': None
            }

            # Upsert theo messageId hoặc sha256Hash
            batch_operations.append(
                UpdateOne(
                    {'$or': [{'messageId': msg_id}, {'sha256Hash': sha256_hash}]},
                    {'$setOnInsert': doc},
                    upsert=True
                )
            )
            existing_hashes.add(sha256_hash)
            inserted_count += 1

            # Ghi vào MongoDB theo từng mẻ (batch 500 records)
            if len(batch_operations) >= 500:
                emails_collection.bulk_write(batch_operations, ordered=False)
                batch_operations = []
                print(f"    -> Đã ghi {inserted_count} email vào database ({i}/{len(eml_files)})...")

        except Exception as e:
            error_count += 1
            if error_count <= 5:
                print(f"[!] Lỗi khi đọc file {os.path.basename(file_path)}: {e}")

    # Ghi phần còn lại
    if batch_operations:
        emails_collection.bulk_write(batch_operations, ordered=False)

    print("\n" + "=" * 50)
    print("           KẾT QUẢ NHẬP EMAIL")
    print("=" * 50)
    print(f"Tổng số file quét được : {len(eml_files)}")
    print(f"Đã nhập thành công    : {inserted_count} email mới")
    print(f"Bỏ qua (đã có sẵn)     : {skipped_count} email trùng")
    print(f"Lỗi đọc file           : {error_count} file")
    print(f"Tổng email trong DB    : {emails_collection.count_documents({})} email")
    print("=" * 50)
    print("[+] Mở Dashboard tại http://localhost:3000 để xem các email vừa nhập.")


if __name__ == '__main__':
    main()
