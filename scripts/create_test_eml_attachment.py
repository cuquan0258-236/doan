"""
Tạo email mẫu chứa file đính kèm để kiểm thử Bước 5
"""
import os
import sys
import base64
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def create_sample_with_attachment():
    msg = MIMEMultipart()
    msg['From'] = '"Ke Toan Cong Ty" <ketoan@fake-company.com>'
    msg['To'] = 'phanquan2973@gmail.com'
    msg['Subject'] = 'Khan cap: Danh sach thuong va bang luong thang nay'
    msg['Date'] = 'Thu, 24 Sep 2026 12:00:00 +0700'
    msg['Message-ID'] = '<malware-test-2026@fake-company.com>'

    body = """Kính gửi Anh/Chị,

Phòng Kế toán gửi danh sách thưởng quý và điều chỉnh bảng lương trong file đính kèm bên dưới.
Vui lòng tải về và mở file để kiểm tra thông tin tài khoản ngân hàng nhận tiền.

Trân trọng,
Phòng Kế toán & Nhân sự"""

    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    # Giả lập payload: File ngụy trang tên là .pdf.exe (Double Extension) và bắt đầu bằng Magic Byte 'MZ' (DOS/PE header)
    # File hoàn toàn vô hại (chỉ chứa chuỗi giả lập chữ ký MZ), an toàn 100%
    fake_exe_payload = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This is a simulated payload for SOAR testing.'
    
    part1 = MIMEBase('application', 'octet-stream')
    part1.set_payload(fake_exe_payload)
    encoders.encode_base64(part1)
    part1.add_header('Content-Disposition', 'attachment', filename='Bang_Luong_Thang_9.pdf.exe')
    msg.attach(part1)

    # Thêm 1 file tài liệu Word macro (.docm)
    docm_payload = b'PK\x03\x04\x14\x00\x06\x00\x08\x00Simulated macro-enabled office document structure.'
    part2 = MIMEBase('application', 'vnd.ms-word.document.macroEnabled.12')
    part2.set_payload(docm_payload)
    encoders.encode_base64(part2)
    part2.add_header('Content-Disposition', 'attachment', filename='Quy_che_thuong_2026.docm')
    msg.attach(part2)

    # Thêm 1 file EICAR chuẩn quốc tế (để test VirusTotal phát hiện thực tế)
    eicar_payload = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    part3 = MIMEBase('application', 'octet-stream')
    part3.set_payload(eicar_payload)
    encoders.encode_base64(part3)
    part3.add_header('Content-Disposition', 'attachment', filename='EICAR_Test_Payload.com')
    msg.attach(part3)

    output_path = os.path.join(os.path.dirname(__file__), '..', 'uploads', 'sample_attachment.eml')
    with open(output_path, 'wb') as f:
        f.write(msg.as_bytes())

    print(f"Đã tạo file mẫu: {output_path}")

if __name__ == '__main__':
    create_sample_with_attachment()
