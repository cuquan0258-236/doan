"""
Mini SOAR - Email Header Analyzer
Bước 2: Phân tích Header, SPF/DKIM/DMARC & Domain Age

Chức năng:
- Bóc tách header: From, Return-Path, Reply-To, Received, X-Mailer
- Parse Authentication-Results: SPF, DKIM, DMARC
- Tra cứu tuổi tên miền (Domain Age) bằng python-whois
- Phát hiện bất thường (anomalies) và tính điểm rủi ro (risk_score)
"""

import sys
import os
import email
import re
import json
from datetime import datetime, timezone
from email.utils import parseaddr

# Fix encoding trên Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# Tra cứu Domain Age
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


def extract_domain(email_address):
    """Trích xuất domain từ địa chỉ email."""
    # Parse email address (xử lý format "Name <email@domain.com>")
    _, addr = parseaddr(email_address)
    if '@' in addr:
        return addr.split('@')[1].strip().lower()
    # Fallback: tìm domain trong chuỗi
    match = re.search(r'@([\w.-]+)', email_address)
    if match:
        return match.group(1).lower()
    return None


def parse_received_chain(msg):
    """Truy vết chuỗi Received headers (mail hops)."""
    received_headers = msg.get_all('Received', [])
    hops = []
    for i, header in enumerate(received_headers):
        hop = {
            'hop': i + 1,
            'raw': header.strip().replace('\n', ' ').replace('\r', ' ')
        }

        # Trích xuất from/by
        from_match = re.search(r'from\s+([\w.-]+)', header, re.IGNORECASE)
        by_match = re.search(r'by\s+([\w.-]+)', header, re.IGNORECASE)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)

        if from_match:
            hop['from'] = from_match.group(1)
        if by_match:
            hop['by'] = by_match.group(1)
        if ip_match:
            hop['ip'] = ip_match.group(1)

        hops.append(hop)

    return hops


def parse_authentication_results(auth_header):
    """Parse trường Authentication-Results để lấy SPF, DKIM, DMARC status."""
    result = {
        'spf': {'status': 'none', 'domain': None, 'ip': None},
        'dkim': {'status': 'none', 'domain': None},
        'dmarc': {'status': 'none', 'domain': None}
    }

    if not auth_header or auth_header == 'Not Found':
        return result

    auth_lower = auth_header.lower()

    # === SPF ===
    spf_match = re.search(
        r'spf\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none)',
        auth_lower
    )
    if spf_match:
        result['spf']['status'] = spf_match.group(1)

    # SPF sender IP
    spf_ip_match = re.search(r'sender\s+ip\s+is\s+([\d.]+)', auth_lower)
    if spf_ip_match:
        result['spf']['ip'] = spf_ip_match.group(1)

    # SPF domain
    spf_domain_match = re.search(r'smtp\.mailfrom=([\w.-]+)', auth_lower)
    if spf_domain_match:
        result['spf']['domain'] = spf_domain_match.group(1)

    # === DKIM ===
    dkim_match = re.search(
        r'dkim\s*=\s*(pass|fail|neutral|temperror|permerror|none)',
        auth_lower
    )
    if dkim_match:
        result['dkim']['status'] = dkim_match.group(1)

    # DKIM domain
    dkim_domain_match = re.search(r'header\.i=@([\w.-]+)', auth_lower)
    if not dkim_domain_match:
        dkim_domain_match = re.search(r'header\.d=([\w.-]+)', auth_lower)
    if dkim_domain_match:
        result['dkim']['domain'] = dkim_domain_match.group(1)

    # === DMARC ===
    dmarc_match = re.search(
        r'dmarc\s*=\s*(pass|fail|bestguesspass|none)',
        auth_lower
    )
    if dmarc_match:
        result['dmarc']['status'] = dmarc_match.group(1)

    # DMARC domain
    dmarc_domain_match = re.search(r'header\.from=([\w.-]+)', auth_lower)
    if dmarc_domain_match:
        result['dmarc']['domain'] = dmarc_domain_match.group(1)

    return result


def lookup_domain_age(domain):
    """Tra cứu tuổi tên miền bằng python-whois (miễn phí, không cần API key)."""
    if not HAS_WHOIS or not domain:
        return {
            'sender_domain': domain,
            'domain_age_days': None,
            'created_date': None,
            'expiry_date': None,
            'registrar': None,
            'is_suspicious': False,
            'error': 'python-whois chưa cài đặt' if not HAS_WHOIS else 'Không có domain'
        }

    try:
        w = whois.whois(domain)

        # Lấy ngày tạo domain
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        # Tính tuổi domain
        age_days = None
        is_suspicious = False
        created_str = None

        if created:
            if isinstance(created, datetime):
                # Đảm bảo cả 2 datetime đều naive hoặc đều aware
                now = datetime.now()
                if created.tzinfo is not None:
                    created = created.replace(tzinfo=None)
                age_days = (now - created).days
                created_str = created.strftime('%Y-%m-%d')
                # Domain < 30 ngày = đáng ngờ
                if age_days < 30:
                    is_suspicious = True
            else:
                created_str = str(created)

        expiry_str = None
        if expiry:
            if isinstance(expiry, datetime):
                expiry_str = expiry.strftime('%Y-%m-%d')
            else:
                expiry_str = str(expiry)

        return {
            'sender_domain': domain,
            'domain_age_days': age_days,
            'created_date': created_str,
            'expiry_date': expiry_str,
            'registrar': w.registrar if hasattr(w, 'registrar') else None,
            'is_suspicious': is_suspicious,
            'error': None
        }

    except Exception as e:
        return {
            'sender_domain': domain,
            'domain_age_days': None,
            'created_date': None,
            'expiry_date': None,
            'registrar': None,
            'is_suspicious': False,
            'error': str(e)
        }


def get_root_domain(domain):
    """Lấy root domain (ví dụ: bounces.google.com → google.com)."""
    if not domain:
        return None
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def detect_anomalies(headers, authentication, domain_info):
    """Phát hiện các bất thường trong email."""
    anomalies = []

    from_domain = extract_domain(headers.get('from', ''))
    return_path_domain = extract_domain(headers.get('return_path', ''))
    reply_to_domain = extract_domain(headers.get('reply_to', ''))

    # 1. From ≠ Return-Path domain (so sánh root domain để tránh false positive cho subdomain)
    if from_domain and return_path_domain:
        from_root = get_root_domain(from_domain)
        rp_root = get_root_domain(return_path_domain)
        if from_root != rp_root:
            anomalies.append({
                'type': 'DOMAIN_MISMATCH',
                'detail': f'From domain ({from_domain}) khác Return-Path domain ({return_path_domain})',
                'severity': 'HIGH'
            })

    # 2. Reply-To ≠ From
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append({
            'type': 'REPLY_TO_MISMATCH',
            'detail': f'Reply-To ({reply_to_domain}) khác From ({from_domain})',
            'severity': 'MEDIUM'
        })

    # 3. SPF fail
    if authentication['spf']['status'] in ('fail', 'softfail'):
        anomalies.append({
            'type': 'SPF_FAIL',
            'detail': f"SPF {authentication['spf']['status']}",
            'severity': 'HIGH'
        })

    # 4. DKIM fail/none
    if authentication['dkim']['status'] in ('fail', 'none'):
        anomalies.append({
            'type': 'DKIM_FAIL',
            'detail': f"DKIM {authentication['dkim']['status']} — email không được ký xác thực",
            'severity': 'HIGH' if authentication['dkim']['status'] == 'fail' else 'MEDIUM'
        })

    # 5. DMARC fail/none
    if authentication['dmarc']['status'] in ('fail', 'none'):
        anomalies.append({
            'type': 'DMARC_FAIL',
            'detail': f"DMARC {authentication['dmarc']['status']}",
            'severity': 'HIGH' if authentication['dmarc']['status'] == 'fail' else 'MEDIUM'
        })

    # 6. Domain Age < 30 ngày
    if domain_info.get('is_suspicious'):
        age = domain_info.get('domain_age_days', 'N/A')
        anomalies.append({
            'type': 'NEW_DOMAIN',
            'detail': f"Domain {domain_info['sender_domain']} mới đăng ký {age} ngày — có thể là domain lừa đảo",
            'severity': 'CRITICAL' if (isinstance(age, int) and age < 7) else 'HIGH'
        })

    # 7. Domain không tồn tại trong WHOIS (có thể đã hết hạn hoặc giả mạo)
    whois_error = domain_info.get('error', '') or ''
    if 'No match' in whois_error or 'NOT FOUND' in whois_error.upper():
        anomalies.append({
            'type': 'DOMAIN_NOT_FOUND',
            'detail': f"Domain {domain_info['sender_domain']} không tồn tại trong WHOIS — có thể là domain giả mạo",
            'severity': 'CRITICAL'
        })

    # 8. Typosquatting / Giả mạo thương hiệu (khoảng cách Levenshtein <= 2)
    typo_match = detect_typosquatting_brand(from_domain) or detect_typosquatting_brand(domain_info.get('sender_domain', ''))
    if typo_match:
        anomalies.append({
            'type': 'TYPOSQUATTING_BRAND',
            'detail': f"Phát hiện Typosquatting giả mạo thương hiệu '{typo_match['brand'].upper()}' qua chuỗi '{typo_match['matched_token']}' (Khoảng cách Levenshtein: {typo_match['distance']}) trong domain {typo_match['domain']}",
            'severity': 'CRITICAL',
            'data': typo_match
        })

    return anomalies


COMMONLY_SPOOFED_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook',
    'instagram', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'dhl',
    'fedex', 'ups', 'adobe', 'dropbox', 'linkedin', 'twitter', 'telegram',
    'binance', 'coinbase', 'metamask', 'vietcombank', 'techcombank', 'mbbank',
    'bidv', 'agribank', 'tpbank', 'vpbank', 'acb', 'outlook', 'office365'
]


def levenshtein_distance(s1, s2):
    """Tính khoảng cách Levenshtein giữa 2 chuỗi."""
    s1, s2 = s1.lower(), s2.lower()
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = min(dp[i - 1][j - 1] + 1, dp[i][j - 1] + 1, dp[i - 1][j] + 1)
    return dp[m][n]


def detect_typosquatting_brand(domain):
    """Phát hiện thương hiệu bị giả mạo với khoảng cách Levenshtein <= 2."""
    if not domain:
        return None
    clean = re.sub(r':\d+$', '', domain.lower().strip())
    parts = clean.split('.')[:-1] if '.' in clean else [clean]
    joined_parts = '.'.join(parts)
    tokens = set(re.split(r'[-_.]', joined_parts) + [joined_parts])
    tokens = [t for t in tokens if len(t) >= 3]

    for token in tokens:
        for brand in COMMONLY_SPOOFED_BRANDS:
            if token == brand:
                continue
            if abs(len(token) - len(brand)) > 2:
                continue
            dist = levenshtein_distance(token, brand)
            if 0 < dist <= 2:
                return {
                    'brand': brand,
                    'matched_token': token,
                    'distance': dist,
                    'domain': domain
                }
    return None


def calculate_risk_score(authentication, anomalies, domain_info):
    """Tính điểm rủi ro tổng hợp (0-100+)."""
    score = 0

    # SPF
    spf_status = authentication['spf']['status']
    if spf_status == 'fail':
        score += 25
    elif spf_status == 'softfail':
        score += 15
    elif spf_status == 'none':
        score += 10

    # DKIM
    dkim_status = authentication['dkim']['status']
    if dkim_status == 'fail':
        score += 25
    elif dkim_status == 'none':
        score += 5

    # DMARC
    dmarc_status = authentication['dmarc']['status']
    if dmarc_status == 'fail':
        score += 20
    elif dmarc_status == 'none':
        score += 15

    # Domain & Typosquatting anomalies
    has_typosquat = False
    has_domain_not_found = False
    for anomaly in anomalies:
        if anomaly['type'] == 'DOMAIN_MISMATCH':
            score += 15
        elif anomaly['type'] == 'REPLY_TO_MISMATCH':
            score += 10
        elif anomaly['type'] == 'DOMAIN_NOT_FOUND':
            score += 25
            has_domain_not_found = True
        elif anomaly['type'] == 'TYPOSQUATTING_BRAND':
            score += 20
            has_typosquat = True

    # Domain Age
    age = domain_info.get('domain_age_days')
    is_new_domain = False
    if isinstance(age, int):
        if age < 7:
            score += 20
            is_new_domain = True
        elif age < 30:
            score += 12
            is_new_domain = True
        elif age < 90:
            score += 6

    # Bonus tương quan: Typosquat + DMARC/DKIM none/fail + Domain không tồn tại hoặc mới (<30 ngày)
    has_auth_none = (dmarc_status in ('none', 'fail') or dkim_status in ('none', 'fail'))
    if has_typosquat and has_auth_none and (has_domain_not_found or is_new_domain):
        score += 15

    # Xác định mức rủi ro
    if score >= 75:
        risk_level = 'HIGH'
    elif score >= 50:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return score, risk_level


def analyze_header(file_path):
    """Phân tích toàn diện header của file .eml."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            msg = email.message_from_file(f)
    except Exception as e:
        return {'error': f'Không đọc được file: {str(e)}'}

    # === 1. Bóc tách Header ===
    from_addr = msg.get('From', 'Unknown')
    return_path = msg.get('Return-Path', 'Not Found')
    reply_to = msg.get('Reply-To', '')
    x_mailer = msg.get('X-Mailer', msg.get('User-Agent', 'Not Found'))
    message_id = msg.get('Message-ID', 'Not Found')
    date = msg.get('Date', 'Not Found')

    headers = {
        'from': from_addr,
        'return_path': return_path,
        'reply_to': reply_to,
        'x_mailer': x_mailer,
        'message_id': message_id,
        'date': date,
        'received_chain': parse_received_chain(msg)
    }

    # === 2. Parse Authentication-Results ===
    auth_header = msg.get('Authentication-Results', 'Not Found')
    authentication = parse_authentication_results(auth_header)
    authentication['raw'] = auth_header

    # === 3. Domain Age Lookup ===
    sender_domain = extract_domain(from_addr)
    domain_info = lookup_domain_age(sender_domain)

    # === 4. Phát hiện bất thường ===
    anomalies = detect_anomalies(headers, authentication, domain_info)

    # === 5. Tính điểm rủi ro ===
    risk_score, risk_level = calculate_risk_score(authentication, anomalies, domain_info)

    result = {
        'file': file_path,
        'headers': headers,
        'authentication': authentication,
        'domain_analysis': domain_info,
        'anomalies': anomalies,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'analyzed_at': datetime.now().isoformat()
    }

    return result


if __name__ == '__main__':
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        result = analyze_header(file_path)
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(json.dumps({'error': 'Thiếu đường dẫn file .eml. Dùng: python header_analyzer.py <path>'}))
