"""
Mini SOAR - URL Scanner & Redirect Chain Tracer
Bước 4: Truy vết URL, phân tích Redirect Chain và gọi URLScan.io API

An toàn:
- TUYỆT ĐỐI KHÔNG dùng trình duyệt thật để click link.
- Dùng Python requests (không chạy JS) để truy vết redirect chain.
- Dùng URLScan.io API (sandbox trình duyệt ảo) để chụp screenshot + phân tích.

Chức năng:
1. Trích xuất URL từ file .eml (text + HTML body)
2. Truy vết Redirect Chain an toàn (HTTP HEAD, không thực thi JS)
3. Gọi URLScan.io API: submit → chờ kết quả → lấy screenshot + verdicts
4. Tổng hợp phân tích rủi ro cho từng URL
"""

import sys
import os
import email
import re
import json
import time
import requests
from datetime import datetime
from urllib.parse import urlparse

# Fix encoding Windows
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

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

# =============================================
# 1. TRÍCH XUẤT URL TỪ EMAIL
# =============================================

def extract_urls_from_eml(file_path):
    """Trích xuất tất cả URL từ file .eml (cả text/plain và text/html)."""
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f)
    except Exception as e:
        return [], str(e)

    all_text = ""
    all_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get('Content-Disposition', ''))
            if 'attachment' in disp:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                decoded = payload.decode('utf-8', errors='replace')
                if ctype == 'text/plain':
                    all_text += decoded + "\n"
                elif ctype == 'text/html':
                    all_html += decoded + "\n"
            except Exception:
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode('utf-8', errors='replace')
            if msg.get_content_type() == 'text/html':
                all_html = decoded
            else:
                all_text = decoded

    # Cào URL từ text thuần
    url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    urls_from_text = set(re.findall(url_pattern, all_text))

    # Cào URL từ href trong HTML
    urls_from_html = set()
    if all_html:
        if HAS_BS4:
            soup = BeautifulSoup(all_html, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                if href.startswith('http'):
                    urls_from_html.add(href)
            # Tìm thêm URL ẩn trong text HTML
            urls_from_html.update(re.findall(url_pattern, all_html))
        else:
            urls_from_html = set(re.findall(url_pattern, all_html))

    all_urls = list(urls_from_text | urls_from_html)

    # Làm sạch: bỏ dấu ) . , ; cuối URL
    cleaned = []
    for u in all_urls:
        u = u.rstrip('.,;:)>]')
        if len(u) > 10:
            cleaned.append(u)

    return list(set(cleaned)), None


# =============================================
# 2. TRUY VẾT REDIRECT CHAIN AN TOÀN
# =============================================

def trace_redirect_chain(url, max_redirects=10, timeout=8):
    """
    Truy vết chuỗi redirect an toàn bằng Python requests (không chạy JS).
    Dùng HEAD request trước, fallback GET nếu server không hỗ trợ HEAD.
    """
    chain = []
    current_url = url
    visited = set()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for i in range(max_redirects):
        if current_url in visited:
            chain.append({
                'hop': i + 1,
                'url': current_url,
                'status': 'LOOP_DETECTED',
                'note': 'Phát hiện vòng lặp redirect'
            })
            break
        visited.add(current_url)

        try:
            # Thử HEAD trước (nhanh hơn, an toàn hơn)
            resp = requests.head(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers=headers,
                verify=False  # Bỏ qua SSL errors cho domain lạ
            )
        except requests.exceptions.SSLError:
            chain.append({
                'hop': i + 1,
                'url': current_url,
                'status': 'SSL_ERROR',
                'note': 'Lỗi SSL - chứng chỉ không hợp lệ (dấu hiệu đáng ngờ)'
            })
            break
        except requests.exceptions.ConnectionError:
            chain.append({
                'hop': i + 1,
                'url': current_url,
                'status': 'CONNECTION_FAILED',
                'note': 'Không thể kết nối - domain có thể đã bị gỡ hoặc không tồn tại'
            })
            break
        except requests.exceptions.Timeout:
            chain.append({
                'hop': i + 1,
                'url': current_url,
                'status': 'TIMEOUT',
                'note': f'Quá thời gian chờ ({timeout}s)'
            })
            break
        except Exception as e:
            chain.append({
                'hop': i + 1,
                'url': current_url,
                'status': 'ERROR',
                'note': str(e)[:200]
            })
            break

        hop_info = {
            'hop': i + 1,
            'url': current_url,
            'status_code': resp.status_code,
            'server': resp.headers.get('Server', 'Unknown'),
            'content_type': resp.headers.get('Content-Type', 'Unknown')
        }

        # Kiểm tra redirect (3xx)
        if 300 <= resp.status_code < 400:
            next_url = resp.headers.get('Location', '')
            if next_url:
                # Xử lý relative redirect
                if next_url.startswith('/'):
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                hop_info['redirect_to'] = next_url
                hop_info['redirect_type'] = 'PERMANENT' if resp.status_code == 301 else 'TEMPORARY'
                chain.append(hop_info)
                current_url = next_url
                continue
            else:
                hop_info['note'] = 'Redirect không có Location header'
                chain.append(hop_info)
                break
        else:
            # Đích cuối cùng (200 hoặc lỗi 4xx/5xx)
            hop_info['is_final'] = True
            chain.append(hop_info)
            break

    # Phân tích chuỗi redirect
    final_url = chain[-1]['url'] if chain else url
    total_redirects = sum(1 for h in chain if h.get('redirect_to'))

    # So sánh domain đầu vs cuối
    initial_domain = urlparse(url).netloc
    final_domain = urlparse(final_url).netloc
    domain_changed = initial_domain.lower() != final_domain.lower()

    return {
        'original_url': url,
        'final_url': final_url,
        'total_redirects': total_redirects,
        'domain_changed': domain_changed,
        'initial_domain': initial_domain,
        'final_domain': final_domain,
        'chain': chain,
        'suspicious': domain_changed or total_redirects > 3
    }


# =============================================
# 3. URLSCAN.IO API (SANDBOX TRÌNH DUYỆT ẢO)
# =============================================

def submit_to_urlscan(url, api_key=None):
    """
    Submit URL lên URLScan.io để quét bằng trình duyệt ảo.
    Free tier: 100 scans/ngày (public), không cần API key cho basic.
    Trả về: screenshot URL, verdicts, page info.
    """
    if not api_key:
        api_key = os.getenv('URLSCAN_API_KEY', '')

    if not api_key:
        return {
            'status': 'skipped',
            'reason': 'Không có URLSCAN_API_KEY trong .env (tùy chọn, miễn phí tại urlscan.io/user/signup)',
            'url': url
        }

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json'
    }

    payload = {
        'url': url,
        'visibility': 'public'  # public = miễn phí
    }

    try:
        # Bước 1: Submit URL để quét
        submit_resp = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=payload,
            timeout=15
        )

        if submit_resp.status_code == 429:
            return {'status': 'rate_limited', 'reason': 'Đã hết quota URLScan.io ngày hôm nay', 'url': url}

        if submit_resp.status_code != 200:
            return {'status': 'error', 'reason': f'HTTP {submit_resp.status_code}: {submit_resp.text[:200]}', 'url': url}

        submit_data = submit_resp.json()
        scan_uuid = submit_data.get('uuid')
        result_url = submit_data.get('api', f'https://urlscan.io/api/v1/result/{scan_uuid}/')

        if not scan_uuid:
            return {'status': 'error', 'reason': 'Không nhận được UUID từ URLScan', 'url': url}

        # Bước 2: Chờ kết quả (polling, tối đa 30s)
        for attempt in range(6):
            time.sleep(5)
            try:
                result_resp = requests.get(result_url, timeout=10)
                if result_resp.status_code == 200:
                    result_data = result_resp.json()

                    # Trích xuất thông tin quan trọng
                    verdicts = result_data.get('verdicts', {})
                    page = result_data.get('page', {})
                    lists = result_data.get('lists', {})
                    task = result_data.get('task', {})
                    stats = result_data.get('stats', {})

                    screenshot_url = f"https://urlscan.io/screenshots/{scan_uuid}.png"

                    return {
                        'status': 'success',
                        'url': url,
                        'scan_uuid': scan_uuid,
                        'scan_url': f'https://urlscan.io/result/{scan_uuid}/',
                        'screenshot_url': screenshot_url,
                        'page': {
                            'title': page.get('title', 'N/A'),
                            'server': page.get('server', 'N/A'),
                            'ip': page.get('ip', 'N/A'),
                            'country': page.get('country', 'N/A'),
                            'status_code': page.get('status', 'N/A')
                        },
                        'verdicts': {
                            'overall_malicious': verdicts.get('overall', {}).get('malicious', False),
                            'overall_score': verdicts.get('overall', {}).get('score', 0),
                            'engines': verdicts.get('engines', {}),
                            'community': verdicts.get('community', {})
                        },
                        'threat_lists': lists.get('urls', [])[:5],
                        'stats': {
                            'requests': stats.get('uniqCountries', 0),
                            'ips': stats.get('uniqIPs', 0)
                        }
                    }
                elif result_resp.status_code == 404:
                    continue  # Chưa có kết quả, chờ tiếp
            except Exception:
                continue

        return {
            'status': 'pending',
            'reason': 'URLScan.io đang xử lý, kết quả chưa sẵn sàng sau 30s',
            'url': url,
            'scan_uuid': scan_uuid,
            'scan_url': f'https://urlscan.io/result/{scan_uuid}/'
        }

    except Exception as e:
        return {'status': 'error', 'reason': str(e)[:300], 'url': url}


# =============================================
# 4. TỔNG HỢP PHÂN TÍCH RỦI RO URL
# =============================================

def assess_url_risk(url, redirect_result, urlscan_result=None):
    """Đánh giá mức độ rủi ro của một URL dựa trên redirect chain + URLScan."""
    score = 0
    flags = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # ---- Phân tích domain ----
    # IP thay vì domain name
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 25
        flags.append('🔴 URL sử dụng địa chỉ IP thay vì tên miền')

    # Domain dài bất thường
    if len(domain) > 40:
        score += 10
        flags.append('🟡 Tên miền dài bất thường')

    # Chứa từ khóa nhạy cảm
    suspicious_words = ['login', 'verify', 'secure', 'update', 'account', 'banking', 'paypal', 'signin']
    for word in suspicious_words:
        if word in domain:
            score += 15
            flags.append(f'🔴 Domain chứa từ khóa nhạy cảm: "{word}"')
            break

    # Dùng HTTP thay vì HTTPS
    if parsed.scheme == 'http':
        score += 10
        flags.append('🟡 Sử dụng HTTP (không mã hóa)')

    # ---- Phân tích Redirect Chain ----
    if redirect_result.get('domain_changed'):
        initial_d = redirect_result.get('initial_domain', '').lower()
        final_d = redirect_result.get('final_domain', '').lower()
        
        initial_root = '.'.join(initial_d.split('.')[-2:]) if '.' in initial_d else initial_d
        final_root = '.'.join(final_d.split('.')[-2:]) if '.' in final_d else final_d
        
        is_same_root = (initial_root == final_root) and bool(initial_root)
        is_google_eco = any(g in initial_d for g in ['google.', 'googleapis.']) and any(g in final_d for g in ['google.', 'googleapis.'])
        is_ms_eco = any(m in initial_d for m in ['microsoft.', 'office.', 'live.', 'bing.']) and any(m in final_d for m in ['microsoft.', 'office.', 'live.', 'bing.'])

        if is_same_root or is_google_eco or is_ms_eco:
            flags.append(f"ℹ️ Chuyển hướng nội bộ dịch vụ chính thức: {redirect_result['initial_domain']} → {redirect_result['final_domain']}")
        else:
            score += 20
            flags.append(f"🔴 Domain thay đổi sau redirect: {redirect_result['initial_domain']} → {redirect_result['final_domain']}")

    if redirect_result.get('total_redirects', 0) > 3:
        score += 15
        flags.append(f"🟡 Nhiều redirect bất thường ({redirect_result['total_redirects']} lần)")

    # Kiểm tra lỗi trong chain
    for hop in redirect_result.get('chain', []):
        status = hop.get('status', '')
        if status == 'SSL_ERROR':
            score += 20
            flags.append('🔴 SSL Error - chứng chỉ không hợp lệ')
        elif status == 'CONNECTION_FAILED':
            score += 10
            flags.append('🟡 Không thể kết nối tới URL')
        elif status == 'LOOP_DETECTED':
            score += 15
            flags.append('🔴 Phát hiện vòng lặp redirect')

    # ---- URLScan.io Verdicts ----
    if urlscan_result and urlscan_result.get('status') == 'success':
        v = urlscan_result.get('verdicts', {})
        if v.get('overall_malicious'):
            score += 40
            flags.append('🚨 URLScan.io đánh giá: MALICIOUS')
        overall_score = v.get('overall_score', 0)
        if overall_score > 0:
            score += min(overall_score * 5, 30)
            flags.append(f'🔴 URLScan.io threat score: {overall_score}')

    # Tổng hợp mức rủi ro
    if score >= 50:
        risk_level = 'HIGH'
    elif score >= 25:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return {
        'risk_score': min(score, 100),
        'risk_level': risk_level,
        'flags': flags
    }


# =============================================
# 5. ĐIỀU PHỐI CHÍNH
# =============================================

def analyze_urls(file_path):
    """Phân tích tất cả URL trong email: redirect chain + URLScan + risk assessment."""
    urls, error = extract_urls_from_eml(file_path)
    if error:
        return {'error': f'Không đọc được file .eml: {error}'}

    if not urls:
        return {
            'file': file_path,
            'total_urls': 0,
            'urls': [],
            'summary': 'Không tìm thấy URL nào trong email.',
            'analyzed_at': datetime.now().isoformat()
        }

    results = []
    has_urlscan_key = bool(os.getenv('URLSCAN_API_KEY', ''))

    urlscan_count = 0
    max_urlscan_per_email = 2

    for url in urls:
        url_result = {
            'url': url,
            'domain': urlparse(url).netloc,
            'scheme': urlparse(url).scheme
        }

        # Truy vết redirect chain (luôn chạy, an toàn, nhanh)
        redirect = trace_redirect_chain(url)
        url_result['redirect_chain'] = redirect

        # URLScan.io (Sandbox trình duyệt ảo)
        urlscan = None
        if has_urlscan_key:
            # Ưu tiên URL nghi vấn hoặc quét tối đa 2 URL đầu để giữ tốc độ nhanh
            is_popular_safe = any(url_result['domain'].endswith(d) for d in ['google.com', 'gstatic.com', 'youtube.com'])
            if urlscan_count < max_urlscan_per_email and not is_popular_safe:
                urlscan = submit_to_urlscan(url)
                url_result['urlscan'] = urlscan
                urlscan_count += 1
            elif is_popular_safe:
                url_result['urlscan'] = {
                    'status': 'skipped',
                    'reason': f"Domain an toàn phổ biến ({url_result['domain']}), bỏ qua quét Sandbox để tiết kiệm quota"
                }
            else:
                url_result['urlscan'] = {
                    'status': 'skipped',
                    'reason': f"Đã quét đủ {max_urlscan_per_email} URL chính trong email"
                }
        else:
            url_result['urlscan'] = {
                'status': 'skipped',
                'reason': 'Chưa cấu hình URLSCAN_API_KEY trong .env'
            }

        # Đánh giá rủi ro
        risk = assess_url_risk(url, redirect, urlscan)
        url_result['risk'] = risk

        results.append(url_result)

    # Tổng hợp
    high_risk = sum(1 for r in results if r['risk']['risk_level'] == 'HIGH')
    medium_risk = sum(1 for r in results if r['risk']['risk_level'] == 'MEDIUM')

    return {
        'file': file_path,
        'total_urls': len(results),
        'high_risk_count': high_risk,
        'medium_risk_count': medium_risk,
        'urls': results,
        'overall_verdict': 'DANGEROUS' if high_risk > 0 else 'CAUTION' if medium_risk > 0 else 'CLEAN',
        'analyzed_at': datetime.now().isoformat()
    }


if __name__ == '__main__':
    # Tắt cảnh báo SSL verify=False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(sys.argv) > 1:
        result = analyze_urls(sys.argv[1])
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(json.dumps({'error': 'Thiếu đường dẫn file .eml. Dùng: python url_scanner.py <path>'}))
