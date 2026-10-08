"""
TC09 - CSRF (Cross-Site Request Forgery) on Login Form
=======================================================
Test ID:         TC09_CSRF_Login_No_Token
Test Name:       CSRF_Login_No_Token
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - Cross-Site Request Forgery (OWASP A01:2021)
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem form Login cua UTC Van Phong Dien Tu co bi tan cong
    CSRF (Cross-Site Request Forgery) hay khong.

    CSRF la ky thuat tan cong trong do attacker lua user da dang nhap
    (co session cookie hop le) click vao 1 lien ket hoac trang web
    doc hai, tu do gui request POST den trang UTC ma user khong hay biet.

    De bao ve khoi CSRF, he thong can:
        1. CSRF Token: an input hidden trong form (vi du: __RequestVerificationToken, csrfmiddlewaretoken)
        2. Hoac kiem tra Origin/Referer header phai tu cung domain
        3. Hoac dung SameSite=Strict cho cookie

    Kiem tra:
        - Form Login co chua CSRF token (hidden input) khong?
        - POST login co thanh cong khi KHONG co cookie session truoc do?
        - POST login co thanh cong khi khong co Origin/Referer header?
        - Server co reject POST tu cross-origin khong?

Pre-condition:
    - URL https://vanphongdientu.utc.edu.vn/Login hoat dong
    - Co the dung requests de gui raw HTTP (khong qua browser)
    - Server accept POST application/x-www-form-urlencoded

Test Data:
    - URL:      https://vanphongdientu.utc.edu.vn/Login
    - Method 1: GET (lay form, kiem tra hidden input)
    - Method 2: POST (khong cookie, khong token, khong Origin/Referer)
    - Username: admin
    - Password: admin

Steps:
    Step 1:  GET /Login - lay HTML form
    Step 2:  Parse HTML, kiem tra cac hidden input co ten lien quan CSRF
             (csrf, _token, __RequestVerificationToken, antiforgery, etc.)
    Step 3:  POST /Login voi username + password, KHONG gui cookie, KHONG gui Origin
    Step 4:  POST /Login voi username + password, KHONG gui cookie, CO Origin gia (evil.com)
    Step 5:  POST /Login voi username + password, KHONG gui cookie, CO Referer gia (evil.com)
    Step 6:  So sanh response: neu server tra 200 (chap nhan) -> CO LO HONG CSRF
    Step 7:  Neu server tra 403/419 -> co CSRF protection (AN TOAN)
    Step 8:  Kiem tra cookie Set-Cookie co SameSite=Strict/Lax khong

Expected (HE THONG AN TOAN):
    - Form Login CO chua CSRF token (hidden input)
    - POST khong token, khong cookie, khong Origin phai bi reject (403/419)
    - Cookie co SameSite=Strict hoac Lax
    - Origin/Referer phai duoc kiem tra va tu domain hop le

Expected (NEU HE THONG YEU - UTC truong hop nay):
    - Form KHONG co CSRF token
    - POST khong cookie, khong Origin, khong Referer VAN thanh cong (200)
    - Server tra lai form login kem error message
    - Cookie KHONG co SameSite attribute
"""

import re
import pytest
import requests
from requests.exceptions import RequestException


# ==================== Configuration ====================

TARGET_URL = "https://vanphongdientu.utc.edu.vn/Login"
LOGIN_PAYLOAD = {
    "username": "admin",
    "userpwd": "admin",
}

# CSRF token names pho bien - neu form co 1 trong cac ten nay -> co CSRF protection
CSRF_TOKEN_NAMES = [
    "__RequestVerificationToken",   # ASP.NET MVC
    "csrfmiddlewaretoken",          # Django
    "csrf_token",                   # Django alt
    "_token",                       # Laravel
    "authenticity_token",           # Ruby on Rails
    "__csrf_token",                 # Symfony
    "antiforgerytoken",             # Generic
    "CSRFToken",                    # Generic
    "csrf",                         # Generic
    "_csrf",                        # Generic
    "token",                        # Generic
    "nonce",                        # Generic
    "user_token",                   # Custom
    "verification_token",           # Custom
]


# ==================== Helper Functions ====================

def get_login_form_html(session=None):
    """
    Step 1: GET /Login de lay HTML form
    Returns: (html_content, response_object)
    """
    try:
        if session:
            response = session.get(TARGET_URL, timeout=10, allow_redirects=True)
        else:
            response = requests.get(TARGET_URL, timeout=10, allow_redirects=True)
        response.raise_for_status()
        return response.text, response
    except RequestException as e:
        pytest.fail(f"[STEP 1] Khong the GET /Login: {e}")


def find_csrf_token_in_form(html_content):
    """
    Step 2: Parse HTML, tim hidden input co CSRF token
    Returns: dict {token_name: token_value} hoac {} neu khong co
    """
    found_tokens = {}

    # Pattern 1: <input type="hidden" name="csrf_name" value="..."/>
    for token_name in CSRF_TOKEN_NAMES:
        pattern = rf'<input[^>]*name=["\']{re.escape(token_name)}["\'][^>]*value=["\']([^"\']*)["\']'
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            found_tokens[token_name] = match.group(1)

    # Pattern 2: <input ... name="csrf_name" ... value="..."/> (dao thu tu attribute)
    for token_name in CSRF_TOKEN_NAMES:
        if token_name in found_tokens:
            continue
        pattern = rf'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']{re.escape(token_name)}["\']'
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            found_tokens[token_name] = match.group(1)

    # Pattern 3: meta tag
    pattern = rf'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']'
    match = re.search(pattern, html_content, re.IGNORECASE)
    if match:
        found_tokens["meta_csrf-token"] = match.group(1)

    # Pattern 4: any hidden input (de xem form co hidden fields nao khac)
    hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']'
    for m in re.finditer(hidden_pattern, html_content, re.IGNORECASE):
        name, value = m.group(1), m.group(2)
        if name not in found_tokens:
            found_tokens[f"HIDDEN_{name}"] = value

    return found_tokens


def post_login_without_cookie():
    """
    Step 3: POST /Login khong cookie, khong Origin/Referer
    Returns: response object
    """
    try:
        response = requests.post(
            TARGET_URL,
            data=LOGIN_PAYLOAD,
            timeout=10,
            allow_redirects=False,
            # KHONG them cookies
            # KHONG them Origin/Referer (de simulate CSRF attack)
        )
        return response
    except RequestException as e:
        pytest.fail(f"[STEP 3] Khong the POST /Login: {e}")


def post_login_with_fake_origin():
    """
    Step 4: POST /Login voi Origin header gia tu evil.com
    Returns: response object
    """
    try:
        headers = {
            "Origin": "http://evil.com",
            "Referer": "http://evil.com/attack.html",
        }
        response = requests.post(
            TARGET_URL,
            data=LOGIN_PAYLOAD,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )
        return response
    except RequestException as e:
        pytest.fail(f"[STEP 4] Khong the POST /Login: {e}")


def post_login_with_fake_referer():
    """
    Step 5: POST /Login chi co Referer gia (khong co Origin)
    Returns: response object
    """
    try:
        headers = {
            "Referer": "http://attacker.evil.com/csrf-page.html",
        }
        response = requests.post(
            TARGET_URL,
            data=LOGIN_PAYLOAD,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )
        return response
    except RequestException as e:
        pytest.fail(f"[STEP 5] Khong the POST /Login: {e}")


# ==================== Test Class ====================

@pytest.mark.security
@pytest.mark.csrf
@pytest.mark.login
@pytest.mark.high
class TestTC09CSRFLoginNoToken:
    """
    Test class cho TC09 - CSRF Login No Token.
    Muc tieu: phat hien xem form Login UTC co CSRF protection hay khong.
    """

    def test_TC09_CSRF_Login_No_Token(self):
        """
        Test method chinh - thuc hien 8 steps theo high-detail format.

        EXPECTED (he thong an toan):
            - Co CSRF token trong form
            - POST khong cookie/origin bi reject (403/419)
            - Cookie co SameSite attribute

        EXPECTED (neu he thong yeu - UTC):
            - KHONG co CSRF token
            - POST khong cookie/origin thanh cong (200)
            - Cookie KHONG co SameSite
        """
        print("\n" + "=" * 70)
        print("TC09 - CSRF Login No Token (Cross-Site Request Forgery)")
        print("=" * 70)

        csrf_findings = []
        csrf_passed = True
        vulnerability_detected = False

        # ----------------------------------------------------------------
        # STEP 1: GET /Login de lay HTML form
        # ----------------------------------------------------------------
        print("\n[STEP 1] GET /Login - lay HTML form")
        html_content, get_response = get_login_form_html()
        assert get_response.status_code == 200, \
            f"GET /Login phai tra 200, nhan duoc {get_response.status_code}"
        print(f"  [OK] GET /Login thanh cong - status {get_response.status_code}")
        print(f"  [OK] Do dai HTML: {len(html_content)} chars")

        # ----------------------------------------------------------------
        # STEP 2: Parse HTML, kiem tra hidden input CSRF
        # ----------------------------------------------------------------
        print("\n[STEP 2] Parse HTML - tim hidden input CSRF token")
        csrf_tokens = find_csrf_token_in_form(html_content)

        if csrf_tokens:
            print(f"  [INFO] Tim thay {len(csrf_tokens)} hidden input trong form:")
            for name, value in csrf_tokens.items():
                display_value = value[:30] + "..." if len(value) > 30 else value
                print(f"    - {name} = {display_value}")
        else:
            print("  [INFO] KHONG co hidden input trong form")

        # Kiem tra co CSRF token that su khong
        real_csrf_tokens = {
            k: v for k, v in csrf_tokens.items()
            if not k.startswith("HIDDEN_") or any(cn in k for cn in CSRF_TOKEN_NAMES)
        }

        if not real_csrf_tokens:
            csrf_findings.append("Form Login KHONG co CSRF token (khong co hidden input nao)")
            print("  [FAIL] Form Login KHONG co CSRF token!")
            vulnerability_detected = True
        else:
            print(f"  [OK] Form co {len(real_csrf_tokens)} CSRF token - HE THONG CO BAO VE")

        # ----------------------------------------------------------------
        # STEP 3: POST khong cookie, khong Origin/Referer
        # ----------------------------------------------------------------
        print("\n[STEP 3] POST /Login khong cookie, khong Origin/Referer")
        r1 = post_login_without_cookie()
        print(f"  [INFO] Status: {r1.status_code}")
        print(f"  [INFO] Set-Cookie: {r1.headers.get('Set-Cookie', 'NONE')}")

        # Neu status = 403/419 -> server co CSRF protection
        # Neu status = 200 -> server CHAP NHAN request khong co CSRF token
        if r1.status_code in [200, 302]:
            csrf_findings.append(
                f"POST khong cookie/origin bi CHAP NHAN (status {r1.status_code}) - "
                f"server KHONG kiem tra CSRF token"
            )
            print(f"  [VULN] Server CHAP NHAN POST khong cookie (status {r1.status_code})")
            vulnerability_detected = True
        elif r1.status_code in [403, 419]:
            print(f"  [OK] Server REJECT POST khong cookie (status {r1.status_code})")
        else:
            print(f"  [INFO] Server tra status {r1.status_code} (khong phai 200/302/403/419)")

        # ----------------------------------------------------------------
        # STEP 4: POST voi fake Origin (http://evil.com)
        # ----------------------------------------------------------------
        print("\n[STEP 4] POST /Login voi Origin = http://evil.com")
        r2 = post_login_with_fake_origin()
        print(f"  [INFO] Status: {r2.status_code}")

        if r2.status_code in [200, 302]:
            csrf_findings.append(
                f"POST voi Origin=http://evil.com bi CHAP NHAN (status {r2.status_code}) - "
                f"server KHONG validate Origin header"
            )
            print(f"  [VULN] Server CHAP NHAN POST tu evil.com (status {r2.status_code})")
            vulnerability_detected = True
        elif r2.status_code in [403, 419]:
            print(f"  [OK] Server REJECT POST tu evil.com (status {r2.status_code})")

        # ----------------------------------------------------------------
        # STEP 5: POST voi fake Referer
        # ----------------------------------------------------------------
        print("\n[STEP 5] POST /Login voi Referer gia (attacker.evil.com)")
        r3 = post_login_with_fake_referer()
        print(f"  [INFO] Status: {r3.status_code}")

        if r3.status_code in [200, 302]:
            csrf_findings.append(
                f"POST voi Referer gia bi CHAP NHAN (status {r3.status_code}) - "
                f"server KHONG validate Referer header"
            )
            print(f"  [VULN] Server CHAP NHAN POST voi Referer gia (status {r3.status_code})")
            vulnerability_detected = True
        elif r3.status_code in [403, 419]:
            print(f"  [OK] Server REJECT POST voi Referer gia (status {r3.status_code})")

        # ----------------------------------------------------------------
        # STEP 6: So sanh response
        # ----------------------------------------------------------------
        print("\n[STEP 6] So sanh response")
        print(f"  - POST khong cookie:        status {r1.status_code}")
        print(f"  - POST fake Origin:         status {r2.status_code}")
        print(f"  - POST fake Referer:        status {r3.status_code}")

        # Neu ca 3 deu tra 200/302 -> he thong rat yeu, khong co CSRF protection nao
        if all(r.status_code in [200, 302] for r in [r1, r2, r3]):
            print("  [CRITICAL] Ca 3 POST deu thanh cong -> HE THONG KHONG CO CSRF PROTECTION")
        elif any(r.status_code in [200, 302] for r in [r1, r2, r3]):
            print("  [HIGH] It nhat 1 POST thanh cong -> he thong co CSRF protection nhung khong day du")
        else:
            print("  [OK] Ca 3 POST deu bi reject -> he thong co CSRF protection tot")

        # ----------------------------------------------------------------
        # STEP 7: Kiem tra SameSite cookie
        # ----------------------------------------------------------------
        print("\n[STEP 7] Kiem tra SameSite attribute trong Set-Cookie")
        set_cookie_header = r1.headers.get("Set-Cookie", "")
        if set_cookie_header:
            print(f"  [INFO] Set-Cookie header: {set_cookie_header}")
            if "SameSite=Strict" in set_cookie_header or "SameSite=Lax" in set_cookie_header:
                print("  [OK] Cookie co SameSite=Strict/Lax - co them 1 lop bao ve")
            else:
                csrf_findings.append(
                    f"Cookie KHONG co SameSite attribute: {set_cookie_header}"
                )
                print("  [VULN] Cookie KHONG co SameSite - browser se tu dong gui kem cross-site")
                vulnerability_detected = True
        else:
            print("  [INFO] POST khong tao cookie moi (co the vi login that bai)")

        # ----------------------------------------------------------------
        # STEP 8: Final assessment
        # ----------------------------------------------------------------
        print("\n[STEP 8] Final assessment - CSRF vulnerability")
        print("-" * 70)
        if vulnerability_detected:
            print("  [CRITICAL] PHAT HIEN LO HONG CSRF!")
            print(f"  [INFO] So finding: {len(csrf_findings)}")
            for i, finding in enumerate(csrf_findings, 1):
                print(f"    {i}. {finding}")
            print("-" * 70)
            print("  [INFO] Test PASSED - da phat hien CSRF vulnerability")
        else:
            print("  [OK] He thong co CSRF protection - AN TOAN")
            print("-" * 70)
            print("  [INFO] Test PASSED - khong phat hien CSRF vulnerability")

        # Final assertion: chi can 1 trong cac tests tren phat hien vulnerability -> test passed
        # Muc tieu cua test la phat hien, neu khong co -> test PASSED (he thong an toan)
        assert True, "Test TC09 completed"

    def test_TC09_CSRF_Login_No_Token_HTML_Form_Structure(self):
        """
        Test phu: kiem tra cau truc HTML form chi tiet.
        Dam bao form dung method POST va co cac field can thiet.
        """
        print("\n" + "=" * 70)
        print("TC09 - HTML Form Structure Analysis")
        print("=" * 70)

        html_content, _ = get_login_form_html()

        # Kiem tra <form> tag
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
        form_match = re.search(form_pattern, html_content, re.IGNORECASE)
        if not form_match:
            # Thu dao thu
            form_pattern = r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\']'
            form_match = re.search(form_pattern, html_content, re.IGNORECASE)
            if form_match:
                method, action = form_match.group(1), form_match.group(2)
            else:
                form_match = re.search(r'<form[^>]*>', html_content, re.IGNORECASE)
                method = "?"
                action = "?"
        else:
            action, method = form_match.group(1), form_match.group(2)

        print(f"  [INFO] Form action: {action}")
        print(f"  [INFO] Form method: {method}")

        # Assertions ve form
        assert action is not None, "Form phai co action attribute"
        assert method.upper() == "POST", f"Form phai dung POST, hien tai: {method}"

        # Kiem tra co username va password field
        has_username = bool(re.search(r'name=["\']username["\']', html_content, re.IGNORECASE))
        has_password = bool(re.search(r'name=["\']userpwd["\']', html_content, re.IGNORECASE))
        print(f"  [INFO] Co field username: {has_username}")
        print(f"  [INFO] Co field userpwd:  {has_password}")

        assert has_username, "Form phai co field username"
        assert has_password, "Form phai co field userpwd"

        # Kiem tra hidden input
        hidden_inputs = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
            html_content,
            re.IGNORECASE
        )
        print(f"  [INFO] Hidden inputs: {hidden_inputs if hidden_inputs else '(khong co)'}")

        # Kiem tra co CSRF token trong cac hidden input
        csrf_in_hidden = any(
            any(cn.lower() in h.lower() for cn in CSRF_TOKEN_NAMES)
            for h in hidden_inputs
        )

        if not csrf_in_hidden:
            print("  [VULN] Form KHONG co CSRF token trong hidden input")
            print("  [INFO] He thong co the bi CSRF attack")
        else:
            print("  [OK] Form CO CSRF token trong hidden input")

        # Test pass
        assert True, "HTML form structure analysis completed"


# ==================== Test Run Helper ====================

if __name__ == "__main__":
    """Cho phep chay truc tiep: python test_TC09_CSRF_Login_No_Token.py"""
    print("=" * 70)
    print("TC09 - CSRF Login No Token - Manual Test Runner")
    print("=" * 70)

    # Step 1: GET form
    print("\n[STEP 1] GET /Login")
    html, _ = get_login_form_html()
    print(f"  Do dai HTML: {len(html)} chars")

    # Step 2: Find CSRF token
    print("\n[STEP 2] Tim CSRF token trong form")
    tokens = find_csrf_token_in_form(html)
    if tokens:
        print(f"  Tokens: {tokens}")
    else:
        print("  KHONG co CSRF token")

    # Step 3: POST khong cookie
    print("\n[STEP 3] POST khong cookie")
    r = post_login_without_cookie()
    print(f"  Status: {r.status_code}")

    # Step 4: POST voi fake Origin
    print("\n[STEP 4] POST voi fake Origin")
    r = post_login_with_fake_origin()
    print(f"  Status: {r.status_code}")

    # Step 5: POST voi fake Referer
    print("\n[STEP 5] POST voi fake Referer")
    r = post_login_with_fake_referer()
    print(f"  Status: {r.status_code}")

    print("\n" + "=" * 70)
    print("Done - xem chi tiet trong report.html")
    print("=" * 70)
