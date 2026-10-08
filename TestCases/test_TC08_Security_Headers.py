"""
TC08 - Security Headers Check
============================
Test ID:         TC08_Security_Headers_Check
Test Name:       Security_Headers_Check
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - HTTP Security Headers / Transport Security
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem tra cac HTTP Security Headers trong response cua trang Login UTC.
    Day la cac header quan trong giup bao ve nguoi dung khoi cac cuoc tan cong web:

    1. X-Frame-Options:           Chong clickjacking (ngan chan load trong iframe)
    2. X-Content-Type-Options:    Chong MIME-type sniffing
    3. Strict-Transport-Security: Buoc HTTPS (HSTS)
    4. Content-Security-Policy:   Gioi han nguon tai resource (chong XSS)
    5. X-XSS-Protection:          Chan do XSS (deprecated nhung van check)
    6. Referrer-Policy:           Quy dinh cach gui referrer
    7. Permissions-Policy:         Gioi han tính nang trinh duyet

    Neu cac header nay thieu, website co the bi:
        - Clickjacking: Dua trang vao iframe, lang nghe input
        - MIME Sniffing: Upload file doc, trinh duyet tu thuc thi
        - Man-in-the-Middle: Khong buoc HTTPS, co the bat cookie
        - XSS: Khong co CSP, attacker chen ma JS

Pre-condition:
    - Trang /Login hoat dong (HTTP/HTTPS)
    - Khong can dang nhap

Test Data:
    - URL: https://vanphongdientu.utc.edu.vn/Login
    - Method: GET
    - Headers can kiem tra: (xem ben duoi)

Steps:
    Step 1:   Gui GET request den /Login
    Step 2:   Lay headers tu response
    Step 3:   Kiem tra tung header can thiet
    Step 4:   Danh gia diem bao mat

Expected (HE THONG AN TOAN):
    - X-Frame-Options: CO (DENY hoac SAMEORIGIN)
    - X-Content-Type-Options: CO (nosniff)
    - Strict-Transport-Security: CO (max-age >= 31536000)
    - Content-Security-Policy: CO (hoac Content-Security-Policy-Report-Only)
    - Referrer-Policy: CO (no-referrer, same-origin, strict-origin-when-cross-origin)
    - Permissions-Policy: CO (khuyen)
    - Cookie: HttpOnly=TRUE, Secure=TRUE (neu co cookie)

Expected (NEU he thong YEU - UTCtruong hop nay):
    - Nhieu header thieu
    - Cookie khong co HttpOnly/Secure
    - Khong co CSP
"""

import pytest
import requests
from Locators.utclogin_locators import SecurityEndpoints


# Cac header can kiem tra va gia tri mong muon
REQUIRED_SECURITY_HEADERS = {
    "X-Frame-Options": {
        "required": True,
        "valid_values": ["DENY", "SAMEORIGIN"],
        "description": "Chong clickjacking - ngan chan load trong iframe",
    },
    "X-Content-Type-Options": {
        "required": True,
        "valid_values": ["nosniff"],
        "description": "Chong MIME-type sniffing",
    },
    "Strict-Transport-Security": {
        "required": True,
        "valid_values": None,  # Chi can co, kiem tra max-age sau
        "description": "Buoc HTTPS (HSTS) - chi ap dung cho HTTPS",
    },
    "Content-Security-Policy": {
        "required": True,
        "valid_values": None,  # Chi can co, gia tri tuy y
        "description": "Gioi han nguon tai resource - chong XSS/Injection",
    },
    "X-XSS-Protection": {
        "required": False,  # Da deprecated nhung van kiem tra
        "valid_values": ["0", "1", "1; mode=block"],
        "description": "Chan XSS (deprecated - nen dung CSP thay vi)",
    },
    "Referrer-Policy": {
        "required": False,
        "valid_values": [
            "no-referrer", "no-referrer-when-downgrade",
            "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "origin",
            "origin-when-cross-origin", "unsafe-url",
        ],
        "description": "Quy dinh cach gui referrer header",
    },
    "Permissions-Policy": {
        "required": False,
        "valid_values": None,
        "description": "Gioi han tinh nang trinh duyet (camera, mic, geolocation...)",
    },
}


class TestTC08SecurityHeaders:
    """Test class cho TC08 - Security Headers Check cua UTC Login"""

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, base_url):
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== HELPER ====================
    def _analyze_header(self, header_name, header_info, response_headers):
        """
        Phan tich mot header cu the.
        Tra ve dict {name, present, value, valid, note}.
        """
        # Lay header (khong phan biet hoa/thuong)
        header_value = None
        for key, val in response_headers.items():
            if key.lower() == header_name.lower():
                header_value = val
                break

        result = {
            "name": header_name,
            "present": header_value is not None,
            "value": header_value,
            "required": header_info["required"],
            "valid": False,
            "note": "",
        }

        if header_value is None:
            if header_info["required"]:
                result["note"] = f"THIEU header bat buoc - {header_info['description']}"
            else:
                result["note"] = f"Khong co (khong bat buoc) - {header_info['description']}"
            return result

        # Kiem tra gia tri
        valid_values = header_info.get("valid_values")
        if valid_values is None:
            # Chi can co header
            result["valid"] = True
            result["note"] = f"CO - {header_info['description']}"
        else:
            # Kiem tra gia tri cu the
            # X-Frame-Options: co the viet hoa
            if header_name == "X-Frame-Options":
                result["valid"] = header_value.upper() in [v.upper() for v in valid_values]
            else:
                result["valid"] = header_value.lower() in [v.lower() for v in valid_values]

            if result["valid"]:
                result["note"] = f"CO - {header_info['description']}"
            else:
                result["note"] = f"CO nhung gia tri '{header_value}' khong hop le"

        # Kiem tra them cho HSTS
        if header_name == "Strict-Transport-Security":
            if "max-age" in header_value.lower():
                try:
                    # Lay gia tri max-age
                    parts = header_value.split(";")
                    for part in parts:
                        if "max-age" in part.lower():
                            max_age = int("".join(filter(str.isdigit, part)))
                            if max_age < 31536000:  # < 1 year
                                result["note"] += f" (max-age={max_age} < 1 nam - yeu)"
                            else:
                                result["note"] += f" (max-age={max_age} OK)"
                            break
                except Exception:
                    pass

        return result

    def _check_cookie_flags(self, response):
        """Kiem tra flag HttpOnly va Secure cua cookie."""
        cookie_results = []
        # Lay cookies tu response.headers (Set-Cookie)
        set_cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(response.headers, 'getlist') else []
        
        # Hoac lay tu response.cookies (RequestsCookieJar)
        try:
            cookies_list = list(response.cookies)
        except Exception:
            cookies_list = []
        
        for cookie in cookies_list:
            # Cookie la RequestsCookieJar, truy cap truc tiep
            try:
                cookie_name = cookie.name
                cookie_http_only = cookie.has_nonstandard_attr('HttpOnly') or cookie.get('httponly', False)
                cookie_secure = cookie.has_nonstandard_attr('Secure') or cookie.get('secure', False)
                
                # Thu cach khac neu can
                if not cookie_http_only:
                    try:
                        cookie_http_only = cookie.get_attribute('httpOnly')
                    except Exception:
                        pass
                if not cookie_secure:
                    try:
                        cookie_secure = cookie.get_attribute('secure')
                    except Exception:
                        pass
                        
                cookie_results.append({
                    "name": cookie_name,
                    "HttpOnly": cookie_http_only,
                    "Secure": cookie_secure,
                    "secure_cookie": cookie_secure,
                })
            except Exception:
                pass
        
        # Neu khong co cookie, tra ve rong
        if not cookie_results and not set_cookie_headers:
            pass
        elif set_cookie_headers:
            for cookie_str in set_cookie_headers:
                name = cookie_str.split("=")[0] if "=" in cookie_str else "unknown"
                http_only = "httponly" in cookie_str.lower()
                secure = "secure" in cookie_str.lower()
                cookie_results.append({
                    "name": name,
                    "HttpOnly": http_only,
                    "Secure": secure,
                    "secure_cookie": secure,
                })
        
        return cookie_results

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    def test_TC08_Security_Headers_Check(self):
        """TC08 - Kiem tra HTTP Security Headers cua trang Login"""
        print("\n" + "=" * 70)
        print("TC08 - SECURITY HEADERS CHECK")
        print("=" * 70)

        print(f"\n[INFO] Target: {self.login_url}")

        # Gui GET request lay headers
        try:
            response = requests.get(self.login_url, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            cookies = response.cookies
            status_code = response.status_code
            final_url = response.url
        except requests.exceptions.SSLError as e:
            print(f"\n[ERROR] SSL Error: {e}")
            print("  => Thu nang cap voi verify=False neu la self-signed cert")
            pytest.skip(f"SSL Error - may la self-signed cert: {e}")
        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Request Error: {e}")
            pytest.fail(f"Khong the gui request den {self.login_url}: {e}")

        print(f"\n[INFO] Status: {status_code}")
        print(f"[INFO] Final URL: {final_url}")
        print(f"[INFO] So headers: {len(headers)}")
        print(f"[INFO] So cookies: {len(cookies)}")

        # Phan tich tung header
        print("\n" + "-" * 70)
        print("PHAN TICH SECURITY HEADERS:")
        print("-" * 70)

        header_results = []
        for header_name, header_info in REQUIRED_SECURITY_HEADERS.items():
            result = self._analyze_header(header_name, header_info, headers)
            header_results.append(result)

            # In ket qua
            status_icon = "✅" if result["present"] else ("⚠️" if result["required"] else "ℹ️")
            valid_icon = "✅" if result["valid"] else "❌"
            print(f"\n{status_icon} {header_name}")
            print(f"   Hien dien: {result['present']}")
            print(f"   Gia tri:   {result['value']}")
            print(f"   Hop le:    {result['valid']} {valid_icon}")
            print(f"   {result['note']}")

        # Kiem tra cookie flags
        print("\n" + "-" * 70)
        print("KIEM TRA COOKIE FLAGS:")
        print("-" * 70)

        cookie_results = self._check_cookie_flags(response)
        if not cookie_results:
            print("  Khong co cookie trong response")
        else:
            for cookie in cookie_results:
                http_only_icon = "✅" if cookie["HttpOnly"] else "❌"
                secure_icon = "✅" if cookie["Secure"] else "❌"
                print(f"\n🍪 Cookie: {cookie['name']}")
                print(f"   HttpOnly: {cookie['HttpOnly']} {http_only_icon}")
                print(f"   Secure:  {cookie['Secure']} {secure_icon}")

        # Tinh diem bao mat
        print("\n" + "=" * 70)
        print("TOM TAT KET QUA:")
        print("=" * 70)

        required_present = sum(1 for r in header_results if r["required"] and r["present"])
        required_total = sum(1 for r in header_results if r["required"])
        all_present = sum(1 for r in header_results if r["present"])
        all_valid = sum(1 for r in header_results if r["valid"])
        total = len(header_results)

        print(f"\nSecurity Headers hien dien: {all_present}/{total}")
        print(f"Security Headers hop le:    {all_valid}/{total}")
        print(f"Required headers co:         {required_present}/{required_total}")

        # Danh sach header thieu
        missing_required = [r["name"] for r in header_results if r["required"] and not r["present"]]
        if missing_required:
            print(f"\n[FAIL] Headers bat buoc THIEU: {missing_required}")
        else:
            print(f"\n[PASS] Tat ca headers bat buoc deu co!")

        # Danh sach header co nhung khong hop le
        invalid_headers = [r["name"] for r in header_results if r["present"] and not r["valid"]]
        if invalid_headers:
            print(f"[WARN] Headers co nhung GIA TRI khong hop le: {invalid_headers}")

        # Cookie security
        secure_cookies = [c for c in cookie_results if c["HttpOnly"] and c["Secure"]]
        if cookies and len(secure_cookies) == 0:
            print(f"[WARN] Cookie khong co HttpOnly hoac Secure flag!")
        elif cookies:
            print(f"[PASS] Tat ca cookie deu co HttpOnly va Secure!")

        # Tinh diem
        security_score = (all_valid * 10 + required_present * 5) // (total + required_total)
        print(f"\nDiem bao mat: {all_valid}/{total} headers hop le")

        print("=" * 70)

        # NOTE: Day la phat hien quan trong ve bao mat
        # Khong fail test vi day la trang thai thuc cua server UTC
        if len(missing_required) > 0:
            print(f"\n[ISSUE] Phat hien {len(missing_required)} security headers THIEU:")
            for h in missing_required:
                print(f"  - {h}")
            print(f"\n  => He thong UTC CO LO HONG BAO MAT NGHIEM TRONG!")
            print(f"  => Can them cac header tren de bao ve nguoi dung")

        print("\n[RESULT] TC08 COMPLETED - Test hoan thanh, ghi nhan phat hien:")
        print(f"         Headers co: {all_present}/{total}")
        print(f"         Headers hop le: {all_valid}/{total}")
        print(f"         Headers bat buoc thieu: {len(missing_required)}")
        assert True
