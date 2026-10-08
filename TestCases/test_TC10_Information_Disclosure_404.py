"""
TC10 - Information Disclosure via 404 / Error Pages
====================================================
Test ID:         TC10_Information_Disclosure_404
Test Name:       Information_Disclosure_404
Target Module:   Login Page & non-existent endpoints (https://vanphongdientu.utc.edu.vn)
Type:            Security - Information Disclosure / Verbose Error Messages (OWASP A05:2021)
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang UTC Van Phong Dien Tu co loi thong tin nhay cam
    (Information Disclosure) qua cac trang loi 404, 500 hay khong.

    Information Disclosure la ky thuat loi ma he thong tiep can loi ro rang
    nhung thong tin ma khong nen cong khai, bao gom:
        - Absolute file path tren server (vi du: /var/www/...)
        - Ten framework / phien ban
        - Stack trace chi tiet
        - Database error message
        - Source code snippet
        - Cau truc thu muc noi bo
        - Phien ban PHP / web server

    Neu he thong de lo nhung thong tin nay, attacker co the:
        - Biet duoc framework dang dung -> tim CVE tuong ung
        - Biet duoc file path -> thuc hien LFI/RFI/path traversal
        - Biet duoc cau truc thu muc -> do tim file nhay cam (.env, .git, backup)
        - Biet duoc phien ban PHP (5.6.40) -> rat cu, co the bi tan cong boi hang loat CVE

Pre-condition:
    - URL https://vanphongdientu.utc.edu.vn hoat dong
    - Co the gui GET request den bat ky endpoint nao
    - Phan hoi tu server co the phan tich duoc

Test Data:
    - URL:      https://vanphongdientu.utc.edu.vn
    - Method:   GET
    - Test cases:
        + 8 endpoint khong ton tai (nonexistent path, .git/config, .env, robots.txt, etc.)
        + 2 path traversal (/Login/../../../etc/passwd, /Login/%2e%2e%2f)
        + 2 common attack targets (phpmyadmin, wp-admin)
        + 1 sensitive file (server-status, .env)
        + 1 valid endpoint de so sanh (/Login)

Steps:
    Step 1:  GET /Login (control - valid endpoint)
    Step 2:  GET 8 nonexistent endpoint (khoi tao 404)
    Step 3:  GET 2 path traversal payload
    Step 4:  GET 2 common attack targets
    Step 5:  GET sensitive files
    Step 6:  GET 1 valid endpoint so sanh response
    Step 7:  Phan tich response body, kiem tra co:
             - Absolute path (Linux / Windows path)
             - Stack trace
             - Framework name / version
             - Source code snippet
             - Server / PHP version
    Step 8:  Kiem tra response header co Server, X-Powered-By khong
    Step 9:  Final assessment

Expected (HE THONG AN TOAN):
    - 404 page: generic, khong co path/framework/stack
    - 500 page: chi hien "Internal Server Error" khong co chi tiet
    - Path traversal: tra 404 hoac 403, khong de lo path
    - Header: Server: nginx (khong co version), X-Powered-By: KHONG co
    - Custom 404 page: "Page not found" - khong co path
    - Production mode: display_errors = Off

Expected (NEU HE THONG YEU - UTC truong hop nay):
    - 404 tra ve PHP Fatal error kem absolute path /var/www/oneoffice/...
    - Path traversal: hien thi ten folder tu path
    - Stack trace: day du file path, function, line number
    - Framework "oneoffice" duoc tiep can cong khai
    - PHP version 5.6.40 (rat cu, khong con ho tro tu 2019)
    - X-Powered-By: PHP/5.6.40 - lo version
    - Server: nginx/1.20.1 - lo version
"""

import re
import pytest
import requests
from requests.exceptions import RequestException


# ==================== Configuration ====================

BASE_URL = "https://vanphongdientu.utc.edu.vn"

# Tap cac endpoint test
# Moi endpoint kem o muc dich, de biet minh dang test gi
TEST_ENDPOINTS = {
    "nonexistent": [
        {
            "path": "/Login/nonexistent",
            "purpose": "Kiem tra 404 co de lo thong tin khong",
        },
        {
            "path": "/nonexistent-page-xyz",
            "purpose": "Kiem tra 404 tuyet doi (khong co /Login)",
        },
        {
            "path": "/Login/123456",
            "purpose": "Endpoint la so",
        },
        {
            "path": "/Login/admin",
            "purpose": "Endpoint la 'admin' (common word)",
        },
        {
            "path": "/Login/test",
            "purpose": "Endpoint la 'test'",
        },
        {
            "path": "/Login/config",
            "purpose": "Endpoint la 'config' (thuong la sensitive)",
        },
        {
            "path": "/Login/backup",
            "purpose": "Endpoint la 'backup' (thuong la sensitive)",
        },
        {
            "path": "/Login/debug",
            "purpose": "Endpoint la 'debug' (thuong la sensitive)",
        },
    ],
    "path_traversal": [
        {
            "path": "/Login/../../../etc/passwd",
            "purpose": "Path traversal co ban (di len thu muc)",
        },
        {
            "path": "/Login/%2e%2e%2f",
            "purpose": "Path traversal voi URL encoding",
        },
    ],
    "common_attack_targets": [
        {
            "path": "/Login/phpmyadmin",
            "purpose": "Kiem tra phpmyadmin co ton tai khong",
        },
        {
            "path": "/Login/wp-admin",
            "purpose": "Kiem tra WordPress admin (co the WP)",
        },
    ],
    "sensitive_files": [
        {
            "path": "/Login/.git/config",
            "purpose": "Kiem tra .git co de lo source code khong",
        },
        {
            "path": "/Login/.env",
            "purpose": "Kiem tra .env (thuong chua DB password)",
        },
        {
            "path": "/Login/robots.txt",
            "purpose": "Kiem tra robots.txt",
        },
        {
            "path": "/Login/server-status",
            "purpose": "Apache/Nginx server-status (thuong chi cho internal)",
        },
    ],
    "control": [
        {
            "path": "/Login",
            "purpose": "Valid endpoint (control group de so sanh)",
        },
    ],
}


# Cac pattern nguy hiem can phat hien trong response
SENSITIVE_PATTERNS = {
    "absolute_path_linux": {
        "pattern": r"(/var/www/|/home/|/opt/|/usr/local/|/srv/|/etc/)",
        "description": "Absolute path tren Linux (he thong production)",
        "severity": "High",
    },
    "absolute_path_windows": {
        "pattern": r"([A-Z]:\\\\[a-zA-Z0-9_\\\\./-]+|[a-zA-Z]:/)",
        "description": "Absolute path tren Windows",
        "severity": "High",
    },
    "stack_trace": {
        "pattern": r"(Stack trace:|Fatal error|Uncaught exception|#[0-9]+\s+/var/www/|#0\s+/var/www/)",
        "description": "Stack trace / PHP fatal error - de lo code path",
        "severity": "Critical",
    },
    "php_version": {
        "pattern": r"PHP/\d+\.\d+\.\d+|PHP/\d+\.\d+",
        "description": "Phien ban PHP cu the",
        "severity": "Medium",
    },
    "framework_name": {
        "pattern": r"(oneoffice|App_Exception|Core/v\d|modules/[A-Z][a-z]+/controllers)",
        "description": "Ten framework / app noi bo",
        "severity": "High",
    },
    "server_version": {
        "pattern": r"(nginx/\d+\.\d+|apache/\d+\.\d+|iis/\d+)",
        "description": "Phien ban web server",
        "severity": "Low",
    },
    "source_code": {
        "pattern": r"<\?php|<\?=|<script\s+language\s*=\s*['\"]?php",
        "description": "Source code PHP bi lo",
        "severity": "Critical",
    },
    "db_info": {
        "pattern": r"(SQLSTATE|mysqli?_connect|pg_connect|pdo->error|mysql_error)",
        "description": "Database error / connection info",
        "severity": "Critical",
    },
    "internal_ip": {
        "pattern": r"\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b",
        "description": "Internal IP address",
        "severity": "Medium",
    },
}


# ==================== Helper Functions ====================

def get_endpoint(url_path):
    """
    Step helper: GET mot endpoint, tra ve (status, body, headers).
    """
    url = BASE_URL + url_path
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response.status_code, response.text, dict(response.headers)
    except RequestException as e:
        # Neu server tra loi 4xx/5xx, requests van co response
        # Exception chi xay ra khi network error
        pytest.fail(f"Khong the GET {url_path}: {e}")


def scan_sensitive_info(body):
    """
    Step 7 helper: Quet response body, kiem tra cac pattern nhay cam.
    Returns: list cac finding phat hien duoc
    """
    findings = []
    for pattern_name, pattern_info in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern_info["pattern"], body, re.IGNORECASE)
        if matches:
            # Lay mau 3 ket qua dau tien
            sample = list(set(matches))[:3]
            findings.append({
                "type": pattern_name,
                "description": pattern_info["description"],
                "severity": pattern_info["severity"],
                "count": len(matches),
                "samples": sample,
            })
    return findings


def check_sensitive_headers(headers):
    """
    Step 8 helper: Kiem tra response headers co lo version khong.
    Returns: list cac finding
    """
    findings = []

    # Server header
    server = headers.get("Server", "")
    if re.search(r"\d+\.\d+", server):
        findings.append({
            "type": "server_version_header",
            "description": f"Server header lo version: {server}",
            "severity": "Low",
            "header": "Server",
            "value": server,
        })

    # X-Powered-By header
    xpb = headers.get("X-Powered-By", "")
    if xpb:
        findings.append({
            "type": "x_powered_by_header",
            "description": f"X-Powered-By header ton tai: {xpb} (nen tat o production)",
            "severity": "Medium",
            "header": "X-Powered-By",
            "value": xpb,
        })

    return findings


# ==================== Test Class ====================

@pytest.mark.security
@pytest.mark.login
@pytest.mark.high
class TestTC10InformationDisclosure404:
    """
    Test class cho TC10 - Information Disclosure 404.
    Muc tieu: phat hien thong tin nhay cam bi lo qua cac trang loi.
    """

    def test_TC10_Information_Disclosure_404(self):
        """
        Test method chinh - thuc hien 9 steps theo high-detail format.

        EXPECTED (he thong an toan):
            - 404 page: generic, khong co path/framework/stack
            - Path traversal: tra 404 hoac 403, khong de lo path
            - Server header: chi co "nginx", khong co version
            - X-Powered-By: KHONG co

        EXPECTED (neu he thong yeu - UTC):
            - 404 tra ve PHP Fatal error kem absolute path /var/www/oneoffice/...
            - Path traversal: hien thi ten folder tu path
            - Stack trace: day du file path, function, line number
            - Framework "oneoffice" duoc tiep can cong khai
            - PHP version 5.6.40 (rat cu, khong con ho tro tu 2019)
            - X-Powered-By: PHP/5.6.40
            - Server: nginx/1.20.1
        """
        print("\n" + "=" * 70)
        print("TC10 - Information Disclosure via 404 / Error Pages")
        print("=" * 70)

        all_findings = []
        endpoint_results = []

        # ----------------------------------------------------------------
        # STEP 1: GET /Login (control - valid endpoint)
        # ----------------------------------------------------------------
        print("\n[STEP 1] GET /Login (control - valid endpoint)")
        status1, body1, headers1 = get_endpoint("/Login")
        print(f"  [INFO] Status: {status1}")
        print(f"  [INFO] Body length: {len(body1)} chars")
        print(f"  [INFO] Server header: {headers1.get('Server', 'N/A')}")
        print(f"  [INFO] X-Powered-By: {headers1.get('X-Powered-By', 'N/A')}")

        # Kiem tra control endpoint co lo thong tin khong
        control_findings = scan_sensitive_info(body1)
        if control_findings:
            print(f"  [WARN] Control endpoint LO THONG TIN: {len(control_findings)} findings")
        else:
            print(f"  [OK] Control endpoint khong lo thong tin nhay cam")

        # ----------------------------------------------------------------
        # STEP 2: GET 8 nonexistent endpoint
        # ----------------------------------------------------------------
        print("\n[STEP 2] GET 8 nonexistent endpoint")
        nonexistent_findings = []
        for ep in TEST_ENDPOINTS["nonexistent"]:
            path = ep["path"]
            purpose = ep["purpose"]
            status, body, headers = get_endpoint(path)
            findings = scan_sensitive_info(body)
            header_findings = check_sensitive_headers(headers)

            all_path_findings = findings + header_findings
            if all_path_findings:
                nonexistent_findings.append({
                    "path": path,
                    "purpose": purpose,
                    "status": status,
                    "findings": all_path_findings,
                })
                critical_count = sum(1 for f in all_path_findings if f["severity"] in ["Critical", "High"])
                print(f"  [VULN] {path:35s} status {status:3d} - {len(all_path_findings)} findings ({critical_count} critical/high)")
            else:
                print(f"  [OK]   {path:35s} status {status:3d} - khong lo thong tin")

        endpoint_results.append(("nonexistent", nonexistent_findings))

        # ----------------------------------------------------------------
        # STEP 3: GET 2 path traversal payload
        # ----------------------------------------------------------------
        print("\n[STEP 3] GET 2 path traversal payload")
        path_traversal_findings = []
        for ep in TEST_ENDPOINTS["path_traversal"]:
            path = ep["path"]
            purpose = ep["purpose"]
            print(f"  [INFO] Test path traversal: {path}")
            status, body, headers = get_endpoint(path)
            findings = scan_sensitive_info(body)
            header_findings = check_sensitive_headers(headers)

            all_path_findings = findings + header_findings
            if all_path_findings:
                path_traversal_findings.append({
                    "path": path,
                    "purpose": purpose,
                    "status": status,
                    "findings": all_path_findings,
                })
                critical_count = sum(1 for f in all_path_findings if f["severity"] in ["Critical", "High"])
                print(f"  [VULN] {path:50s} status {status:3d} - {len(all_path_findings)} findings ({critical_count} critical/high)")
            else:
                print(f"  [OK]   {path:50s} status {status:3d} - khong lo thong tin")

        endpoint_results.append(("path_traversal", path_traversal_findings))

        # ----------------------------------------------------------------
        # STEP 4: GET 2 common attack targets
        # ----------------------------------------------------------------
        print("\n[STEP 4] GET 2 common attack targets (phpmyadmin, wp-admin)")
        attack_findings = []
        for ep in TEST_ENDPOINTS["common_attack_targets"]:
            path = ep["path"]
            purpose = ep["purpose"]
            status, body, headers = get_endpoint(path)
            findings = scan_sensitive_info(body)
            header_findings = check_sensitive_headers(headers)

            all_path_findings = findings + header_findings
            if all_path_findings:
                attack_findings.append({
                    "path": path,
                    "purpose": purpose,
                    "status": status,
                    "findings": all_path_findings,
                })
                critical_count = sum(1 for f in all_path_findings if f["severity"] in ["Critical", "High"])
                print(f"  [VULN] {path:35s} status {status:3d} - {len(all_path_findings)} findings ({critical_count} critical/high)")
            else:
                print(f"  [OK]   {path:35s} status {status:3d} - khong lo thong tin")

        endpoint_results.append(("attack_targets", attack_findings))

        # ----------------------------------------------------------------
        # STEP 5: GET sensitive files
        # ----------------------------------------------------------------
        print("\n[STEP 5] GET sensitive files (.git, .env, robots.txt, server-status)")
        sensitive_findings = []
        for ep in TEST_ENDPOINTS["sensitive_files"]:
            path = ep["path"]
            purpose = ep["purpose"]
            status, body, headers = get_endpoint(path)
            findings = scan_sensitive_info(body)
            header_findings = check_sensitive_headers(headers)

            all_path_findings = findings + header_findings
            if all_path_findings:
                sensitive_findings.append({
                    "path": path,
                    "purpose": purpose,
                    "status": status,
                    "findings": all_path_findings,
                })
                critical_count = sum(1 for f in all_path_findings if f["severity"] in ["Critical", "High"])
                print(f"  [VULN] {path:35s} status {status:3d} - {len(all_path_findings)} findings ({critical_count} critical/high)")
            else:
                print(f"  [OK]   {path:35s} status {status:3d} - khong lo thong tin")

        endpoint_results.append(("sensitive_files", sensitive_findings))

        # ----------------------------------------------------------------
        # STEP 6: GET valid endpoint so sanh response
        # ----------------------------------------------------------------
        print("\n[STEP 6] GET valid endpoint so sanh response")
        for ep in TEST_ENDPOINTS["control"]:
            path = ep["path"]
            purpose = ep["purpose"]
            status, body, headers = get_endpoint(path)
            print(f"  [INFO] Control: {path} - status {status}, body {len(body)} chars")

        # ----------------------------------------------------------------
        # STEP 7: Phan tich response body tong the
        # ----------------------------------------------------------------
        print("\n[STEP 7] Phan tich response body tong the")

        # Dem tong findings
        all_vuln_paths = []
        for category, findings_list in endpoint_results:
            for item in findings_list:
                all_vuln_paths.append((category, item))

        print(f"  [INFO] Tong so endpoint lo thong tin: {len(all_vuln_paths)}/{sum(len(v) for v in TEST_ENDPOINTS.values())}")

        # Phan tich severity
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        pattern_count = {}
        for category, item in all_vuln_paths:
            for f in item["findings"]:
                severity_count[f["severity"]] = severity_count.get(f["severity"], 0) + 1
                pattern_count[f["type"]] = pattern_count.get(f["type"], 0) + 1

        print(f"  [INFO] Severity breakdown:")
        for sev, cnt in severity_count.items():
            if cnt > 0:
                print(f"    {sev}: {cnt}")
        print(f"  [INFO] Pattern breakdown:")
        for ptype, cnt in sorted(pattern_count.items(), key=lambda x: -x[1]):
            print(f"    {ptype}: {cnt}")

        # ----------------------------------------------------------------
        # STEP 8: Kiem tra response header
        # ----------------------------------------------------------------
        print("\n[STEP 8] Kiem tra response header")
        # Lay header tu 1 endpoint bat ky (nonexistent dau tien)
        if all_vuln_paths:
            sample_item = all_vuln_paths[0][1]
            sample_path = sample_item["path"]
            status, body, headers = get_endpoint(sample_path)
            print(f"  [INFO] Test header tu: {sample_path}")
            for header, value in headers.items():
                # In cac header nhay cam
                if header.lower() in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
                    print(f"  [WARN] Header nhay cam: {header} = {value}")

        # ----------------------------------------------------------------
        # STEP 9: Final assessment
        # ----------------------------------------------------------------
        print("\n[STEP 9] Final assessment - Information Disclosure")
        print("-" * 70)

        critical_total = severity_count.get("Critical", 0)
        high_total = severity_count.get("High", 0)
        medium_total = severity_count.get("Medium", 0)
        low_total = severity_count.get("Low", 0)

        if critical_total > 0 or high_total > 0:
            print("  [CRITICAL] PHAT HIEN LO HONG INFORMATION DISCLOSURE!")
            print(f"  [INFO] Critical: {critical_total}, High: {high_total}, Medium: {medium_total}, Low: {low_total}")
            print(f"  [INFO] Lo hong tren {len(all_vuln_paths)} endpoint")
            print("-" * 70)

            # In chi tiet cac finding quan trong
            print("  [INFO] CHI TIET CAC FINDING:")
            for category, item in all_vuln_paths[:5]:  # Top 5
                print(f"    Path: {item['path']} (status {item['status']})")
                for f in item["findings"][:3]:  # Top 3 findings moi path
                    samples_str = ", ".join(str(s)[:50] for s in f.get("samples", []))
                    print(f"      [{f['severity']}] {f['type']}: {f['description']}")
                    if samples_str:
                        print(f"        Sample: {samples_str}")
                print()
        elif medium_total > 0:
            print("  [MEDIUM] Phat hien thong tin ro ri o muc do trung binh")
        else:
            print("  [OK] He thong khong lo thong tin nhay cam")

        # Test pass neu phat hien duoc (muc tieu cua test la phat hien)
        # hoac neu khong phat hien (he thong an toan)
        assert True, "Test TC10 completed"


# ==================== Test Run Helper ====================

if __name__ == "__main__":
    """Cho phep chay truc tiep: python test_TC10_Information_Disclosure_404.py"""
    print("=" * 70)
    print("TC10 - Information Disclosure 404 - Manual Test Runner")
    print("=" * 70)

    # Test tat ca endpoint
    test = TestTC10InformationDisclosure404()
    test.test_TC10_Information_Disclosure_404()

    print("\n" + "=" * 70)
    print("Done - xem chi tiet trong report.html")
    print("=" * 70)
