# Test Summary Report - UTC Van Phong Dien Tu Security Testing

| Field | Value |
|-------|-------|
| Project | Security Testing for UTC Van Phong Dien Tu |
| Target URL | https://vanphongdientu.utc.edu.vn/Login |
| Test Framework | pytest + Selenium |
| Author | baitap - buoi6 |
| Created | 2026-10-08 |
| Last Updated | 2026-10-08 |

This document summarizes the results of all security test cases run against the UTC Van Phong Dien Tu Login page. The report will be updated as TC09 and TC10 are added.

---

## Overall Statistics

| Metric | Count |
|--------|-------|
| Total test cases planned | 10 |
| Test cases completed | 10 |
| PASSED clean (no vulnerability) | 5 |
| PASSED with findings (vulnerability detected) | 5 |
| FAILED | 0 |

---

## Test Results Table

| ID  | Test Case                    | Attack Type              | Priority | Result           | Severity of Finding |
|-----|------------------------------|--------------------------|----------|------------------|---------------------|
| TC1 | SQLi_Login_Username          | SQL Injection            | High     | PASSED           | None                |
| TC2 | SQLi_Login_Password          | SQL Injection            | High     | PASSED           | None                |
| TC3 | XSS_Reflected_Login          | XSS Reflected            | High     | PASSED           | None                |
| TC4 | Command_Injection_Login      | OS Command Injection     | High     | PASSED           | None                |
| TC5 | LDAP_Injection_Login         | LDAP Injection           | High     | PASSED           | None                |
| TC6 | Brute_Force_Login_5times     | Brute Force              | High     | PASSED with finding | High             |
| TC7 | DoS_Stress_Login             | Denial of Service        | High     | PASSED with finding | Medium           |
| TC8 | Security_Headers_Check       | HTTP Security Headers    | High     | PASSED with finding | Critical         |
| TC9 | CSRF_Login_No_Token          | CSRF                     | High     | PASSED with finding | Critical         |
| TC10| Information_Disclosure_404   | Information Disclosure   | High     | PASSED with finding | Critical         |

---

## Detailed Findings

### TC01 - SQL Injection (Username Field)

| Field | Value |
|-------|-------|
| Status | PASSED |
| Target | Form Login - username field |
| Payload | `admin' OR '1'='1` |
| Result | UTC properly blocks SQLi in username field. No bypass detected. |
| Finding | No vulnerability found |

### TC02 - SQL Injection (Password Field)

| Field | Value |
|-------|-------|
| Status | PASSED |
| Target | Form Login - password field |
| Payload | `' OR '1'='1' --` |
| Result | UTC properly blocks SQLi in password field. No bypass detected. |
| Finding | No vulnerability found |

### TC03 - XSS Reflected

| Field | Value |
|-------|-------|
| Status | PASSED |
| Target | Form Login - username field |
| Payload | `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>` |
| Result | UTC properly escapes XSS payload. No script execution detected. |
| Finding | No vulnerability found |

### TC04 - OS Command Injection

| Field | Value |
|-------|-------|
| Status | PASSED |
| Target | Form Login - username field |
| Payload | `; ls -la`, `\| whoami`, `` ` cat /etc/passwd` ``, `$(reboot)` |
| Result | UTC does not execute OS commands from user input. Safe. |
| Finding | No vulnerability found |

### TC05 - LDAP Injection

| Field | Value |
|-------|-------|
| Status | PASSED |
| Target | Form Login - username field |
| Payload | `*)(uid=*))((\|(uid=*`, `admin)(&)`, `*)(objectClass=*` |
| Result | UTC properly handles LDAP metacharacters. No injection detected. |
| Finding | No vulnerability found |

### TC06 - Brute Force Attack

| Field | Value |
|-------|-------|
| Status | PASSED with finding |
| Target | Form Login - 5 consecutive failed attempts |
| Payload | `admin` / `wrongpass_1` through `wrongpass_5` |
| Severity | High |
| Result | 5 failed attempts in a row all returned normal error. No lock, no CAPTCHA, no delay. |
| Finding | UTC has NO rate limiting and NO account lockout. Vulnerable to brute force attack. |
| Risk | Password cracking, credential stuffing, account takeover |

### TC07 - DoS Stress Test

| Field | Value |
|-------|-------|
| Status | PASSED with finding |
| Target | POST /Login - 50 sequential requests |
| Payload | `admin` / `admin` sent 50 times rapidly |
| Severity | Medium |
| Result | Server returned 2x HTTP 504 Gateway Timeout during stress test. Average response time: 438ms, max: 941ms. |
| Finding | Server is WEAK under load - 4% of requests failed. Insufficient server capacity or missing rate limiting. |
| Risk | Resource exhaustion, service unavailability |

### TC08 - Security Headers Check

| Field | Value |
|-------|-------|
| Status | PASSED with finding |
| Target | HTTP response headers from GET /Login |
| Headers Checked | X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| Severity | Critical |
| Result | Score: 0/7 security headers present. |
| Finding | UTC is missing ALL 4 REQUIRED security headers: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy. |
| Risk | Clickjacking, MIME sniffing, MITM, XSS attacks |

### TC09 - CSRF Login No Token

| Field | Value |
|-------|-------|
| Status | PASSED with finding |
| Target | Form Login - POST without prior cookie/origin |
| Severity | Critical |
| Method | Raw HTTP via Python requests (no browser needed) |
| Result | All 3 CSRF attack simulations succeeded - server returned status 200 in all cases. |
| Finding 1 | Form Login KHONG co CSRF token (khong co hidden input nao) |
| Finding 2 | POST khong cookie, khong Origin, khong Referer bi CHAP NHAN (status 200) |
| Finding 3 | POST voi Origin=http://evil.com bi CHAP NHAN (status 200) - server KHONG validate Origin |
| Finding 4 | POST voi Referer gia (attacker.evil.com) bi CHAP NHAN (status 200) - server KHONG validate Referer |
| Finding 5 | Cookie `sso_utc_token_office` KHONG co SameSite attribute |
| Risk | Attacker co the lua user da login vao UTC click vao trang doc hai, tu do gui POST request den /Login ma user khong hay biet. Vi cookie khong co SameSite, browser se tu dong gui kem cookie -> attacker co the thuc hien hanh vi tren danh nghiep user. |
| OWASP | A01:2021 - Broken Access Control |
| Total findings | 5 (Critical) |

### TC10 - Information Disclosure 404

| Field | Value |
|-------|-------|
| Status | PASSED with finding |
| Target | 17 endpoints (control + 8 nonexistent + 2 path traversal + 2 attack targets + 4 sensitive files) |
| Severity | Critical |
| Method | Raw HTTP GET via Python requests |
| Result | 16/17 endpoint (94%) de lo thong tin nhay cam. 80 findings tong cong (16 Critical, 32 High, 16 Medium, 16 Low). |
| Finding 1 | **Absolute path disclosure**: /var/www/oneoffice/Core/v2.1/... tren TAT CA cac error page |
| Finding 2 | **Stack trace disclosure**: day du file path, function call, line number (Fatal error + Uncaught exception) |
| Finding 3 | **Framework name disclosure**: oneoffice (custom framework), App_Exception class, Core/v2.1 |
| Finding 4 | **App structure disclosure**: modules/Login/controllers/, apps/modules/Api/controllers/ |
| Finding 5 | **Path traversal reflection**: /Login/../../../etc/passwd tra "Folder for Etc is not found" (server xu ly path) |
| Finding 6 | **PHP version disclosure**: X-Powered-By: PHP/5.6.40 (EOL since 2019, nguy co cao) |
| Finding 7 | **Web server version disclosure**: Server: nginx/1.20.1 (lo version) |
| Risk | Attacker biet framework, version, app structure, file path -> co the: (1) tim CVE tuong ung cho PHP 5.6.40 (rat nhieu), (2) thuc hien path traversal bi muc tieu hon, (3) do tim file nhay cam, (4) tao malware chuyen biet cho framework "oneoffice" |
| OWASP | A05:2021 - Security Misconfiguration |
| Total findings | 80 (16 Critical, 32 High, 16 Medium, 16 Low) |

---

## Critical Findings Summary

| ID  | Finding                                    | Severity | OWASP Category     |
|-----|--------------------------------------------|----------|---------------------|
| TC6 | No rate limiting on login endpoint         | High     | A07:2021 - Auth     |
| TC7 | Server returns 504 under stress (4% fail)  | Medium   | A04:2021 - DoS      |
| TC8 | Missing all 4 required security headers    | Critical | A05:2021 - Security Misconfiguration |
| TC9 | Login form has no CSRF token               | Critical | A01:2021 - Broken Access Control |
| TC10| Verbose error pages disclose paths, stack trace, framework, PHP version | Critical | A05:2021 - Security Misconfiguration |

---

## Recommendations

### For TC06 - Brute Force
- Implement account lockout after 5 failed attempts
- Add progressive delay between login attempts
- Add CAPTCHA after 3 failed attempts
- Implement IP-based rate limiting

### For TC07 - DoS Stress
- Add rate limiting on login endpoint (e.g., 10 requests per minute per IP)
- Increase server capacity or use load balancer
- Add CDN with DDoS protection (e.g., Cloudflare)
- Implement request queue with timeout handling

### For TC08 - Security Headers (CRITICAL)
- Add X-Frame-Options: DENY or SAMEORIGIN
- Add X-Content-Type-Options: nosniff
- Add Strict-Transport-Security: max-age=31536000; includeSubDomains
- Add Content-Security-Policy: default-src 'self'
- Ensure cookies have HttpOnly and Secure flags

### For TC09 - CSRF Protection (CRITICAL)
- Add CSRF token to login form (hidden input) - regenerate on each request
- Validate Origin header must match own domain
- Validate Referer header must be from own domain
- Add SameSite=Strict or SameSite=Lax to session cookie
- Consider using SameSite=Strict on sso_utc_token_office cookie

### For TC10 - Information Disclosure (CRITICAL)
- Set `display_errors = Off` in php.ini for production
- Set `expose_php = Off` to remove X-Powered-By header
- Configure custom 404/500 error pages that do NOT show stack trace
- Remove `Server` header version: use `server_tokens off` in nginx
- Implement generic error handler that returns only "Page not found" / "Server Error"
- Fix path traversal: do not reflect user-controlled path in error messages
- Upgrade PHP from 5.6.40 to PHP 8.x (5.6 is EOL since 2019 with many known CVEs)
- Add try/catch around controller instantiation to handle missing controllers gracefully

---

## Update History

| Date       | Author       | Changes                              |
|------------|--------------|--------------------------------------|
| 2026-10-08 | baitap - buoi6 | Initial report with 8 test cases (TC01 to TC08). TC09 and TC10 pending. |
| 2026-10-08 | baitap - buoi6 | Added TC09 - CSRF Login No Token. Test detected 5 critical CSRF findings: no token, no Origin validation, no Referer validation, no SameSite cookie. TC10 still pending. |
| 2026-10-08 | baitap - buoi6 | Added TC10 - Information Disclosure 404. Test detected 80 findings (16 Critical, 32 High) on 16/17 endpoints: absolute paths, stack traces, framework name, PHP version, nginx version. ALL 10 test cases completed. |
