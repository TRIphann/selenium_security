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
| Test cases completed | 9 |
| Test cases pending (TC10) | 1 |
| PASSED clean (no vulnerability) | 5 |
| PASSED with findings (vulnerability detected) | 4 |
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
| TC10| Information_Disclosure_404   | Information Disclosure   | High     | Pending          | TBD                 |

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
| Status | Pending (to be added) |
| Target | GET /Login/NonexistentEndpoint |
| Result | TBD |
| Finding | TBD |

---

## Critical Findings Summary

| ID  | Finding                                    | Severity | OWASP Category     |
|-----|--------------------------------------------|----------|---------------------|
| TC6 | No rate limiting on login endpoint         | High     | A07:2021 - Auth     |
| TC7 | Server returns 504 under stress (4% fail)  | Medium   | A04:2021 - DoS      |
| TC8 | Missing all 4 required security headers    | Critical | A05:2021 - Security Misconfiguration |
| TC9 | Login form has no CSRF token               | Critical | A01:2021 - Broken Access Control |

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

---

## Update History

| Date       | Author       | Changes                              |
|------------|--------------|--------------------------------------|
| 2026-10-08 | baitap - buoi6 | Initial report with 8 test cases (TC01 to TC08). TC09 and TC10 pending. |
| 2026-10-08 | baitap - buoi6 | Added TC09 - CSRF Login No Token. Test detected 5 critical CSRF findings: no token, no Origin validation, no Referer validation, no SameSite cookie. TC10 still pending. |
