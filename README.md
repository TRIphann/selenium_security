# Selenium Security Testing - UTC Van Phong Dien Tu

A Security Testing project for the **UTC Van Phong Dien Tu** (University of Transport and Communications - Electronic Office) application using **Selenium Python + Pytest**. The project focuses on **10 security test cases** targeting the Login module: SQL Injection (Username/Password), XSS Reflected, OS Command Injection, LDAP Injection, Brute Force, DoS Stress, Security Headers Check, CSRF Protection, and Information Disclosure.

**Test target**: https://vanphongdientu.utc.edu.vn/Login

---

## Objectives

- Test 10 common web security vulnerabilities (OWASP Top 10) against the UTC Van Phong Dien Tu Login page
- Each test case is written in **high detail** format — step-by-step with clearly defined Expected results
- Test data is loaded from `test_cases.csv` (data-driven approach)
- Organized by functional module: Login, Session, Transport Security, Error Handling

---

## Project Structure

```
selenium_security/
|-- README.md                              # This file - documentation
|-- pytest.ini                             # Pytest configuration
|-- conftest.py                            # Driver setup, shared fixtures
|-- test_cases.csv                         # 10 test cases data (data-driven)
|-- test_summary.md                        # Detailed test results report
|-- requirements.txt                       # Required Python packages
|
|-- Locators/                              # Locators for UTC login page
|   |-- __init__.py
|   |-- orangehrm_locators.py              # XPath/CSS selectors
|   `-- __pycache__/
|
|-- TestData/                              # Test data
|   `-- __init__.py
|
|-- TestCases/                             # Test case files (10 tests)
|   |-- __init__.py
|   |-- test_TC01_SQLi_Login_Username.py
|   |-- test_TC02_SQLi_Login_Password.py
|   |-- test_TC03_XSS_Reflected_Login.py
|   |-- test_TC04_Command_Injection_Login.py
|   |-- test_TC05_LDAP_Injection_Login.py
|   |-- test_TC06_Brute_Force_Login_5times.py
|   |-- test_TC07_DoS_Stress_Login.py
|   |-- test_TC08_Security_Headers.py
|   |-- test_TC09_CSRF_Login_No_Token.py
|   `-- test_TC10_Information_Disclosure_404.py
|
|-- TestReports/                           # Output: screenshots, logs, report.html
|   |-- screenshots/
|   `-- logs/
|
`-- venv/                                  # Python virtual environment
```

---

## Installation

```bash
# 1. Install Python 3.8 or higher
# 2. Create a virtual environment
python -m venv venv
venv\Scripts\activate                      # Windows
source venv/bin/activate                   # Linux/Mac

# 3. Install required packages
pip install -r requirements.txt
```

---

## Running Tests

```bash
# Run a specific test case
pytest TestCases/test_TC01_SQLi_Login_Username.py -v --html=TestReports/report.html

# Run all security tests (all 10 cases)
pytest TestCases/ -v --html=TestReports/report.html

# Run by marker
pytest -m security -v

# Run by attack type marker
pytest -m csrf -v
pytest -m information_disclosure -v

# Run a single test method
pytest TestCases/test_TC01_SQLi_Login_Username.py::TestTC01SQLiLoginUsername::test_TC01_SQLi_Login_Username -v
```

---

## Test Cases Overview (10 test cases - high detail)

| ID   | Test Case                       | Module        | Attack Type              | Result           | Finding |
|------|---------------------------------|---------------|--------------------------|------------------|---------|
| TC01 | SQLi_Login_Username             | Login         | SQL Injection            | PASSED           | Blocked |
| TC02 | SQLi_Login_Password             | Login         | SQL Injection            | PASSED           | Blocked |
| TC03 | XSS_Reflected_Login_Username    | Login         | XSS Reflected            | PASSED           | Blocked |
| TC04 | Command_Injection_Login         | Login         | OS Command Injection     | PASSED           | Blocked |
| TC05 | LDAP_Injection_Login            | Login         | LDAP Injection           | PASSED           | Blocked |
| TC06 | Brute_Force_Login_5times        | Login         | Brute Force              | PASSED with finding | No rate limit detected |
| TC07 | DoS_Stress_Login                | Login         | Denial of Service        | PASSED with finding | 504 Timeout under stress |
| TC08 | Security_Headers_Check          | Login Headers | HTTP Security Headers    | PASSED with finding | Missing 4 critical headers |
| TC09 | CSRF_Login_No_Token             | Login Form    | CSRF                     | PASSED with finding | No CSRF token, no Origin/Referer validation |
| TC10 | Information_Disclosure_404      | Error Pages   | Information Disclosure   | PASSED with finding | 80 findings: paths, stack trace, framework, PHP version |

---

## Test Case Details

### TC01 - SQL Injection (Username Field)
- **Payload**: `admin' OR '1'='1` in username field
- **Expected**: Login is rejected, URL stays at /Login, no DB information leak
- **Risk**: Authentication bypass, full database dump
- **Result**: PASSED - payload blocked, no error message leak

### TC02 - SQL Injection (Password Field)
- **Payload**: `admin` / `' OR '1'='1' --`
- **Expected**: Login is rejected, no SQL syntax error visible
- **Risk**: Password verification bypass
- **Result**: PASSED - payload blocked

### TC03 - XSS Reflected
- **Payload**: `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`
- **Expected**: Payload is escaped, no JavaScript execution
- **Risk**: Session hijacking, phishing, keylogger injection
- **Result**: PASSED - payload escaped, no script execution

### TC04 - OS Command Injection
- **Payload**: `; ls -la`, `| whoami`, `` ` cat /etc/passwd` ``, `$(reboot)`
- **Expected**: Shell metacharacters not interpreted, treated as plain text
- **Risk**: Full Remote Code Execution, server takeover
- **Result**: PASSED - shell metacharacters treated as plain text

### TC05 - LDAP Injection
- **Payload**: `*)(uid=*))(|(uid=*`, `admin)(&)`, `*)(objectClass=*`
- **Expected**: LDAP filter not manipulated, no user enumeration
- **Risk**: User enumeration, authentication bypass
- **Result**: PASSED - LDAP filter not manipulated

### TC06 - Brute Force (5 attempts)
- **Payload**: `admin` / `wrongpass_1` through `wrongpass_5`
- **Expected**: Account lockout or CAPTCHA after multiple failures
- **Risk**: Password cracking, credential stuffing, account takeover
- **Result**: PASSED with finding - no rate limit detected, server accepted all 5 attempts

### TC07 - DoS Stress (50 requests)
- **Payload**: `admin` / `admin` sent 50 times rapidly
- **Expected**: Server stays responsive, response time < 5s
- **Risk**: Resource exhaustion, service unavailability
- **Result**: PASSED with finding - 4% requests returned 504 Timeout

### TC08 - Security Headers Check
- **Headers Checked**: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- **Expected**: All required headers present with valid values
- **Risk**: Clickjacking, MIME sniffing, MITM, XSS
- **Result**: PASSED with finding - missing 4 critical headers (CRITICAL)

### TC09 - CSRF Protection (Login Form)
- **Method**: Send login request WITHOUT CSRF token, check Origin/Referer header validation, inspect session cookie SameSite flag
- **Expected**: Server rejects request without valid CSRF token, OR Origin/Referer is validated
- **Risk**: Cross-Site Request Forgery, attacker forces user to login as attacker (session fixation), or actions performed without user consent
- **Result**: PASSED with finding - login form has NO CSRF token, NO Origin validation, NO Referer validation, NO SameSite cookie attribute (CRITICAL)

### TC10 - Information Disclosure via 404 / Error Pages
- **Method**: GET 17 endpoints (control + 8 nonexistent + 2 path traversal + 2 attack targets + 4 sensitive files), scan response body and headers
- **Expected**: Generic 404/500 pages, no absolute paths, no stack trace, no framework name, no version info in headers
- **Risk**: Attacker discovers framework, version, app structure, file path -> can find targeted CVEs, perform LFI/path traversal, locate sensitive files
- **Result**: PASSED with finding - 16/17 endpoints (94%) leak sensitive info. 80 findings total: 16 Critical, 32 High, 16 Medium, 16 Low (CRITICAL)

---

## Critical Findings Summary

| ID   | Finding                                                        | Severity | OWASP Category                  |
|------|----------------------------------------------------------------|----------|---------------------------------|
| TC06 | No rate limiting on login endpoint                             | High     | A07:2021 - Auth Failures        |
| TC07 | Server returns 504 under stress (4% failure)                   | Medium   | A04:2021 - DoS                  |
| TC08 | Missing all 4 required security headers                        | Critical | A05:2021 - Security Misconfig   |
| TC09 | Login form has no CSRF token, no Origin/Referer validation     | Critical | A01:2021 - Broken Access Control|
| TC10 | Verbose error pages disclose paths, stack trace, framework, PHP version | Critical | A05:2021 - Security Misconfig |

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

## High-Detail Test Case Convention

Each test case file follows this structure:
- **Objective**: Short description of what the test verifies
- **Pre-condition**: Required state before test execution
- **Test data**: Username, password, payload, URL
- **Steps**: Step-by-step actions with comments in the code (Step 1, Step 2, ...)
- **Expected**: Expected outcome for each step
- **Assertions**: Validation statements (assert)
- **Teardown**: Cleanup after test

---

## Test Results Summary

- **Total tests**: 10
- **PASSED clean** (no vulnerability): 5 tests (TC01, TC02, TC03, TC04, TC05)
- **PASSED with findings** (vulnerabilities detected): 5 tests (TC06, TC07, TC08, TC09, TC10)
- **Critical issues found**: 3 (TC08 - missing security headers, TC09 - no CSRF, TC10 - information disclosure)
- **High risk issues found**: 1 (TC06 - no rate limit)
- **Medium risk issues found**: 1 (TC07 - 504 timeout)

See `test_summary.md` for the full detailed report.

---

## Author

- Assignment: buoi6 - Security Testing
- Test target: [UTC Van Phong Dien Tu](https://vanphongdientu.utc.edu.vn/Login)
- Framework: Selenium WebDriver + Pytest
- Test data format: CSV (data-driven)
- Test detail level: High (step-by-step with Expected)
- Test count: 10 security test cases (OWASP Top 10 coverage)
