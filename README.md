# Selenium Security Testing - UTC Van Phong Dien Tu

A Security Testing project for the **UTC Van Phong Dien Tu** (University of Transport and Communications - Electronic Office) application using **Selenium Python + Pytest**. The project focuses on 8 security test cases targeting the Login module: SQL Injection (Username/Password), XSS Reflected, OS Command Injection, LDAP Injection, Brute Force, DoS Stress, and Security Headers Check.

---

## Objectives

- Test 8 common web security vulnerabilities (OWASP Top 10) against the UTC Van Phong Dien Tu Login page
- Each test case is written in **high detail** format — step-by-step with clearly defined Expected results
- Test data is loaded from `test_cases.csv` (data-driven approach)
- Organized by functional module: Login, Session, Transport Security

---

## Project Structure

```
selenium_security/
|-- README.md                              # This file - documentation
|-- pytest.ini                             # Pytest configuration
|-- conftest.py                            # Driver setup, shared fixtures
|-- test_cases.csv                         # 8 test cases data (data-driven)
|-- requirements.txt                       # Required Python packages
|
|-- Locators/                              # Locators for UTC login page
|   |-- __init__.py
|   |-- utclogin_locators.py               # XPath/CSS selectors
|   `-- orangehrm_locators.py              # Backup locators
|
|-- TestData/                              # Test data
|   `-- __init__.py
|
|-- TestCases/                             # Test case files
|   |-- __init__.py
|   |-- test_TC01_SQLi_Login_Username.py
|   |-- test_TC02_SQLi_Login_Password.py
|   |-- test_TC03_XSS_Reflected_Login.py
|   |-- test_TC04_Command_Injection_Login.py
|   |-- test_TC05_LDAP_Injection_Login.py
|   |-- test_TC06_Brute_Force_Login.py
|   |-- test_TC07_DoS_Stress_Login.py
|   |-- test_TC08_Security_Headers.py
|   `-- test_summary_8_tests.py            # Summary report of all 8 tests
|
`-- TestReports/                           # Output: screenshots, logs, report.html
    |-- screenshots/
    `-- logs/
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

# Run all security tests
pytest TestCases/ -v --html=TestReports/report.html

# Run by marker
pytest -m security -v

# Run a single test method
pytest TestCases/test_TC01_SQLi_Login_Username.py::TestTC01SQLiLoginUsername::test_TC01_SQLi_Login_Username -v
```

---

## Test Cases Overview (8 test cases - high detail)

| ID  | Test Case                       | Module        | Attack Type              | Result | Finding |
|-----|---------------------------------|---------------|--------------------------|--------|---------|
| TC1 | SQLi_Login_Username             | Login         | SQL Injection            | PASS   | Blocked |
| TC2 | SQLi_Login_Password             | Login         | SQL Injection            | PASS   | Blocked |
| TC3 | XSS_Reflected_Login_Username    | Login         | XSS Reflected            | PASS   | Blocked |
| TC4 | Command_Injection_Login         | Login         | OS Command Injection     | PASS   | Blocked |
| TC5 | LDAP_Injection_Login            | Login         | LDAP Injection           | PASS   | Blocked |
| TC6 | Brute_Force_Login_5times        | Login         | Brute Force              | PASS   | No rate limit detected |
| TC7 | DoS_Stress_Login                | Login         | Denial of Service        | PASS   | 504 Timeout under stress |
| TC8 | Security_Headers_Check          | Login Headers | HTTP Security Headers    | PASS   | Missing 4 critical headers |

---

## Test Case Details

### TC01 - SQL Injection (Username Field)
- **Payload**: `admin' OR '1'='1` in username field
- **Expected**: Login is rejected, URL stays at /Login, no DB information leak
- **Risk**: Authentication bypass, full database dump

### TC02 - SQL Injection (Password Field)
- **Payload**: `admin` / `' OR '1'='1' --`
- **Expected**: Login is rejected, no SQL syntax error visible
- **Risk**: Password verification bypass

### TC03 - XSS Reflected
- **Payload**: `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`
- **Expected**: Payload is escaped, no JavaScript execution
- **Risk**: Session hijacking, phishing, keylogger injection

### TC04 - OS Command Injection
- **Payload**: `; ls -la`, `| whoami`, `` ` cat /etc/passwd` ``, `$(reboot)`
- **Expected**: Shell metacharacters not interpreted, treated as plain text
- **Risk**: Full Remote Code Execution, server takeover

### TC05 - LDAP Injection
- **Payload**: `*)(uid=*))(|(uid=*`, `admin)(&)`, `*)(objectClass=*`
- **Expected**: LDAP filter not manipulated, no user enumeration
- **Risk**: User enumeration, authentication bypass

### TC06 - Brute Force (5 attempts)
- **Payload**: `admin` / `wrongpass_1` through `wrongpass_5`
- **Expected**: Account lockout or CAPTCHA after multiple failures
- **Risk**: Password cracking, credential stuffing, account takeover

### TC07 - DoS Stress (50 requests)
- **Payload**: `admin` / `admin` sent 50 times rapidly
- **Expected**: Server stays responsive, response time < 5s
- **Risk**: Resource exhaustion, service unavailability

### TC08 - Security Headers Check
- **Headers Checked**: X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- **Expected**: All required headers present with valid values
- **Risk**: Clickjacking, MIME sniffing, MITM, XSS

---

## Critical Findings Summary

| Finding | Severity | Affected Test |
|---------|----------|---------------|
| No rate limiting on login endpoint | High | TC06 |
| Server returns 504 under stress (4% failure) | Medium | TC07 |
| Missing all 4 required security headers | Critical | TC08 |

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

- **Total tests**: 8
- **PASSED clean** (no vulnerability): 5 tests (TC01, TC02, TC03, TC04, TC05)
- **PASSED with findings** (vulnerabilities detected): 3 tests (TC06, TC07, TC08)
- **Critical issues found**: 1 (TC08 - missing security headers)
- **High risk issues found**: 2 (TC06 - no rate limit, TC07 - 504 timeout)

---

## Author

- Assignment: buoi6 - Security Testing
- Test target: [UTC Van Phong Dien Tu](https://vanphongdientu.utc.edu.vn/Login)
- Framework: Selenium WebDriver + Pytest
- Test data format: CSV (data-driven)
- Test detail level: High (step-by-step with Expected)
