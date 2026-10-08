# 🛡️ Selenium Security Testing - OrangeHRM

Project kiểm thử bảo mật (Security Testing) cho ứng dụng **OrangeHRM** sử dụng **Selenium Python + Pytest**. Tập trung vào 15 test case: SQL Injection, XSS, Brute Force, DDoS, CSRF, IDOR, Path Traversal, Command Injection, LDAP Injection, CRLF Header Injection.

---

## 🎯 Mục tiêu

- Kiểm thử 15 lỗ hổng bảo mật phổ biến (OWASP Top 10) trên OrangeHRM
- Mỗi test case viết ở **mức chi tiết cao** (high detail) — step-by-step, có Expected rõ ràng
- Dữ liệu test đọc từ `test_cases.csv` (data-driven)
- Tổ chức theo module chức năng: Login, Directory, PIM, Leave, Buzz, Dashboard, Session

---

## 📁 Cấu trúc thư mục

```
selenium_security/
├── README.md                          # File này - hướng dẫn
├── pytest.ini                         # Cấu hình pytest
├── conftest.py                        # Setup driver, fixtures chung
├── requirements.txt                   # Thư viện cần cài
│
├── Locators/                          # Chứa locators cho OrangeHRM
│   ├── __init__.py
│   └── orangehrm_locators.py          # XPath/CSS selectors cho từng trang
│
├── TestData/                          # Chứa dữ liệu test
│   ├── __init__.py
│   ├── security_test_data.py          # Helper đọc CSV
│   └── test_cases_security.csv        # 15 test case data
│
├── TestCases/                         # Chứa các file test
│   ├── __init__.py
│   ├── test_TC01_SQLi_Login_Username.py
│   ├── test_TC02_SQLi_Login_Password.py
│   ├── test_TC03_SQLi_Search_Employee.py
│   ├── test_TC04_SQLi_Add_Employee_PIM.py
│   ├── test_TC05_XSS_Search_Directory.py
│   ├── test_TC06_XSS_Employee_FirstName.py
│   ├── test_TC07_XSS_Buzz_Post.py
│   ├── test_TC08_Command_Injection_Leave.py
│   ├── test_TC09_Brute_Force_Login.py
│   ├── test_TC10_DoS_Dashboard.py
│   ├── test_TC11_CSRF_Logout.py
│   ├── test_TC12_IDOR_Employee_Detail.py
│   ├── test_TC13_Path_Traversal_Buzz.py
│   ├── test_TC14_LDAP_Injection_Login.py
│   └── test_TC15_Header_Injection_CRLF.py
│
└── TestReports/                       # Output: screenshots, logs, report.html
    ├── screenshots/
    └── logs/
```

---

## 🚀 Cài đặt

```bash
# 1. Cài Python 3.8+
# 2. Tạo virtual env
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/Mac

# 3. Cài thư viện
pip install -r requirements.txt
```

## ▶️ Chạy test

```bash
# Chạy 1 test cụ thể
pytest TestCases/test_TC01_SQLi_Login_Username.py -v --html=TestReports/report.html

# Chạy tất cả security tests
pytest TestCases/ -v --html=TestReports/report.html

# Chạy theo marker
pytest -m security -v
```

---

## 📋 15 Test Cases (mức chi tiết cao)

| ID | Test Case | Module | Loại tấn công |
|----|-----------|--------|---------------|
| TC1 | SQLi_Login_Username | Login | SQL Injection |
| TC2 | SQLi_Login_Password | Login | SQL Injection |
| TC3 | SQLi_Search_Employee_Directory | Directory | SQL Injection |
| TC4 | SQLi_Add_Employee_PIM | PIM | SQL Injection |
| TC5 | XSS_Reflected_Search_Directory | Directory | XSS Reflected |
| TC6 | XSS_Stored_Employee_FirstName | PIM | XSS Stored |
| TC7 | XSS_Stored_Buzz_Post | Buzz | XSS Stored |
| TC8 | Command_Injection_Leave_Reason | Leave | Command Injection |
| TC9 | Brute_Force_Login_5times | Login | Brute Force |
| TC10 | DoS_1000_Requests_Dashboard | Dashboard | DDoS |
| TC11 | CSRF_Logout_GET | Session | CSRF |
| TC12 | IDOR_Employee_Detail | PIM | IDOR |
| TC13 | Path_Traversal_Buzz_Upload | Buzz | Path Traversal |
| TC14 | LDAP_Injection_Login | Login | LDAP Injection |
| TC15 | Header_Injection_CRLF | Session | CRLF Injection |

---

## 📝 Quy ước viết test (mức chi tiết cao)

Mỗi test case file có cấu trúc:
- **Mục tiêu**: Mô tả ngắn
- **Pre-condition**: Trạng thái trước khi test
- **Test data**: Username, password, payload
- **Steps**: Từng bước (Step 1, Step 2, ...) có comment trong code
- **Expected**: Kết quả mong đợi
- **Assert**: Câu lệnh kiểm tra
- **Cleanup**: Dọn dẹp sau test

---

## 👤 Tác giả

- Bài tập buoi6 - Security Testing
- Test target: [OrangeHRM Demo](https://opensource-demo.orangehrmlive.com/)
- Default account: `Admin` / `admin123`
