"""
TC01 - SQL Injection Login Username
=====================================
Test ID:         TC01_SQLi_Login_Username
Test Name:       SQLi_Login_Username
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - SQL Injection
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Login cua UTC Van Phong Dien Tu co bi tan cong
    SQL Injection o truong Username hay khong. Hacker co the dung payload
    "admin' OR '1'='1" de bypass authentication va truy cap trai phep.

Pre-condition:
    - Webdriver da san sang (Chrome/Firefox/Edge)
    - URL https://vanphongdientu.utc.edu.vn/Login con hoat dong
    - Khong co session dang nhap truoc do

Test Data:
    - Username (payload SQLi):  admin' OR '1'='1
    - Password (gia tri binh thuong):  anything
    - Expected URL sau khi submit:  van o trang /Login
    - Expected message:            "Tài khoản hoặc mật khẩu không đúng."

Steps:
    Step 1: Dieu huong den trang Login cua UTC
    Step 2: Cho trang load xong (wait for username input)
    Step 3: Nhap payload SQL Injection vao o Username
    Step 4: Nhap password bat ky vao o Password
    Step 5: Click nut Login (submit)
    Step 6: Doi response tu server (2s)
    Step 7: Kiem tra URL hien tai - phai VAN o trang /Login
    Step 8: Kiem tra thong bao loi xuat hien
    Step 9: Kiem tra khong co nut Logout (chua dang nhap thanh cong)
    Step 10: Kiem tra khong co loi SQL syntax bi loi ra ngoai (information disclosure)

Expected:
    - Trang KHONG dang nhap thanh cong
    - URL giu nguyen o trang /Login
    - Hien thi thong bao loi (Tài khoản hoặc mật khẩu không đúng.)
    - Khong co loi SQL syntax bi phoi bay
    - Hacker KHONG the bypass authentication bang SQLi

Cleanup:
    - Khong can cleanup vi test khong tao side effect
    - Driver se tu dong quit boi fixture (scope=function)
"""

import pytest
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from Locators.utclogin_locators import (
    UTCLoginLocators,
    UTCDashboardLocators,
    SecurityEndpoints,
)


class TestTC01SQLiLoginUsername:
    """Test class cho TC01 - SQL Injection o truong Username cua trang Login UTC"""

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        """
        Setup tu dong chay truoc moi test method.
        """
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.sqli
    @pytest.mark.login
    def test_TC01_SQLi_Login_Username_bypass_authentication(self):
        """
        TC01 - SQL Injection Login Username

        Mo ta chi tiet:
            Kiem tra xem UTC Van Phong Dien Tu co cho phep dang nhap bang
            payload SQL Injection "admin' OR '1'='1" hay khong.

            Logic tan cong:
                - Cau SQL goc:   SELECT * FROM users WHERE username='<input>' AND password='<pwd>'
                - Sau khi nhap:  SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
                - Dieu kien OR '1'='1' luon dung -> bypass password check
                - Neu he thong KHONG su dung parameterized query, hacker se vao duoc

            He thong AN TOAN se:
                - Su dung parameterized query / ORM
                - Hien thi "Tài khoản hoặc mật khẩu không đúng." ma khong can biet
                  user co ton tai khong
        """
        # ----------------- TEST DATA -----------------
        sql_payload = "admin' OR '1'='1"
        password = "anything"
        expected_url_contains = "/Login"
        # Trang UTC co the tra cac thong bao sau:
        expected_error_substrings = [
            "Tài khoản hoặc mật khẩu không đúng",
            "Invalid",
            "Sai",
            "không đúng",
        ]

        # ==================== STEP 1: Dieu huong den trang Login ====================
        print(f"\n[STEP 1] Navigate to Login page: {self.login_url}")
        self.driver.get(self.login_url)

        # ==================== STEP 2: Cho trang load xong ====================
        print("[STEP 2] Wait for username input visible (page loaded)")
        username_input = self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, UTCLoginLocators.USERNAME_INPUT)
            )
        )
        assert username_input.is_displayed(), \
            "Username input phai hien thi tren trang Login"

        # ==================== STEP 3: Nhap SQL payload vao Username ====================
        print(f"[STEP 3] Nhap payload SQLi vao Username: {sql_payload!r}")
        username_input.clear()
        username_input.send_keys(sql_payload)

        # Verify gia tri da duoc nhap
        actual_value = username_input.get_attribute("value")
        assert actual_value == sql_payload, \
            f"Username input phai chua payload. Actual: {actual_value!r}"

        # ==================== STEP 4: Nhap password bat ky vao Password ====================
        print("[STEP 4] Nhap password vao Password field")
        password_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys(password)

        # ==================== STEP 5: Click nut Login ====================
        print("[STEP 5] Click button Login (submit)")
        login_button = self.driver.find_element(
            By.XPATH, UTCLoginLocators.SUBMIT_BUTTON
        )
        login_button.click()

        # ==================== STEP 6: Doi response tu server ====================
        print("[STEP 6] Cho server xu ly (2s)")
        time.sleep(2)

        # ==================== STEP 7: Kiem tra URL van o trang login ====================
        current_url = self.driver.current_url
        print(f"[STEP 7] Current URL: {current_url}")
        assert expected_url_contains in current_url, \
            f"URL phai van o trang login (chua dang nhap thanh cong). " \
            f"Expected contains: {expected_url_contains!r}, Actual: {current_url!r}"

        # ==================== STEP 8: Kiem tra thong bao loi ====================
        print("[STEP 8] Kiem tra thong bao loi xuat hien")
        error_text = ""
        try:
            error_element = self.driver.find_element(
                By.XPATH, UTCLoginLocators.ERROR_DIV
            )
            error_text = error_element.text
            print(f"   Error message hien thi: {error_text!r}")
        except Exception:
            # Fallback: thu ERROR_ANY
            try:
                error_element = self.driver.find_element(
                    By.XPATH, UTCLoginLocators.ERROR_ANY
                )
                error_text = error_element.text
                print(f"   Error message (fallback) hien thi: {error_text!r}")
            except Exception as e:
                pytest.fail(
                    f"Khong tim thay thong bao loi tren trang. "
                    f"Co the he thong da bi bypass hoac error locator sai. Error: {e}"
                )

        # Kiem tra thong bao loi co noi dung mong doi (case-insensitive)
        error_text_lower = error_text.lower()
        matched = any(
            sub.lower() in error_text_lower
            for sub in expected_error_substrings
        )
        assert matched, \
            f"Error message phai chua mot trong cac substring: {expected_error_substrings}. " \
            f"Actual: {error_text!r}"

        # ==================== STEP 9: Kiem tra khong co nut Logout ====================
        print("[STEP 9] Kiem tra khong co nut Logout (chua dang nhap thanh cong)")
        logout_elements = self.driver.find_elements(
            By.XPATH, UTCDashboardLocators.LOGOUT_LINK
        )
        assert len(logout_elements) == 0, \
            "KHONG duoc co nut Logout vi user chua dang nhap thanh cong. " \
            f"Tim thay {len(logout_elements)} nut Logout - co the da bi SQLi bypass!"

        # ==================== STEP 10: Kiem tra khong co SQL syntax error ====================
        print("[STEP 10] Kiem tra khong co SQL syntax error bi phoi bay")
        page_source = self.driver.page_source
        sql_error_keywords = [
            "SQL syntax", "mysql_fetch", "mysql_num_rows",
            "ORA-", "PostgreSQL", "SQLSTATE", "syntax error",
            "unterminated quoted string", "quoted string not properly terminated",
            "You have an error in your SQL syntax",
        ]
        leaked_errors = [kw for kw in sql_error_keywords if kw.lower() in page_source.lower()]
        assert len(leaked_errors) == 0, \
            f"HE THONG BI LOI SQL SYNTAX! Khong duoc phep phoi bay thong tin DB. " \
            f"Cac keyword bi loi: {leaked_errors}"

        # ==================== FINAL: Test PASS ====================
        print("\n[RESULT] TC01 PASSED - He thong CHONG duoc SQLi o Username")
        print("         - URL van o trang /Login")
        print("         - Hien thi thong bao loi dang mong doi")
        print("         - Khong co SQL syntax error")
        print("         - Khong co nut Logout (chua bi bypass)")
        assert True
