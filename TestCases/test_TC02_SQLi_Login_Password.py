"""
TC02 - SQL Injection Login Password
=====================================
Test ID:         TC02_SQLi_Login_Password
Test Name:       SQLi_Login_Password
Target Module:   Login Page (https://opensource-demo.orangehrmlive.com/web/index.php/auth/login)
Type:            Security - SQL Injection
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Login cua OrangeHRM co bi tan cong SQL Injection
    o truong PASSWORD hay khong. Hacker co the dung payload
    "' OR '1'='1' -- " trong o Password de bypass xac thuc
    va truy cap vao tai khoan Admin ma khong can biet mat khau that.

    Day la mot dang tan cong rat pho bien vi nhieu lap trinh vien
    chi filter input o username ma quen filter o password.

Pre-condition:
    - Webdriver da san sang (Chrome/Firefox/Edge)
    - URL OrangeHRM demo con hoat dong
    - Khong co session dang nhap truoc do (browser moi)
    - Da biet username hop le: "Admin"

Test Data:
    - Username (gia tri hop le):     Admin
    - Password (payload SQLi):       ' OR '1'='1' --
    - Expected URL sau khi submit:   van o trang /auth/login
    - Expected message:             "Invalid credentials"

Steps:
    Step 1:  Dieu huong den trang Login cua OrangeHRM
    Step 2:  Cho trang load xong (wait for username input visible)
    Step 3:  Nhap username "Admin" vao o Username
    Step 4:  Verify username da duoc nhap thanh cong
    Step 5:  Nhap payload SQLi "' OR '1'='1' --" vao o Password
    Step 6:  Verify password da duoc nhap thanh cong
    Step 7:  Click nut Login
    Step 8:  Doi response tu server (1.5s)
    Step 9:  Kiem tra URL hien tai - phai VAN o trang login
    Step 10: Kiem tra thong bao loi "Invalid credentials" xuat hien
    Step 11: Kiem tra khong co nut Logout tren trang
    Step 12: Kiem tra khong co SQL syntax error bi phoi bay

Expected:
    - Trang KHONG dang nhap thanh cong (SQLi o password bi chan)
    - URL giu nguyen o trang /auth/login
    - Hien thi thong bao "Invalid credentials"
    - Khong co loi SQL syntax bi phoi bay (an toan thong tin DB)
    - Hacker KHONG the bypass authentication qua password

Cleanup:
    - Khong can cleanup vi test khong tao side effect
    - Driver se tu dong quit boi fixture (scope=function)
"""

import pytest
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from Locators.orangehrm_locators import (
    OrangeHRMLoginLocators,
    SecurityEndpoints,
)


class TestTC02SQLiLoginPassword:
    """Test class cho TC02 - SQL Injection o truong Password cua trang Login"""

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        """
        Setup tu dong chay truoc moi test method.
        Khoi tao:
            - self.driver:    Selenium WebDriver
            - self.base_url:  URL co so cua OrangeHRM
            - self.wait:      WebDriverWait (timeout 10s)
            - self.login_url: URL cua trang Login
        """
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.sqli
    @pytest.mark.login
    def test_TC02_SQLi_Login_Password_bypass_authentication(self):
        """
        TC02 - SQL Injection Login Password

        Mo ta chi tiet:
            Kiem tra xem OrangeHRM co cho phep bypass authentication
            bang cach inject SQL o truong Password hay khong.

            Payload:    ' OR '1'='1' --
            Logic tan cong:
                - Cau SQL goc:   SELECT * FROM users
                                 WHERE username='Admin'
                                 AND password='<input>'
                - Sau khi nhap:  SELECT * FROM users
                                 WHERE username='Admin'
                                 AND password='' OR '1'='1' --'
                - Phan password duoc comment boi "--"
                - '1'='1' luon dung -> OR tra ve true
                - Neu he thong KHONG su dung parameterized query,
                  hacker se vao duoc voi username bat ky.

            He thong AN TOAN se:
                - Su dung parameterized query / ORM
                - Validate/escape input o CA username va password
                - Hien thi "Invalid credentials" ma khong can biet
                  user co ton tai hay khong (chong user enumeration)
        """
        # ----------------- TEST DATA -----------------
        valid_username = "Admin"
        sqli_password = "' OR '1'='1' --"
        expected_url_contains = "/auth/login"
        expected_error_substring = "Invalid"

        # ==================== STEP 1: Dieu huong den trang Login ====================
        print(f"\n[STEP 1] Navigate to Login page: {self.login_url}")
        self.driver.get(self.login_url)

        # ==================== STEP 2: Cho trang load xong ====================
        print("[STEP 2] Wait for username input visible (page loaded)")
        username_input = self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, OrangeHRMLoginLocators.USERNAME_INPUT)
            )
        )
        assert username_input.is_displayed(), \
            "Username input phai hien thi tren trang Login"

        # ==================== STEP 3: Nhap username hop le ====================
        print(f"[STEP 3] Nhap username hop le: {valid_username!r}")
        username_input.clear()
        username_input.send_keys(valid_username)

        # ==================== STEP 4: Verify username da duoc nhap ====================
        print("[STEP 4] Verify username input da duoc nhap thanh cong")
        actual_username = username_input.get_attribute("value")
        assert actual_username == valid_username, \
            f"Username input phai chua '{valid_username}'. " \
            f"Actual: {actual_username!r}"

        # ==================== STEP 5: Nhap SQL payload vao Password ====================
        print(f"[STEP 5] Nhap payload SQLi vao Password: {sqli_password!r}")
        password_input = self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys(sqli_password)

        # ==================== STEP 6: Verify password da duoc nhap ====================
        print("[STEP 6] Verify password input da duoc nhap thanh cong")
        actual_password = password_input.get_attribute("value")
        assert actual_password == sqli_password, \
            f"Password input phai chua payload. Actual: {actual_password!r}"

        # ==================== STEP 7: Click nut Login ====================
        print("[STEP 7] Click button Login")
        login_button = self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.LOGIN_BUTTON
        )
        login_button.click()

        # ==================== STEP 8: Doi response tu server ====================
        print("[STEP 8] Cho server xu ly (1.5s)")
        time.sleep(1.5)

        # ==================== STEP 9: Kiem tra URL van o trang login ====================
        current_url = self.driver.current_url
        print(f"[STEP 9] Current URL: {current_url}")
        assert expected_url_contains in current_url, \
            f"URL phai van o trang login (chua dang nhap thanh cong). " \
            f"Expected contains: {expected_url_contains!r}, " \
            f"Actual: {current_url!r}"

        # ==================== STEP 10: Kiem tra thong bao "Invalid credentials" ====================
        print("[STEP 10] Kiem tra thong bao 'Invalid credentials' xuat hien")
        try:
            error_element = self.driver.find_element(
                By.XPATH, OrangeHRMLoginLocators.LOGIN_ERROR_INVALID
            )
            error_text = error_element.text
            print(f"   Error message hien thi: {error_text!r}")
            assert expected_error_substring in error_text, \
                f"Error message phai chua '{expected_error_substring}'. " \
                f"Actual: {error_text!r}"
        except Exception as e:
            pytest.fail(
                f"Khong tim thay thong bao loi 'Invalid credentials'. "
                f"Co the he thong da bi bypass hoac error locator sai. Error: {e}"
            )

        # ==================== STEP 11: Kiem tra khong co nut Logout ====================
        print("[STEP 11] Kiem tra khong co nut Logout (chua dang nhap thanh cong)")
        logout_elements = self.driver.find_elements(
            By.XPATH, "//a[text()='Logout']"
        )
        assert len(logout_elements) == 0, \
            "KHONG duoc co nut Logout vi user chua dang nhap thanh cong. " \
            f"Tim thay {len(logout_elements)} nut Logout - " \
            "co the SQLi o password da bypass thanh cong!"

        # ==================== STEP 12: Kiem tra khong co SQL syntax error ====================
        print("[STEP 12] Kiem tra khong co SQL syntax error bi phoi bay")
        page_source = self.driver.page_source
        sql_error_keywords = [
            "SQL syntax", "mysql_fetch", "mysql_num_rows",
            "ORA-", "PostgreSQL", "SQLSTATE", "syntax error",
            "unterminated quoted string", "quoted string not properly terminated",
        ]
        leaked_errors = [
            kw for kw in sql_error_keywords if kw.lower() in page_source.lower()
        ]
        assert len(leaked_errors) == 0, \
            f"HE THONG BI LOI SQL SYNTAX! Khong duoc phep phoi bay thong tin DB. " \
            f"Cac keyword bi loi: {leaked_errors}"

        # ==================== FINAL: Test PASS ====================
        print("\n[RESULT] TC02 PASSED - He thong CHONG duoc SQLi o Password")
        print("         - URL van o trang login")
        print("         - Hien thi 'Invalid credentials'")
        print("         - Khong co SQL syntax error")
        print("         - Khong co nut Logout (chua bi bypass)")
        assert True
