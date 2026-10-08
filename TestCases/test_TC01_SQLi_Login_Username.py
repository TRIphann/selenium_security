"""
TC01 - SQL Injection Login Username
=====================================
Test ID:         TC01_SQLi_Login_Username
Test Name:       SQLi_Login_Username
Target Module:   Login Page (https://opensource-demo.orangehrmlive.com/web/index.php/auth/login)
Type:            Security - SQL Injection
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Login cua OrangeHRM co bi tan cong SQL Injection
    o truong Username hay khong. Hacker co the dung payload
    "Admin' OR '1'='1" de bypass authentication va truy cap
    trai phep vao tai khoan Admin.

Pre-condition:
    - Webdriver da san sang (Chrome/Firefox/Edge)
    - URL OrangeHRM demo con hoat dong
    - Khong co session dang nhap truoc do
    - Da biet username hop le: "Admin", password: "admin123"

Test Data:
    - Username (payload SQLi):  Admin' OR '1'='1
    - Password (gia tri binh thuong):  admin123
    - Expected URL sau khi submit:  van o trang /auth/login
    - Expected message:            "Invalid credentials"

Steps:
    Step 1: Dieu huong den trang Login cua OrangeHRM
    Step 2: Cho trang load xong (wait for username input)
    Step 3: Nhap payload SQL Injection vao o Username
    Step 4: Nhap password "admin123" vao o Password
    Step 5: Click nut Login
    Step 6: Doi response tu server (1.5s)
    Step 7: Kiem tra URL hien tai - phai VAN o trang login
    Step 8: Kiem tra thong bao loi "Invalid credentials" xuat hien
    Step 9: Kiem tra khong co nut Logout tren trang (chua dang nhap thanh cong)
    Step 10: Kiem tra khong co loi SQL syntax bi loi ra ngoai (information disclosure)

Expected:
    - Trang KHONG dang nhap thanh cong
    - URL giu nguyen o trang /auth/login
    - Hien thi thong bao "Invalid credentials"
    - Khong co loi SQL syntax bi phoi bay (an toan thong tin DB)
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
from Locators.orangehrm_locators import (
    OrangeHRMLoginLocators,
    OrangeHRMCommonLocators,
    SecurityEndpoints,
)


class TestTC01SQLiLoginUsername:
    """Test class cho TC01 - SQL Injection o truong Username cua trang Login"""

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
    def test_TC01_SQLi_Login_Username_bypass_authentication(self):
        """
        TC01 - SQL Injection Login Username

        Mo ta chi tiet:
            Kiem tra xem OrangeHRM co cho phep dang nhap bang payload
            SQL Injection "Admin' OR '1'='1" hay khong.

            Logic tan cong:
                - Cau SQL goc:   SELECT * FROM users WHERE username='<input>' AND password='<pwd>'
                - Sau khi nhap:  SELECT * FROM users WHERE username='Admin' OR '1'='1' AND password='admin123'
                - Dieu kien OR '1'='1' luon dung -> bypass password check
                - Neu he thong KHONG su dung parameterized query, hacker se vao duoc

            He thong AN TOAN se:
                - Su dung parameterized query / ORM (Hibernate, JPA, ...)
                - Escape ky tu dac biet (')
                - Hien thi "Invalid credentials" ma khong can biet user co ton tai khong
        """
        # ----------------- TEST DATA -----------------
        sql_payload = "Admin' OR '1'='1"
        password = "admin123"
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

        # ==================== STEP 3: Nhap SQL payload vao Username ====================
        print(f"[STEP 3] Nhap payload SQLi vao Username: {sql_payload!r}")
        username_input.clear()
        username_input.send_keys(sql_payload)

        # Verify gia tri da duoc nhap
        actual_value = username_input.get_attribute("value")
        assert actual_value == sql_payload, \
            f"Username input phai chua payload. Actual: {actual_value!r}"

        # ==================== STEP 4: Nhap password hop le vao Password ====================
        print("[STEP 4] Nhap password 'admin123' vao Password field")
        password_input = self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys(password)

        # ==================== STEP 5: Click nut Login ====================
        print("[STEP 5] Click button Login")
        login_button = self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.LOGIN_BUTTON
        )
        login_button.click()

        # ==================== STEP 6: Doi response tu server ====================
        print("[STEP 6] Cho server xu ly (1.5s)")
        time.sleep(1.5)

        # ==================== STEP 7: Kiem tra URL van o trang login ====================
        current_url = self.driver.current_url
        print(f"[STEP 7] Current URL: {current_url}")
        assert expected_url_contains in current_url, \
            f"URL phai van o trang login (chua dang nhap thanh cong). " \
            f"Expected contains: {expected_url_contains!r}, Actual: {current_url!r}"

        # ==================== STEP 8: Kiem tra thong bao "Invalid credentials" ====================
        print("[STEP 8] Kiem tra thong bao 'Invalid credentials' xuat hien")
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

        # ==================== STEP 9: Kiem tra khong co nut Logout ====================
        print("[STEP 9] Kiem tra khong co nut Logout (chua dang nhap thanh cong)")
        logout_elements = self.driver.find_elements(
            By.XPATH, OrangeHRMDashboardLocators.LOGOUT_LINK
            if False else "//a[text()='Logout']"
        )
        # Note: vi chua dang nhap, khong co dropdown user, nen khong co nut Logout
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
        ]
        leaked_errors = [kw for kw in sql_error_keywords if kw.lower() in page_source.lower()]
        assert len(leaked_errors) == 0, \
            f"HE THONG BI LOI SQL SYNTAX! Khong duoc phep phoi bay thong tin DB. " \
            f"Cac keyword bi loi: {leaked_errors}"

        # ==================== FINAL: Test PASS ====================
        print("\n[RESULT] TC01 PASSED - He thong CHONG duoc SQLi o Username")
        print("         - URL van o trang login")
        print("         - Hien thi 'Invalid credentials'")
        print("         - Khong co SQL syntax error")
        print("         - Khong co nut Logout (chua bi bypass)")
        assert True


# Import rieng de tranh circular import trong final check
from Locators.orangehrm_locators import OrangeHRMDashboardLocators
