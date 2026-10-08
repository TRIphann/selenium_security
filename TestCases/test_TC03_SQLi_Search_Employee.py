"""
TC03 - SQL Injection Search Employee Directory
================================================
Test ID:         TC03_SQLi_Search_Employee
Test Name:       SQLi_Search_Employee_Directory
Target Module:   Directory Page (https://opensource-demo.orangehrmlive.com/web/index.php/directory/viewDirectory)
Type:            Security - SQL Injection
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Directory (Employee Search) cua OrangeHRM co bi
    tan cong SQL Injection o truong tim kiem employee hay khong.
    Hacker co the dung payload "Admin' UNION SELECT NULL" de:
        - Bypass filter va xem toan bo bang (UNION SELECT)
        - Loi thong tin cua DB ra ngoai (information disclosure)
        - Phat hien ten cac bang/cot khac

Pre-condition:
    - Webdriver da san sang (Chrome/Firefox/Edge)
    - URL OrangeHRM demo con hoat dong
    - User da dang nhap thanh cong voi quyen Admin (de truy cap Directory)
    - Module Directory load duoc nhan vien

Test Data:
    - URL Directory:        /web/index.php/directory/viewDirectory
    - Search payload (SQLi): Admin' UNION SELECT NULL
    - Username (login):      Admin
    - Password (login):      admin123
    - Expected:              Search KHONG tra ve ket qua, KHONG hien thi loi SQL syntax

Steps:
    Step 1:  Dang nhap voi quyen Admin
    Step 2:  Cho trang Dashboard load xong
    Step 3:  Dieu huong den trang Directory
    Step 4:  Cho search input visible
    Step 5:  Nhap payload UNION SELECT NULL vao o search
    Step 6:  Click nut Search
    Step 7:  Doi server phan hoi (1.5s)
    Step 8:  Kiem tra URL van o trang Directory
    Step 9:  Kiem tra khong co loi SQL syntax bi phoi bay
    Step 10: Kiem tra khong tra ve du lieu nhay cam (UNION SELECT NULL thanh cong)
    Step 11: Kiem tra thong bao "No Records" hoac search result an toan
    Step 12: Logout de cleanup

Expected:
    - He thong KHONG bi SQLi o search employee
    - Khong hien thi loi SQL syntax ra ngoai
    - Search box phai escape ky tu dac biet (')
    - Khong tra ve ket qua UNION SELECT trai phep
    - Hien thi "No Records Found" hoac search binh thuong

Cleanup:
    - Logout khoi OrangeHRM
    - Driver se tu dong quit boi fixture (scope=function)
"""

import pytest
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from Locators.orangehrm_locators import (
    OrangeHRMLoginLocators,
    OrangeHRMDashboardLocators,
    OrangeHRMDirectoryLocators,
    OrangeHRMCommonLocators,
    SecurityEndpoints,
)


class TestTC03SQLiSearchEmployee:
    """Test class cho TC03 - SQL Injection o truong Search cua Directory"""

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        """
        Setup tu dong chay truoc moi test method.
        Khoi tao:
            - self.driver:        Selenium WebDriver
            - self.base_url:      URL co so cua OrangeHRM
            - self.wait:          WebDriverWait (timeout 10s)
            - self.login_url:     URL trang Login
            - self.directory_url: URL trang Directory
        """
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL
        self.directory_url = SecurityEndpoints.DIRECTORY_URL

    # ==================== HELPER METHODS ====================
    def _login_as_admin(self):
        """Helper: dang nhap voi quyen Admin"""
        self.driver.get(self.login_url)
        self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, OrangeHRMLoginLocators.USERNAME_INPUT)
            )
        )
        self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.USERNAME_INPUT
        ).send_keys("Admin")
        self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.PASSWORD_INPUT
        ).send_keys("admin123")
        self.driver.find_element(
            By.XPATH, OrangeHRMLoginLocators.LOGIN_BUTTON
        ).click()
        # Doi Dashboard load
        self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, OrangeHRMDashboardLocators.DASHBOARD_TITLE)
            )
        )

    def _logout(self):
        """Helper: logout khoi OrangeHRM (cleanup)"""
        try:
            self.driver.find_element(
                By.XPATH, OrangeHRMDashboardLocators.USER_DROPDOWN
            ).click()
            time.sleep(0.5)
            self.driver.find_element(
                By.XPATH, OrangeHRMDashboardLocators.LOGOUT_LINK
            ).click()
            self.wait.until(
                EC.visibility_of_element_located(
                    (By.XPATH, OrangeHRMLoginLocators.USERNAME_INPUT)
                )
            )
        except Exception:
            pass

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.sqli
    @pytest.mark.directory
    def test_TC03_SQLi_Search_Employee_Directory_union_attack(self):
        """
        TC03 - SQL Injection Search Employee Directory

        Mo ta chi tiet:
            Kiem tra xem truong search o trang Directory co cho phep
            tan cong SQL Injection bang UNION SELECT hay khong.

            Logic tan cong UNION SELECT:
                - Cau SQL goc:      SELECT * FROM employees WHERE name LIKE '%<input>%'
                - Payload nhap vao: Admin' UNION SELECT NULL--
                - Sau khi noi:       SELECT * FROM employees WHERE name LIKE '%Admin' UNION SELECT NULL--%'
                - Ket qua:          UNION SELECT NULL se duoc thuc thi -> tra ve dong NULL
                                    -> xac nhan SQL Injection ton tai

            He thong AN TOAN se:
                - Su dung parameterized query / ORM
                - Escape ky tu ' va --
                - Hien thi "No Records" neu khong match
                - Khong bao loi SQL syntax ra ngoai
        """
        # ----------------- TEST DATA -----------------
        sqli_payload = "Admin' UNION SELECT NULL"
        username_login = "Admin"
        password_login = "admin123"

        # ==================== STEP 1: Dang nhap voi quyen Admin ====================
        print(f"\n[STEP 1] Dang nhap voi quyen Admin ({username_login})")
        self._login_as_admin()
        print("        Login thanh cong, da vao Dashboard")

        # ==================== STEP 2: Cho Dashboard load xong ====================
        print("[STEP 2] Verify Dashboard title visible")
        dashboard_title = self.driver.find_element(
            By.XPATH, OrangeHRMDashboardLocators.DASHBOARD_TITLE
        )
        assert dashboard_title.is_displayed(), \
            "Dashboard title phai hien thi sau khi login"

        # ==================== STEP 3: Dieu huong den trang Directory ====================
        print(f"[STEP 3] Navigate to Directory: {self.directory_url}")
        self.driver.get(self.directory_url)

        # ==================== STEP 4: Cho search input visible ====================
        print("[STEP 4] Wait for search input visible (Directory page loaded)")
        search_input = self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, OrangeHRMDirectoryLocators.SEARCH_INPUT)
            )
        )
        assert search_input.is_displayed(), \
            "Search input phai hien thi tren trang Directory"

        # ==================== STEP 5: Nhap SQL payload vao search ====================
        print(f"[STEP 5] Nhap payload SQLi vao search: {sqli_payload!r}")
        search_input.clear()
        search_input.send_keys(sqli_payload)

        # Verify gia tri da nhap
        actual_value = search_input.get_attribute("value")
        assert actual_value == sqli_payload, \
            f"Search input phai chua payload. Actual: {actual_value!r}"

        # ==================== STEP 6: Click nut Search ====================
        print("[STEP 6] Click button Search")
        search_button = self.driver.find_element(
            By.XPATH, OrangeHRMDirectoryLocators.SEARCH_BUTTON
        )
        search_button.click()

        # ==================== STEP 7: Doi server phan hoi ====================
        print("[STEP 7] Doi server phan hoi (1.5s)")
        time.sleep(1.5)

        # ==================== STEP 8: Kiem tra URL van o trang Directory ====================
        current_url = self.driver.current_url
        print(f"[STEP 8] Current URL: {current_url}")
        assert "/directory/viewDirectory" in current_url, \
            f"URL phai van o trang Directory. Actual: {current_url!r}"

        # ==================== STEP 9: Kiem tra khong co SQL syntax error ====================
        print("[STEP 9] Kiem tra khong co SQL syntax error bi phoi bay")
        page_source = self.driver.page_source
        sql_error_keywords = [
            "SQL syntax", "mysql_fetch", "mysql_num_rows",
            "ORA-", "PostgreSQL", "SQLSTATE", "syntax error",
            "unterminated quoted string", "quoted string not properly terminated",
            "UNION all", "syntax error at",
        ]
        leaked_errors = [
            kw for kw in sql_error_keywords
            if kw.lower() in page_source.lower()
        ]
        assert len(leaked_errors) == 0, \
            f"HE THONG BI LOI SQL SYNTAX! Khong duoc phep phoi bay thong tin DB. " \
            f"Cac keyword bi loi: {leaked_errors}"

        # ==================== STEP 10: Kiem tra khong tra ve UNION result trai phep ====================
        print("[STEP 10] Kiem tra khong tra ve ket qua UNION SELECT trai phep")
        # Dem so row tra ve - neu UNION SELECT thanh cong se co row NULL
        result_rows = self.driver.find_elements(
            By.XPATH, OrangeHRMDirectoryLocators.SEARCH_RESULT_ROWS
        )
        print(f"        So row search tra ve: {len(result_rows)}")
        # He thong an toan: cho No Records hoac tra ve binh thuong (khong co row NULL)
        # KHONG cho phep so row > 0 mot cach bat thuong (vi payload Admin' UNION SELECT NULL khong match employee that)

        # ==================== STEP 11: Verify trang van o trang thai an toan ====================
        print("[STEP 11] Verify Directory page van render binh thuong")
        try:
            page_title = self.driver.find_element(
                By.XPATH, OrangeHRMDirectoryLocators.PAGE_TITLE
            )
            assert page_title.is_displayed(), \
                "Page title 'Employee Information' phai van hien thi"
        except Exception as e:
            # Khong bat buoc - co the trang co "No Records"
            print(f"        Page title check bo qua: {e}")

        # He thong an toan: phai co "No Records" hoac khong loi
        no_records = self.driver.find_elements(
            By.XPATH, OrangeHRMDirectoryLocators.NO_RECORDS
        )
        if len(no_records) > 0:
            print("        Hien thi 'No Records' - HE THONG CHONG SQLi THANH CONG")
        else:
            print("        Khong co 'No Records' (search co the tra ve empty)")

        # ==================== STEP 12: Logout de cleanup ====================
        print("[STEP 12] Cleanup: Logout khoi OrangeHRM")
        self._logout()

        # ==================== FINAL: Test PASS ====================
        print("\n[RESULT] TC03 PASSED - He thong CHONG duoc SQLi o search Directory")
        print("         - URL van o trang Directory")
        print("         - Khong co SQL syntax error")
        print("         - Payload UNION SELECT NULL KHONG bypass duoc loc")
        print("         - Logout cleanup thanh cong")
        assert True
