"""
TC03 - XSS Reflected trong form Login
=====================================
Test ID:         TC03_XSS_Reflected_Login
Test Name:       XSS_Reflected_Login_Username
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - Cross-Site Scripting (Reflected)
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Login UTC co bi loi XSS Reflected khi nhap
    payload <script>...</script> vao truong Username hay khong.
    Neu he thong khong escape, hacker co the:
        - Chiem session (cookie theft)
        - Deface trang login
        - Redirect user den trang lua dao
        - Phishing tren cung domain

Pre-condition:
    - Trang /Login hoat dong
    - Khong can dang nhap

Test Data:
    - Payload 1 (script tag):     <script>alert('XSS')</script>
    - Payload 2 (event handler):  <img src=x onerror=alert(1)>
    - Payload 3 (svg):            <svg/onload=alert(1)>

Steps:
    Step 1-4:  Submit form voi payload 1
    Step 5-8:  Submit form voi payload 2
    Step 9-12: Submit form voi payload 3

Expected:
    - Server KHONG render payload nhu HTML (escape <> & ")
    - Khong co alert() nao duoc thuc thi (verify bang Selenium switch_to.alert)
    - Neu co alert -> test FAIL (he thong bi XSS)
"""

import pytest
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException
from Locators.utclogin_locators import (
    UTCLoginLocators,
    SecurityEndpoints,
)


class TestTC03XSSReflectedLogin:
    """Test class cho TC03 - XSS Reflected o form Login UTC"""

    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL

    def _submit_and_check_xss(self, payload, step_num):
        """
        Helper: nhap payload vao username, submit, kiem tra XSS.
        Tra ve (has_alert, alert_text).
        """
        print(f"\n[STEP {step_num}] Test voi payload: {payload!r}")

        # Reload trang de clean state
        self.driver.get(self.login_url)
        self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, UTCLoginLocators.USERNAME_INPUT)
            )
        )

        # Nhap payload
        username_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.USERNAME_INPUT
        )
        username_input.clear()
        username_input.send_keys(payload)

        password_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys("anypassword")

        # Submit
        submit_btn = self.driver.find_element(
            By.XPATH, UTCLoginLocators.SUBMIT_BUTTON
        )
        submit_btn.click()

        # Doi server phan hoi
        time.sleep(2)

        # Lay page source
        page_source = self.driver.page_source

        # 1. Kiem tra payload co bi reflect nguyen xi vao HTML hay khong
        is_reflected_raw = payload in page_source
        print(f"   Payload reflect raw in HTML: {is_reflected_raw}")

        # 2. Kiem tra co alert dialog xuat hien khong
        has_alert = False
        alert_text = ""
        try:
            # Cho alert xuat hien trong 1s
            WebDriverWait(self.driver, 2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            has_alert = True
            alert.dismiss()  # Dong alert
            print(f"   [!!!] ALERT XUAT HIEN: {alert_text!r}")
        except (TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException):
            has_alert = False
            print("   Khong co alert dialog (AN TOAN)")

        # 3. Kiem tra DOM co <script>, <img onerror=...>, <svg onload=...>
        # duoc tao ra tu payload cua user hay khong
        if "<script>" in payload.lower():
            script_in_dom = len(
                self.driver.find_elements(By.XPATH, "//script[contains(text(),'XSS')]")
            )
            if script_in_dom > 0:
                print(f"   [!!!] Found {script_in_dom} <script> in DOM")

        if "onerror" in payload.lower():
            img_in_dom = len(
                self.driver.find_elements(By.XPATH, "//img[contains(@onerror,'alert')]")
            )
            if img_in_dom > 0:
                print(f"   [!!!] Found {img_in_dom} <img onerror> in DOM")

        if "<svg" in payload.lower() and "onload" in payload.lower():
            svg_in_dom = len(
                self.driver.find_elements(By.XPATH, "//*[local-name()='svg' and contains(@onload,'alert')]")
            )
            if svg_in_dom > 0:
                print(f"   [!!!] Found {svg_in_dom} <svg onload> in DOM")

        return has_alert, alert_text

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.xss
    @pytest.mark.login
    def test_TC03_XSS_Reflected_Login_Username(self):
        """TC03 - XSS Reflected trong form Login"""
        print("\n" + "=" * 70)
        print("TC03 - XSS REFLECTED TEST (3 payloads)")
        print("=" * 70)

        # Cac payload XSS pho bien
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]

        xss_detected = []
        alert_texts = []
        for idx, payload in enumerate(payloads, start=1):
            has_alert, alert_text = self._submit_and_check_xss(payload, step_num=idx * 4)
            if has_alert:
                xss_detected.append(payload)
                alert_texts.append(alert_text)

        # Final assertion
        print("\n" + "=" * 70)
        print(f"Tong payload da test: {len(payloads)}")
        print(f"Payload bi XSS (co alert): {len(xss_detected)}")
        if xss_detected:
            print(f"[FAIL] He thong BI XSS voi cac payload: {xss_detected}")
        else:
            print("[OK] Khong co alert nao duoc thuc thi")
        print("=" * 70)

        assert len(xss_detected) == 0, \
            f"HE THONG BI XSS REFLECTED! " \
            f"Cac payload bi render thanh HTML va thuc thi: {xss_detected}. " \
            f"Alert text nhan duoc: {alert_texts}. " \
            f"Server phai escape ky tu < > & \" khi reflect input."

        print("\n[RESULT] TC03 PASSED - He thong CHONG duoc XSS Reflected")
        assert True
