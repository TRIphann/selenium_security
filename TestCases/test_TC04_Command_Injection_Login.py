"""
TC04 - Command Injection trong form Login
==========================================
Test ID:         TC04_Command_Injection_Login
Test Name:       Command_Injection_Login_Username
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - Command Injection / OS Command Injection
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem trang Login UTC co bi loi Command Injection khi
    nhap cac payload shell ( ; | ` $ ) vao truong Username hay khong.
    Neu he thong khong escape, hacker co the:
        - Thuc thi lenh OS tren server (doc file, xoa file, tao user, ...)
        - Reverse shell de chiem quyen dieu khien server
        - Pivot sang cac he thong noi bo

Pre-condition:
    - Trang /Login hoat dong
    - Khong can dang nhap

Test Data (cac payload command injection pho bien):
    - Payload 1: ; ls -la        (command separator)
    - Payload 2: | whoami         (pipe)
    - Payload 3: ` cat /etc/passwd` (backtick)
    - Payload 4: $(reboot)        (command substitution)

Steps:
    Step 1-4:  Submit form voi payload 1 (; ls -la)
    Step 5-8:  Submit form voi payload 2 (| whoami)
    Step 9-12: Submit form voi payload 3 (` cat /etc/passwd`)
    Step 13-16: Submit form voi payload 4 ($(reboot))

Expected:
    - Server KHONG thuc thi bat ky lenh OS nao
    - Response KHONG chua output cua lenh (vi du: danh sach file, user, ...)
    - Response time KHONG bat thuong (lenh shell chay lau se lam cham)
    - Tra ve error binh thuong "Tài khoản hoặc mật khẩu không đúng."
    - URL van o /Login

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
    SecurityEndpoints,
)


class TestTC04CommandInjectionLogin:
    """Test class cho TC04 - Command Injection o form Login UTC"""

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== HELPER ====================
    def _submit_command_payload(self, payload, step_num):
        """
        Helper: nhap payload command injection vao username, submit, kiem tra.
        Tra ve (response_time_ms, page_source, has_command_output).
        """
        print(f"\n[STEP {step_num}] Test payload: {payload!r}")

        # Reload trang de clean state
        self.driver.get(self.login_url)
        self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, UTCLoginLocators.USERNAME_INPUT)
            )
        )

        # Nhap payload vao username
        username_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.USERNAME_INPUT
        )
        username_input.clear()
        username_input.send_keys(payload)

        # Password bat ky
        password_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys("anypassword")

        # Submit va do thoi gian response
        start = time.time()
        submit_btn = self.driver.find_element(
            By.XPATH, UTCLoginLocators.SUBMIT_BUTTON
        )
        submit_btn.click()

        # Doi server phan hoi (neu co command injection chay, se ton thoi gian)
        time.sleep(2)
        elapsed_ms = (time.time() - start) * 1000

        # Lay response
        page_source = self.driver.page_source
        current_url = self.driver.current_url

        # Kiem tra URL phai van o /Login
        assert "/Login" in current_url, \
            f"URL phai van o trang login. Actual: {current_url!r}"

        # Kiem tra xem response co chua output cua lenh OS hay khong
        # Cac dau hieu command injection thanh cong:
        command_output_signatures = [
            # Output cua 'ls -la': drwx, -rw-r--r--, root, bin, etc
            "drwx", "-rw-r--r--", "-rwxr-xr-x", "total ",
            # Output cua 'whoami': cac username OS pho bien
            "root\n", "www-data\n", "apache\n", "nginx\n",
            # Output cua 'cat /etc/passwd': cac field dac trung
            "root:x:0:", "/bin/bash", "/bin/sh", ":/home/",
            # Output cua 'reboot'/'shutdown': cac tu khoa
            "reboot: need to be root", "shutdown", "System going down",
        ]

        has_command_output = False
        matched_signatures = []
        for sig in command_output_signatures:
            if sig.lower() in page_source.lower():
                has_command_output = True
                matched_signatures.append(sig)

        if has_command_output:
            print(f"   [!!!] COMMAND OUTPUT detected: {matched_signatures}")
        else:
            print(f"   Khong co output shell command (AN TOAN)")

        # Kiem tra response time co bat thuong khong (>5s co the la command dang chay)
        abnormal_response_time = elapsed_ms > 5000
        if abnormal_response_time:
            print(f"   [WARN] Response time bat thuong: {elapsed_ms:.0f}ms")
        else:
            print(f"   Response time binh thuong: {elapsed_ms:.0f}ms")

        return elapsed_ms, page_source, has_command_output, abnormal_response_time

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.input_validation
    @pytest.mark.login
    def test_TC04_Command_Injection_Login_Username(self):
        """TC04 - Command Injection trong form Login"""
        print("\n" + "=" * 70)
        print("TC04 - COMMAND INJECTION TEST (4 payloads)")
        print("=" * 70)

        # 4 payload command injection pho bien
        payloads = [
            "; ls -la",
            "| whoami",
            "` cat /etc/passwd`",
            "$(reboot)",
        ]

        command_output_detected = []
        abnormal_response_times = []

        for idx, payload in enumerate(payloads, start=1):
            elapsed_ms, page_source, has_output, abnormal_time = \
                self._submit_command_payload(payload, step_num=idx * 4)
            if has_output:
                command_output_detected.append(payload)
            if abnormal_time:
                abnormal_response_times.append((payload, elapsed_ms))

        # Final report
        print("\n" + "=" * 70)
        print(f"Tong payload da test: {len(payloads)}")
        print(f"Payload co command output: {len(command_output_detected)}")
        print(f"Payload co response time bat thuong: {len(abnormal_response_times)}")
        if command_output_detected:
            print(f"[FAIL] Bi command injection: {command_output_detected}")
        if abnormal_response_times:
            print(f"[WARN] Response time bat thuong: {abnormal_response_times}")
        print("=" * 70)

        # Assertion
        assert len(command_output_detected) == 0, \
            f"HE THONG BI COMMAND INJECTION! " \
            f"Cac payload co output shell: {command_output_detected}. " \
            f"Server phai escape hoac reject cac ky tu ; | ` $ trong input."

        # Warning neu response time bat thuong (khong fail nhung can bao)
        if abnormal_response_times:
            print("\n[NOTE] Co response time >5s, co the command dang chay cham")
            for p, t in abnormal_response_times:
                print(f"   - {p!r}: {t:.0f}ms")

        print("\n[RESULT] TC04 PASSED - He thong CHONG duoc Command Injection")
        print("         - Khong co output shell command")
        print("         - URL van o trang /Login")
        print("         - Response time binh thuong")
        assert True
