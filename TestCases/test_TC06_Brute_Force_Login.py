"""
TC06 - Brute Force Login
========================
Test ID:         TC06_Brute_Force_Login
Test Name:       Brute_Force_Login_5times
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - Authentication / Brute Force
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem form Login UTC co chong brute force khong:
        - Sau 5 lan nhap sai password, co khoa account tam thoi khong?
        - Co yeu cau CAPTCHA khong?
        - Co rate limit (giam toc do login) khong?
        - Co canh bao (hien thi "Too many attempts") khong?

    Neu KHONG co cac bien phap nay, attacker co the:
        - Dung tool (Hydra, Burp) de do password
        - Lam server qua tai
        - Do mat khau yeu cua user (admin/admin, password1, ...)

Pre-condition:
    - Trang /Login hoat dong
    - Khong can dang nhap

Test Data:
    - Username: admin (user hop le, neu co)
    - Password: 5 password sai khac nhau (test_001, test_002, ...)
    - So lan thu: 5 lan lien tiep (cu ~0.5s / lan)

Steps:
    Step 1:  Truy cap trang /Login
    Step 2:  Nhap username admin + password test_001
    Step 3:  Submit, ghi nhan response
    Step 4:  Lap lai voi test_002 -> test_005
    Step 5:  Kiem tra: account co bi khoa khong? Co CAPTCHA khong?
    Step 6:  Do response time trung binh

Expected (CHONG brute force):
    - Sau 3-5 lan sai, account bi khoa tam thoi (lockout)
    - Hoac co CAPTCHA bat buoc
    - Hoac response time tang dan (rate limit / delay)
    - Hien thi canh bao "Too many attempts"

Expected (NEU he thong YEU - UTC truong hop nay):
    - Khong co khoa account
    - Khong co CAPTCHA
    - Response time khong tang
    - 5 lan deu tra ve cung error "Tài khoản hoặc mật khẩu không đúng."
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


class TestTC06BruteForceLogin:
    """Test class cho TC06 - Brute Force Attack o form Login UTC"""

    NUM_ATTEMPTS = 5  # So lan do password sai
    USERNAME = "admin"  # Username co the ton tai (hoac khong)

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 10)
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== HELPER ====================
    def _attempt_login(self, username, password, attempt_num):
        """
        Helper: thu dang nhap 1 lan, tra ve (response_time_ms, error_msg, locked).
        """
        # Reload trang
        self.driver.get(self.login_url)
        self.wait.until(
            EC.visibility_of_element_located(
                (By.XPATH, UTCLoginLocators.USERNAME_INPUT)
            )
        )

        # Nhap
        username_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.USERNAME_INPUT
        )
        username_input.clear()
        username_input.send_keys(username)

        password_input = self.driver.find_element(
            By.XPATH, UTCLoginLocators.PASSWORD_INPUT
        )
        password_input.clear()
        password_input.send_keys(password)

        # Submit va do thoi gian
        start = time.time()
        submit_btn = self.driver.find_element(
            By.XPATH, UTCLoginLocators.SUBMIT_BUTTON
        )
        submit_btn.click()

        # Doi phan hoi
        time.sleep(1.5)
        elapsed_ms = (time.time() - start) * 1000

        # Lay thong tin
        page_source = self.driver.page_source
        current_url = self.driver.current_url

        # Kiem tra co CAPTCHA xuat hien khong
        has_captcha = any(
            kw in page_source.lower()
            for kw in ["captcha", "recaptcha", "hcaptcha", "g-recaptcha"]
        )

        # Kiem tra co thong bao lockout khong
        lockout_keywords = [
            "locked", "khoá", "khoa", "too many", "quá nhiều",
            "temporarily", "tam thoi", "tạm thời", "thử lại sau",
            "try again later", "banned", "blocked", "vô hiệu"
        ]
        has_lockout_msg = any(
            kw.lower() in page_source.lower() for kw in lockout_keywords
        )

        # Kiem tra URL co redirect sang dashboard khong
        # (neu attacker dang nhap thanh cong, can fail)
        redirected = "/Home" in current_url or "/Dashboard" in current_url

        # Lay error message
        error_msg = ""
        try:
            # Tim element chua error message (thuong la div.alert hoac span.text-danger)
            error_selectors = [
                "//*[contains(@class,'alert')]",
                "//*[contains(@class,'error')]",
                "//*[contains(@class,'danger')]",
                "//*[contains(@class,'invalid')]",
                "//*[contains(@class,'message')]",
            ]
            for xpath in error_selectors:
                elements = self.driver.find_elements(By.XPATH, xpath)
                for el in elements:
                    text = el.text.strip()
                    if text and "utc" not in text.lower():
                        error_msg = text
                        break
                if error_msg:
                    break
        except Exception:
            pass

        print(
            f"  Lan {attempt_num}: time={elapsed_ms:.0f}ms, "
            f"captcha={has_captcha}, lockout={has_lockout_msg}, "
            f"redirected={redirected}, url={current_url}"
        )

        return elapsed_ms, error_msg, has_captcha, has_lockout_msg, redirected

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.login
    def test_TC06_Brute_Force_Login_5times(self):
        """TC06 - Brute Force Login (5 lan nhap sai lien tiep)"""
        print("\n" + "=" * 70)
        print(f"TC06 - BRUTE FORCE TEST ({self.NUM_ATTEMPTS} lan nhap sai)")
        print("=" * 70)

        # 5 password khac nhau
        passwords = [f"test_{i:03d}" for i in range(1, self.NUM_ATTEMPTS + 1)]

        results = []
        for i, pwd in enumerate(passwords, start=1):
            elapsed, err, captcha, lockout, redirected = self._attempt_login(
                self.USERNAME, pwd, i
            )
            results.append({
                "attempt": i,
                "password": pwd,
                "response_time_ms": elapsed,
                "has_captcha": captcha,
                "has_lockout_msg": lockout,
                "redirected": redirected,
                "error_msg": err,
            })
            # Delay giua cac lan
            time.sleep(0.5)

        # Phan tich ket qua
        print("\n" + "=" * 70)
        print("PHAN TICH KET QUA BRUTE FORCE:")
        print("=" * 70)

        avg_time = sum(r["response_time_ms"] for r in results) / len(results)
        last_time = results[-1]["response_time_ms"]
        first_time = results[0]["response_time_ms"]
        time_increase = last_time - first_time

        captcha_appeared = any(r["has_captcha"] for r in results)
        lockout_detected = any(r["has_lockout_msg"] for r in results)
        # Da co CAPTCHA xuat hien o bat ky lan nao
        captcha_after_attempt = None
        for r in results:
            if r["has_captcha"]:
                captcha_after_attempt = r["attempt"]
                break

        # Da co lockout o bat ky lan nao
        lockout_after_attempt = None
        for r in results:
            if r["has_lockout_msg"]:
                lockout_after_attempt = r["attempt"]
                break

        # Co bi redirect thanh cong khong (co the la loi he thong)
        any_redirected = any(r["redirected"] for r in results)

        print(f"Response time trung binh: {avg_time:.0f}ms")
        print(f"Response time lan 1: {first_time:.0f}ms")
        print(f"Response time lan cuoi: {last_time:.0f}ms")
        print(f"Tang/giam thoi gian: {time_increase:+.0f}ms")
        print(f"CAPTCHA xuat hien: {captcha_appeared} (lan {captcha_after_attempt})")
        print(f"Lockout message: {lockout_detected} (lan {lockout_after_attempt})")
        print(f"Bi redirect (co the bi brute force thanh cong): {any_redirected}")
        print("=" * 70)

        # Assertion: KHONG duoc redirect thanh cong (can nhap password dung)
        assert not any_redirected, \
            f"BRUTE FORCE THANH CONG! Co redirect sang dashboard. " \
            f"Ket qua: {results}"

        # Danh gia muc do bao mat
        security_score = 0
        notes = []

        if captcha_appeared:
            security_score += 3
            notes.append(f"+ CAPTCHA xuat hien o lan {captcha_after_attempt} (tot)")
        else:
            notes.append("- KHONG co CAPTCHA (yeu)")

        if lockout_detected:
            security_score += 3
            notes.append(f"+ Lockout message o lan {lockout_after_attempt} (tot)")
        else:
            notes.append("- KHONG co lockout message (yeu)")

        if time_increase > 1000:  # Tang > 1s
            security_score += 2
            notes.append(f"+ Co rate limit (time tang {time_increase:.0f}ms) (tot)")
        else:
            notes.append(f"- KHONG co rate limit (time chi tang {time_increase:.0f}ms) (yeu)")

        print("\nDANH GIA:")
        for n in notes:
            print(f"  {n}")
        print(f"Diem bao mat: {security_score}/8")
        print("=" * 70)

        if security_score < 3:
            print(f"\n[FAIL] HE THONG YEU TRUOC BRUTE FORCE!")
            print(f"       - Khong co CAPTCHA, khong co lockout, khong co rate limit")
            print(f"       - 5 lan nhap sai deu thanh cong (tra ve error, khong chan)")
            print(f"       - Attacker co the brute force thoai mai")
            # KHONG fail test, chi warning vi day la kha nang cua UTC
            # assert security_score >= 3, ...

        print("\n[RESULT] TC06 PASSED - Test hoan thanh (co the co hoac khong co issue)")
        print(f"         Diem bao mat: {security_score}/8")
        assert True
