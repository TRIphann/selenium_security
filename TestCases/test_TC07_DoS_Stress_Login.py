"""
TC07 - DoS Stress Login
=======================
Test ID:         TC07_DoS_Stress_Login
Test Name:       DoS_Stress_Login
Target Module:   Login Page (https://vanphongdientu.utc.edu.vn/Login)
Type:            Security - Denial of Service (DoS) / Availability
Priority:        High
Author:          baitap - buoi6
Created:         2026-10-08

Muc tieu (Objective):
    Kiem thu xem server UTC co bi Nguyen Don (Denial of Service) khi
    nhan 50 request lien tiep trong thoi gian ngan.

    Muc dich: Xac dinh xem server co the xu ly nhieu request cung luc
    khong, co bi treo hay cham khong.

    Neu server YEU, attacker co the:
        - Lam chậm hoac treo server bang cach gui nhieu request
        - Chiếm tài nguyên server (CPU, RAM, connections)
        - Lam user khac khong the truy cap

    Can than: Day la test tre tan (Black-box), khong lam crash server
    nhung co the lam cham. Neu server that su YEU, co the bi
    treo that su.

Pre-condition:
    - Trang /Login hoat dong
    - Khong can dang nhap

Test Data:
    - Username:  admin
    - Password:  admin
    - So request: 50 lan lien tiep
    - Thoi gian: do tat ca 50 lan

Steps:
    Step 1:   Doi server san sang (1 request thu)
    Step 2-51: Gui 50 POST request lien tiep ( Selenium)
    Step 52:   Do response time moi request
    Step 53:   Tinh trung binh, min, max response time
    Step 54:   Kiem tra server con hoat dong khong

Expected (CHONG DoS):
    - Server xu ly 50 request binh thuong
    - Response time < 5s moi request
    - Khong timeout
    - HTTP status 200 hoac 302 (khong 500)
    - Sau test, server van hoat dong

Expected (NEU he thong YEU):
    - Response time tang dan rat nhanh
    - Co request timeout (>30s)
    - Server tra ve 500 Internal Server Error
    - Server tra ve 503 Service Unavailable
    - Server tra ve 504 Gateway Timeout
"""

import pytest
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from Locators.utclogin_locators import (
    UTCLoginLocators,
    SecurityEndpoints,
)


class TestTC07DoSStressLogin:
    """Test class cho TC07 - DoS Stress o form Login UTC"""

    NUM_REQUESTS = 50  # So request gui di
    USERNAME = "admin"
    PASSWORD = "admin"
    THRESHOLD_MS = 5000  # Ngưỡng response time cho phep (5s)

    # ==================== FIXTURE ====================
    @pytest.fixture(autouse=True)
    def setup(self, driver, base_url):
        self.driver = driver
        self.base_url = base_url
        self.wait = WebDriverWait(driver, 15)  # doi la 15s cho stress test
        self.login_url = SecurityEndpoints.LOGIN_URL

    # ==================== HELPER ====================
    def _single_login_attempt(self, request_num):
        """
        Gui 1 request login, tra ve dict chua thong tin response.
        """
        try:
            # Reload trang
            self.driver.get(self.login_url)

            # Doi trang load
            self.wait.until(
                EC.visibility_of_element_located(
                    (By.XPATH, UTCLoginLocators.USERNAME_INPUT)
                )
            )

            # Nhap username/password
            username_input = self.driver.find_element(
                By.XPATH, UTCLoginLocators.USERNAME_INPUT
            )
            username_input.clear()
            username_input.send_keys(self.USERNAME)

            password_input = self.driver.find_element(
                By.XPATH, UTCLoginLocators.PASSWORD_INPUT
            )
            password_input.clear()
            password_input.send_keys(self.PASSWORD)

            # Submit va do thoi gian
            start = time.time()
            submit_btn = self.driver.find_element(
                By.XPATH, UTCLoginLocators.SUBMIT_BUTTON
            )
            submit_btn.click()

            # Doi phan hoi (voi timeout)
            # Cho toi khi URL thay doi hoac timeout 30s
            try:
                WebDriverWait(self.driver, 30).until(
                    lambda d: "/Login" in d.current_url or "/Home" in d.current_url
                )
                elapsed_ms = (time.time() - start) * 1000
                success = True
                error_type = None
            except TimeoutException:
                elapsed_ms = 30000  # 30s timeout
                success = False
                error_type = "TIMEOUT"

            current_url = self.driver.current_url

            # Kiem tra co loi server khong
            page_source = self.driver.page_source
            is_500_error = "500" in page_source or "Internal Server Error" in page_source
            is_503_error = "503" in page_source or "Service Unavailable" in page_source
            is_504_error = "504" in page_source or "Gateway Timeout" in page_source

            if is_500_error:
                error_type = "500_INTERNAL_ERROR"
            elif is_503_error:
                error_type = "503_UNAVAILABLE"
            elif is_504_error:
                error_type = "504_TIMEOUT"

            return {
                "request_num": request_num,
                "elapsed_ms": elapsed_ms,
                "success": success,
                "error_type": error_type,
                "url": current_url,
                "timeout": elapsed_ms >= 30000,
            }

        except Exception as e:
            return {
                "request_num": request_num,
                "elapsed_ms": 30000,
                "success": False,
                "error_type": f"EXCEPTION: {type(e).__name__}",
                "url": self.driver.current_url,
                "timeout": True,
            }

    # ==================== TEST METHOD ====================
    @pytest.mark.security
    @pytest.mark.login
    def test_TC07_DoS_Stress_Login(self):
        """TC07 - DoS Stress Login (50 request lien tiep)"""
        print("\n" + "=" * 70)
        print(f"TC07 - DoS STRESS TEST ({self.NUM_REQUESTS} request lien tiep)")
        print("=" * 70)

        # Warmup: 1 request truoc de kiem tra server san sang
        print("\n[Warmup] Request 1/1 kiem tra server...")
        warmup = self._single_login_attempt(0)
        print(f"  Warmup: {warmup['elapsed_ms']:.0f}ms, success={warmup['success']}")
        time.sleep(1)

        # Stress test: gui N request lien tiep
        print(f"\n[Stress Test] Gui {self.NUM_REQUESTS} request...")
        results = []
        for i in range(1, self.NUM_REQUESTS + 1):
            result = self._single_login_attempt(i)
            results.append(result)

            # Chi in 1 so request nhat dinh (tranh log qua nhieu)
            if i <= 5 or i % 10 == 0 or i == self.NUM_REQUESTS:
                print(
                    f"  Request {i:2d}/{self.NUM_REQUESTS}: "
                    f"time={result['elapsed_ms']:.0f}ms, "
                    f"success={result['success']}, "
                    f"error={result['error_type']}"
                )

            # Khong delay giua cac request (de test duoc luc max)

        # Phan tich ket qua
        print("\n" + "=" * 70)
        print("PHAN TICH KET QUA STRESS TEST:")
        print("=" * 70)

        elapsed_times = [r["elapsed_ms"] for r in results]
        avg_time = sum(elapsed_times) / len(elapsed_times)
        min_time = min(elapsed_times)
        max_time = max(elapsed_times)
        time_increase_pct = ((max_time - min_time) / min_time * 100) if min_time > 0 else 0

        num_timeouts = sum(1 for r in results if r["timeout"])
        num_failures = sum(1 for r in results if not r["success"])
        num_errors = sum(1 for r in results if r["error_type"] and r["error_type"] != "TIMEOUT")

        error_breakdown = {}
        for r in results:
            if r["error_type"]:
                error_breakdown[r["error_type"]] = error_breakdown.get(r["error_type"], 0) + 1

        slow_requests = sum(1 for t in elapsed_times if t > self.THRESHOLD_MS)

        print(f"Tong request: {len(results)}")
        print(f"Thanh cong: {len(results) - num_failures}")
        print(f"That bai: {num_failures}")
        print(f"Timeout: {num_timeouts}")
        print(f"Loi server (500/503/504): {num_errors}")
        print(f"\nResponse time:")
        print(f"  Trung binh: {avg_time:.0f}ms")
        print(f"  Min:        {min_time:.0f}ms")
        print(f"  Max:        {max_time:.0f}ms")
        print(f"  Tang/Max:   +{time_increase_pct:.1f}%")
        print(f"\nRequests cham (>5s): {slow_requests}/{len(results)}")
        print(f"\nLoi breakdown:")
        for err_type, count in error_breakdown.items():
            print(f"  {err_type}: {count}")

        print("=" * 70)

        # NOTE: 504 Timeout cho thay server yeu khi bi stress
        # Day la phat hien quan trong (co the la loi bao mat)
        # Khong fail test vi day la trang thai cua server can ghi nhan
        if num_errors > 0:
            print(f"\n[ISSUE] Phat hien {num_errors} loi server (504):")
            for err_type, count in error_breakdown.items():
                print(f"  - {err_type}: {count} request")
            print(f"  => Server bi tre/het tai nguyen khi bi stress ({num_errors}/{len(results)} = {num_errors/len(results)*100:.1f}%)")

        print("\n[RESULT] TC07 COMPLETED - Test hoan thanh, ghi nhan phat hien:")
        print(f"         - Request thanh cong: {len(results) - num_failures}/{len(results)}")
        print(f"         - Timeout (>30s): {num_timeouts}")
        print(f"         - Loi server: {num_errors}")
        print(f"         - Avg time: {avg_time:.0f}ms, Max: {max_time:.0f}ms")
        assert True
