"""
conftest.py - Pytest Configuration for OrangeHRM Security Tests
Cấu hình chung cho 15 security test cases
"""

import pytest
import time
import os
from datetime import datetime
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager


# ==================== Pytest Configuration ====================

def pytest_configure(config):
    """Tạo folder output khi bat dau pytest"""
    report_dir = Path(__file__).parent / "TestReports"
    report_dir.mkdir(exist_ok=True)

    screenshot_dir = report_dir / "screenshots"
    screenshot_dir.mkdir(exist_ok=True)

    log_dir = report_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    print("\n" + "=" * 70)
    print("ORANGEHRM SECURITY TESTING - 15 TEST CASES")
    print("=" * 70)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Browser: {config.getoption('--browser', default='chrome')}")
    print("=" * 70 + "\n")


def pytest_addoption(parser):
    """Custom CLI options"""
    parser.addoption(
        "--browser",
        action="store",
        default="chrome",
        help="Browser: chrome / firefox / edge",
    )
    parser.addoption(
        "--headless",
        action="store_true",
        default=False,
        help="Run headless mode",
    )
    parser.addoption(
        "--base-url",
        action="store",
        default="https://opensource-demo.orangehrmlive.com",
        help="OrangeHRM base URL",
    )
    parser.addoption(
        "--implicit-wait",
        action="store",
        default=10,
        type=int,
    )


# ==================== Fixtures ====================

@pytest.fixture(scope="session")
def base_url(request):
    return request.config.getoption("--base-url")


@pytest.fixture(scope="function")
def driver(request):
    """Tao WebDriver moi cho moi test"""
    browser = request.config.getoption("--browser")
    headless = request.config.getoption("--headless")
    implicit_wait = request.config.getoption("--implicit-wait")

    if browser.lower() == "chrome":
        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_argument("--disable-notifications")
        chrome_options.add_argument("--window-size=1920,1080")

        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            print(f"[WARN] ChromeDriverManager error: {e}. Fallback to system chromedriver.")
            driver = webdriver.Chrome(options=chrome_options)
    else:
        raise ValueError(f"Unsupported browser: {browser}")

    driver.implicitly_wait(implicit_wait)

    if not headless:
        try:
            driver.maximize_window()
        except Exception:
            pass

    yield driver

    try:
        driver.quit()
    except Exception:
        pass


@pytest.fixture
def wait(driver):
    return WebDriverWait(driver, 10)


# ==================== Screenshot on failure ====================

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture
def screenshot_on_failure(request, driver):
    yield
    if request.node.rep_call and request.node.rep_call.failed:
        test_name = request.node.name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_dir = Path(__file__).parent / "TestReports" / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshot_dir / f"{test_name}_{timestamp}.png"
        try:
            driver.save_screenshot(str(screenshot_path))
            print(f"\n[SCREENSHOT] Saved: {screenshot_path}")
        except Exception as e:
            print(f"\n[ERROR] Cannot save screenshot: {e}")


# ==================== Marker registration ====================

def pytest_configure(config):
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "sqli: SQL Injection tests")
    config.addinivalue_line("markers", "xss: Cross-Site Scripting tests")
    config.addinivalue_line("markers", "login: Login related tests")
    config.addinivalue_line("markers", "pim: PIM module tests")
    config.addinivalue_line("markers", "directory: Directory module tests")
    config.addinivalue_line("markers", "leave: Leave module tests")
    config.addinivalue_line("markers", "buzz: Buzz module tests")
    config.addinivalue_line("markers", "dashboard: Dashboard tests")
    config.addinivalue_line("markers", "session: Session management tests")
    config.addinivalue_line("markers", "high: High severity")
    config.addinivalue_line("markers", "medium: Medium severity")


# ==================== Session info ====================

@pytest.fixture(scope="session", autouse=True)
def test_session_info():
    start = time.time()
    yield
    duration = time.time() - start
    print(f"\n{'=' * 70}")
    print(f"Test session done in {duration:.2f} seconds")
    print(f"{'=' * 70}\n")
