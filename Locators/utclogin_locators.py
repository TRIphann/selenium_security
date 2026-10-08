"""
UTC Van Phong Dien Tu - Security Locators Module
Chứa các XPath và CSS Selectors dành riêng cho security tests trên
https://vanphongdientu.utc.edu.vn/Login

Lưu ý: Selector dùng cú pháp Selenium 4 (không cần tiền tố xpath:/css:)
"""


class UTCLoginLocators:
    """Locators cho trang Login UTC Van Phong Dien Tu"""

    # Form chính
    LOGIN_FORM = "//form[@action='/Login']"

    # Input fields
    USERNAME_INPUT = "//input[@name='username']"
    PASSWORD_INPUT = "//input[@name='userpwd']"
    PERSISTENT_CHECKBOX = "//input[@id='persistent']"

    # Submit button (là input type=submit, không phải <button>)
    SUBMIT_BUTTON = "//input[@type='submit' and @class='submit_login']"

    # Error / alert messages
    # UTC dung <div class="error"> de hien thi thong bao
    ERROR_DIV = "//div[@class='error']"
    # Generic fallback neu class khac
    ERROR_ANY = "//*[contains(@class,'error') or contains(@class,'alert') or contains(@class,'message') or contains(@class,'invalid')]"

    # Link quên mật khẩu
    FORGOT_PASSWORD_LINK = "//a[contains(@href,'/Login/GetPass')]"

    # Link OAuth Google
    GOOGLE_OAUTH_LINK = "//a[contains(@href,'accounts.google.com')]"


class UTCDashboardLocators:
    """Locators cho trang Dashboard / sau khi đăng nhập thành công"""

    # Trang chủ sau khi login thường chuyển đến /Home hoặc /
    LOGOUT_LINK = "//a[contains(text(),'Đăng xuất') or contains(text(),'Logout') or contains(@href,'/Logout')]"
    USER_MENU = "//*[contains(@class,'user') or contains(@class,'profile') or contains(@class,'avatar')]"

    # Tiêu đề dashboard
    DASHBOARD_TITLE = "//*[contains(@class,'title') or contains(@class,'header')]"


class UTCGetPassLocators:
    """Locators cho trang quên mật khẩu /Login/GetPass"""

    # Form
    GETPASS_FORM = "//form[@action='/Login/Getpass']"

    # Inputs
    CAPTCHA_INPUT = "//input[@name='captcha']"
    EMAIL_INPUT = "//input[@name='email']"

    # Submit
    GETPASS_SUBMIT = "//input[@type='submit']"

    # Captcha image
    CAPTCHA_IMAGE = "//img[contains(@src,'/login/index/captcha')]"

    # Error
    ERROR_DIV = "//div[@class='error']"

    # Link quay lai
    BACK_TO_LOGIN_LINK = "//a[contains(@href,'/Login') and not(contains(@href,'GetPass'))]"


class UTCCommonLocators:
    """Locators chung cho UTC Van Phong Dien Tu"""

    # Page indicators
    PAGE_TITLE = "//title"

    # Loading spinner
    SPINNER = "//*[contains(@class,'loading') or contains(@class,'spinner')]"


class SecurityEndpoints:
    """Các URL / endpoint dùng cho security test UTC"""

    BASE_URL = "https://vanphongdientu.utc.edu.vn"
    LOGIN_URL = "https://vanphongdientu.utc.edu.vn/Login"
    FORGOT_PASSWORD_URL = "https://vanphongdientu.utc.edu.vn/Login/GetPass"
    HOME_URL = "https://vanphongdientu.utc.edu.vn/Home"
    LOGOUT_URL = "https://vanphongdientu.utc.edu.vn/Logout"
