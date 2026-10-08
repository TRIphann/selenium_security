"""
OrangeHRM Security Locators Module
Chứa các XPath và CSS Selectors dành riêng cho security tests trên OrangeHRM
URL: https://opensource-demo.orangehrmlive.com/
"""

class OrangeHRMLoginLocators:
    """Locators cho trang Login OrangeHRM"""

    USERNAME_INPUT = "//input[@name='username']"
    PASSWORD_INPUT = "//input[@name='password']"
    LOGIN_BUTTON = "//button[@type='submit']"

    # Error / alert messages
    LOGIN_ERROR_INVALID = "//p[contains(@class,'oxd-alert-content-text')]"
    SPAN_INVALID = "//span[contains(@class,'oxd-input-field-error-message')]"
    BRUTE_FORCE_ALERT = "//div[contains(@class,'oxd-alert')]"


class OrangeHRMDashboardLocators:
    """Locators cho trang Dashboard"""

    DASHBOARD_TITLE = "//h6[contains(text(),'Dashboard')]"
    USER_DROPDOWN = "//span[@class='oxd-userdropdown-tab']"
    LOGOUT_LINK = "//a[text()='Logout']"

    # Menu items (sidebar)
    MENU_DIRECTORY = "//span[text()='Directory']"
    MENU_PIM = "//span[text()='PIM']"
    MENU_LEAVE = "//span[text()='Leave']"
    MENU_BUZZ = "//span[text()='Buzz']"
    MENU_ADMIN = "//span[text()='Admin']"


class OrangeHRMDirectoryLocators:
    """Locators cho Directory (Employee Search)"""

    SEARCH_INPUT = "//input[@placeholder='Type for hints...']"
    SEARCH_BUTTON = "//button[@type='submit']"
    SEARCH_RESULT_ROWS = "//div[@class='oxd-table-card']"
    NO_RECORDS = "//span[contains(text(),'No Records')]"
    PAGE_TITLE = "//h5[contains(text(),'Employee Information')]"


class OrangeHRMPIMLocators:
    """Locators cho PIM (Add/View Employee)"""

    ADD_EMPLOYEE_BUTTON = "//a[contains(@href,'addEmployee')]"
    FIRST_NAME_INPUT = "//input[@name='firstName']"
    MIDDLE_NAME_INPUT = "//input[@name='middleName']"
    LAST_NAME_INPUT = "//input[@name='lastName']"
    EMPLOYEE_ID_INPUT = "//div[contains(@class,'oxd-input-group')]//input[contains(@class,'oxd-input')]"
    SAVE_BUTTON = "//button[@type='submit']"
    EMPLOYEE_LIST_LINK = "//a[contains(@href,'viewEmployeeList')]"

    # View employee detail
    EMPLOYEE_DETAIL_HEADER = "//h6[contains(@class,'orangehrm-main-title')]"
    EMPLOYEE_ROW_NAME = "//div[@class='oxd-table-cell']//div[contains(@class,'oxd-table-card')]"


class OrangeHRMLeaveLocators:
    """Locators cho Leave module"""

    APPLY_LEAVE_MENU = "//a[contains(text(),'Apply')]"
    LEAVE_TYPE_DROPDOWN = "//div[contains(@class,'oxd-select-text')]"
    FROM_DATE_INPUT = "//input[@placeholder='yyyy-dd-mm']"
    TO_DATE_INPUT = "//input[@placeholder='yyyy-dd-mm']"
    COMMENT_TEXTAREA = "//textarea"
    APPLY_BUTTON = "//button[@type='submit']"


class OrangeHRMBuzzLocators:
    """Locators cho Buzz (social)"""

    POST_TEXTAREA = "//textarea[contains(@class,'oxd-buzz-post-input')]"
    POST_SUBMIT_BUTTON = "//button[@type='submit']"
    UPLOAD_FILE_INPUT = "//input[@type='file']"
    POSTS_LIST = "//div[contains(@class,'orangehrm-buzz-post')]"
    POST_BODY = "//div[@class='oxd-buzz-post-body']"


class OrangeHRMCommonLocators:
    """Locators chung cho OrangeHRM"""

    # Error / alert messages
    TOAST_ERROR = "//div[contains(@class,'oxd-toast--error')]"
    TOAST_SUCCESS = "//div[contains(@class,'oxd-toast--success')]"
    FORM_ERROR = "//span[contains(@class,'oxd-input-field-error-message')]"

    # Page indicator
    SPINNER = "//div[contains(@class,'oxd-loading-spinner')]"

    # Header
    TOPBAR = "//header"
    SIDEBAR = "//nav[contains(@class,'oxd-sidepanel')]"


class SecurityEndpoints:
    """Các URL / endpoint dùng cho security test"""

    LOGIN_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/auth/login"
    DASHBOARD_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/dashboard/index"
    PIM_VIEW_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/pim/viewEmployee/empNumber/"
    LOGOUT_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/auth/logout"
    BUZZ_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/buzz/viewBuzz"
    LEAVE_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/leave/viewLeaveList"
    DIRECTORY_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/directory/viewDirectory"
    PIM_ADD_URL = "https://opensource-demo.orangehrmlive.com/web/index.php/pim/addEmployee"

