"""
OrangeHRM Security Locators Module
Chứa các XPath và CSS Selectors dành riêng cho security tests trên OrangeHRM
URL: https://opensource-demo.orangehrmlive.com/
"""

class OrangeHRMLoginLocators:
    """Locators cho trang Login OrangeHRM"""

    USERNAME_INPUT = "xpath://input[@name='username']"
    PASSWORD_INPUT = "xpath://input[@name='password']"
    LOGIN_BUTTON = "xpath://button[@type='submit']"

    # Error / alert messages
    LOGIN_ERROR_INVALID = "xpath://p[contains(@class,'oxd-alert-content-text')]"
    SPAN_INVALID = "xpath://span[contains(@class,'oxd-input-field-error-message')]"
    BRUTE_FORCE_ALERT = "xpath://div[contains(@class,'oxd-alert')]"


class OrangeHRMDashboardLocators:
    """Locators cho trang Dashboard"""

    DASHBOARD_TITLE = "xpath://h6[contains(text(),'Dashboard')]"
    USER_DROPDOWN = "xpath://span[@class='oxd-userdropdown-tab']"
    LOGOUT_LINK = "xpath://a[text()='Logout']"

    # Menu items (sidebar)
    MENU_DIRECTORY = "xpath://span[text()='Directory']"
    MENU_PIM = "xpath://span[text()='PIM']"
    MENU_LEAVE = "xpath://span[text()='Leave']"
    MENU_BUZZ = "xpath://span[text()='Buzz']"
    MENU_ADMIN = "xpath://span[text()='Admin']"


class OrangeHRMDirectoryLocators:
    """Locators cho Directory (Employee Search)"""

    SEARCH_INPUT = "xpath://input[@placeholder='Type for hints...']"
    SEARCH_BUTTON = "xpath://button[@type='submit']"
    SEARCH_RESULT_ROWS = "xpath://div[@class='oxd-table-card']"
    NO_RECORDS = "xpath://span[contains(text(),'No Records')]"
    PAGE_TITLE = "xpath://h5[contains(text(),'Employee Information')]"


class OrangeHRMPIMLocators:
    """Locators cho PIM (Add/View Employee)"""

    ADD_EMPLOYEE_BUTTON = "xpath://a[contains(@href,'addEmployee')]"
    FIRST_NAME_INPUT = "xpath://input[@name='firstName']"
    MIDDLE_NAME_INPUT = "xpath://input[@name='middleName']"
    LAST_NAME_INPUT = "xpath://input[@name='lastName']"
    EMPLOYEE_ID_INPUT = "xpath://div[contains(@class,'oxd-input-group')]//input[contains(@class,'oxd-input')]"
    SAVE_BUTTON = "xpath://button[@type='submit']"
    EMPLOYEE_LIST_LINK = "xpath://a[contains(@href,'viewEmployeeList')]"

    # View employee detail
    EMPLOYEE_DETAIL_HEADER = "xpath://h6[contains(@class,'orangehrm-main-title')]"
    EMPLOYEE_ROW_NAME = "xpath://div[@class='oxd-table-cell']//div[contains(@class,'oxd-table-card')]"


class OrangeHRMLeaveLocators:
    """Locators cho Leave module"""

    APPLY_LEAVE_MENU = "xpath://a[contains(text(),'Apply')]"
    LEAVE_TYPE_DROPDOWN = "xpath://div[contains(@class,'oxd-select-text')]"
    FROM_DATE_INPUT = "xpath://input[@placeholder='yyyy-dd-mm']"
    TO_DATE_INPUT = "xpath://input[@placeholder='yyyy-dd-mm']"
    COMMENT_TEXTAREA = "xpath://textarea"
    APPLY_BUTTON = "xpath://button[@type='submit']"


class OrangeHRMBuzzLocators:
    """Locators cho Buzz (social)"""

    POST_TEXTAREA = "xpath://textarea[contains(@class,'oxd-buzz-post-input')]"
    POST_SUBMIT_BUTTON = "xpath://button[@type='submit']"
    UPLOAD_FILE_INPUT = "xpath://input[@type='file']"
    POSTS_LIST = "xpath://div[contains(@class,'orangehrm-buzz-post')]"
    POST_BODY = "xpath://div[@class='oxd-buzz-post-body']"


class OrangeHRMCommonLocators:
    """Locators chung cho OrangeHRM"""

    # Error / alert messages
    TOAST_ERROR = "xpath://div[contains(@class,'oxd-toast--error')]"
    TOAST_SUCCESS = "xpath://div[contains(@class,'oxd-toast--success')]"
    FORM_ERROR = "xpath://span[contains(@class,'oxd-input-field-error-message')]"

    # Page indicator
    SPINNER = "xpath://div[contains(@class,'oxd-loading-spinner')]"

    # Header
    TOPBAR = "xpath://header"
    SIDEBAR = "xpath://nav[contains(@class,'oxd-sidepanel')]"


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
