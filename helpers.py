"""
helpers.py - Cac ham tien ich cho security testing
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time


def create_session_with_retries(pool_size=10):
    """Tao requests.Session co retry + connection pool lon (dung cho DoS test)"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def post_login(session, username, password, timeout=15):
    """Helper: POST den /Login, tra ve (status_code, response_time_ms, body)"""
    start = time.time()
    # GET truoc de lay cookie session
    session.get("https://vanphongdientu.utc.edu.vn/Login", timeout=timeout)
    r = session.post(
        "https://vanphongdientu.utc.edu.vn/Login",
        data={"username": username, "userpwd": password},
        timeout=timeout,
        allow_redirects=False,
    )
    elapsed_ms = (time.time() - start) * 1000
    return r.status_code, elapsed_ms, r.text
