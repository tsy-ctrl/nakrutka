import requests
import json
import base64
import time
import logging
import urllib3
import csv
import os
import threading
import sys
import colorama
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from pymongo import MongoClient
from datetime import datetime, UTC
from dotenv import load_dotenv
import subprocess
import uuid
import psutil

load_dotenv("keys/.env")
colorama.init()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CAPSOLVER_API_KEY = os.getenv('CAPSOLVER_API_KEY')

CSV_FIELDS = [
    'password', 'email', 'proxy', 'user_agent', 'id', 'all_cookies', 'x_bc', 'x_hash'
]

DATA_CSV_FILE = "data/data.csv"
SUBS_CSV_FILE = "data/subs_data.csv"
SUBS_CSV_FIELDS = ["email", "subs_and_likes"]

csv_lock = threading.Lock()

MODEL_ID = None
MODEL_NICKNAME = None
MAX_LIKES = 0
MAX_SUBS = 0
CURRENT_SUBS = 0
CURRENT_LIKES = 0
GLOBAL_PROXY = None

mongo_client = MongoClient("mongodb+srv://nakrutka:h2m9zTE9AHD2yknB@nakrutka.baw2l.mongodb.net/")
db = mongo_client['onlyfans_db']
subs_and_likes_collection = db.SubsAndLikes

def read_csv_file(filename):
    accounts = []
    if not os.path.exists(filename):
        logger.error(f"File {filename} not found! Please add it manually.")
        return accounts
    try:
        with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                accounts.append(row)
        logger.info(f"Successfully loaded {len(accounts)} accounts from {filename}")
        return accounts
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        return accounts
    

def save_subscription_to_db(email, password, proxy, model_nickname):
    try:
        result = subs_and_likes_collection.update_one(
            {"email": email},
            {"$addToSet": {"subscriptions": model_nickname},
             "$setOnInsert": {"likes": {}},
             "$set": {
                 "password": password,
                 "proxy": proxy,
                 "timestamp": datetime.now(UTC)
             }
            },
            upsert=True
        )
        
        return True, f"Subscription updated. Modified: {result.modified_count}, Upserted: {result.upserted_id is not None}"
    except Exception as e:
        logger.error(f"Error saving subscription to MongoDB: {e}")
        return False, str(e)

def save_like_to_db(email, password, proxy, model_nickname):
    try:
        result = subs_and_likes_collection.update_one(
            {"email": email},
            {"$inc": {f"likes.{model_nickname}": 1},
             "$setOnInsert": {"subscriptions": []},
             "$set": {
                 "password": password,
                 "proxy": proxy,
                 "timestamp": datetime.now(UTC)
             }
            },
            upsert=True
        )
        return True, f"Like updated. Modified: {result.modified_count}, Upserted: {result.upserted_id is not None}"
    except Exception as e:
        logger.error(f"Error saving like to MongoDB: {e}")
        return False, str(e)

def print_status(account_index, email, request_name, success, message=""):
    if success:
        print(f"\033[92m[{account_index}. {email}] {request_name} - Request completed successfully\033[0m")
    else:
        print(f"\033[91m[{account_index}. {email}] {request_name} - Request failed with error: {message}\033[0m")

def get_proxies(proxy_str):
    if proxy_str:
        parts = proxy_str.split(":")
        if len(parts) == 4:
            ip, port, user, pwd = parts
            proxy_url = f"http://{user}:{pwd}@{ip}:{port}"
        elif len(parts) == 2:
            ip, port = parts
            proxy_url = f"http://{ip}:{port}"
        else:
            logger.error(f"Invalid proxy format: {proxy_str}")
            return None
        return {"http": proxy_url, "https": proxy_url}
    return None

def generate_user_agent():
    try:
        ua = UserAgent()
        return ua.chrome
    except Exception as e:
        logger.error(f"Error generating user agent: {e}")
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

def read_subs_csv_file(filename=SUBS_CSV_FILE):
    subs = []
    if os.path.exists(filename):
        try:
            with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    try:
                        row["subs_and_likes"] = json.loads(row.get("subs_and_likes", "[]"))
                    except Exception as e:
                        logger.error(f"Error parsing subs_and_likes: {e}")
                        row["subs_and_likes"] = []
                    subs.append(row)
        except Exception as e:
            logger.error(f"Error reading {filename}: {e}")
    return subs

def write_subs_csv_file(subs, filename=SUBS_CSV_FILE):
    try:
        with csv_lock:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["email", "subs_and_likes"])
                writer.writeheader()
                for row in subs:
                    row_copy = row.copy()
                    row_copy["subs_and_likes"] = json.dumps(row.get("subs_and_likes", []))
                    writer.writerow(row_copy)
    except Exception as e:
        logger.error(f"Error writing to {filename}: {e}")

def update_csv_row(filename, email, data):
    try:
        with csv_lock:
            rows = []
            with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                field_names = reader.fieldnames
                for row in reader:
                    if row['email'] == email:
                        for key in data:
                            if key in field_names:
                                row[key] = data[key]
                    rows.append(row)
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=field_names)
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Data for {email} updated successfully in CSV file")
    except Exception as e:
        logger.error(f"Error updating CSV file for {email}: {e}")

def read_subs_csv_file(filename=SUBS_CSV_FILE):
    subs = []
    if os.path.exists(filename):
        try:
            with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    try:
                        row["subs_and_likes"] = json.loads(row.get("subs_and_likes", "[]"))
                    except Exception as e:
                        logger.error(f"Error parsing subs_and_likes: {e}")
                        row["subs_and_likes"] = []
                    subs.append(row)
        except Exception as e:
            logger.error(f"Error reading {filename}: {e}")
    return subs

def write_subs_csv_file(new_subs, filename=SUBS_CSV_FILE):
    try:
        existing_subs = []
        if os.path.exists(filename):
            try:
                with csv_lock:
                    with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                        reader = csv.DictReader(csvfile)
                        for row in reader:
                            if "subs_and_likes" in row:
                                try:
                                    row["subs_and_likes"] = json.loads(row["subs_and_likes"])
                                except:
                                    row["subs_and_likes"] = {}
                            existing_subs.append(row)
            except Exception as e:
                logger.error(f"Error reading from {filename}: {e}")
        email_to_data = {sub["email"]: sub for sub in existing_subs}
        for new_sub in new_subs:
            email = new_sub.get("email")
            if email:
                if email in email_to_data:
                    email_to_data[email].update(new_sub)
                else:
                    email_to_data[email] = new_sub
        all_subs = list(email_to_data.values())
        with csv_lock:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["email", "subs_and_likes"])
                writer.writeheader()
                for row in all_subs:
                    row_copy = row.copy()
                    row_copy["subs_and_likes"] = json.dumps(row.get("subs_and_likes", {}))
                    writer.writerow(row_copy)
        logger.info(f"Successfully updated {filename} with {len(new_subs)} new or updated records")
    except Exception as e:
        logger.error(f"Error updating {filename}: {e}")

def add_subscription_record(email, model_id):
    subs = read_subs_csv_file()
    email_record = None
    for row in subs:
        if row.get("email") == email:
            email_record = row
            break
    if not email_record:
        email_record = {
            "email": email,
            "subs_and_likes": []
        }
        subs.append(email_record)
    model_exists = any(
        str(sub.get("model_id")) == str(model_id) 
        for sub in email_record.get("subs_and_likes", [])
    )
    if not model_exists:
        email_record["subs_and_likes"].append({
            "model_id": str(model_id),
            "liked_posts": []
        })
    write_subs_csv_file(subs)

def update_subscription_record(email, model_id, liked_posts):
    subs = read_subs_csv_file()
    for row in subs:
        if row.get("email") == email:
            for sub in row.get("subs_and_likes", []):
                if str(sub.get("model_id")) == str(model_id):
                    existing_posts = sub.get("liked_posts", [])
                    sub["liked_posts"] = list(set(existing_posts + liked_posts))
    write_subs_csv_file(subs)

def get_dynamic_headers(user_agent, path):
    node_script_path = 'headers/headers.js'
    try:
        cmd = ['node', node_script_path, path, user_agent]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        headers = json.loads(output)
        return headers
    except subprocess.CalledProcessError as e:
        print(f"Error calling Node.js script: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return None

def solve_recaptcha(captcha_type, proxy=None):
    proxies = get_proxies(proxy) if proxy else None
    create_task_url = "https://api.capsolver.com/createTask"
    if captcha_type == "v3":
        task = {
            "type": "ReCaptchaV3EnterpriseTask",
            "websiteURL": "https://onlyfans.com",
            "websiteKey": "6LcvNcwdAAAAAMWAuNRXH74u3QePsEzTm6GEjx0J",
            "apiDomain": "www.recaptcha.net",
            "action": "login",
            "proxy":  proxy
        }
    else:
        task = {
            "type": "ReCaptchaV2EnterpriseTask",
            "websiteURL": "https://onlyfans.com",
            "websiteKey": "6LddGoYgAAAAAHD275rVBjuOYXiofr1u4pFS5lHn",
            "apiDomain": "www.recaptcha.net",
            "proxy": proxy
        }
    task_payload = {"clientKey": CAPSOLVER_API_KEY, "task": task}
    try:
        response = requests.post(create_task_url, json=task_payload, verify=False, proxies=proxies)
        response_json = response.json()
        if response_json.get("errorId") > 0:
            return None, response_json.get("errorDescription", "Unknown error")
        task_id = response_json.get("taskId")
    except Exception as e:
        return None, str(e)
    get_task_result_url = "https://api.capsolver.com/getTaskResult"
    task_result_payload = {"clientKey": CAPSOLVER_API_KEY, "taskId": task_id}
    attempts = 0
    max_attempts = 20
    last_error = ""
    while attempts < max_attempts:
        attempts += 1
        try:
            response = requests.post(get_task_result_url, json=task_result_payload, verify=False, proxies=proxies)
            data = response.json()
            if data.get("errorId") > 0:
                last_error = data.get("errorDescription", "Unknown error")
                break
            if data.get("status") == "ready":
                token = data.get("solution", {}).get("gRecaptchaResponse", "")
                return token, ""
        except Exception as e:
            last_error = str(e)
        time.sleep(3)
    return None, f"Captcha token not received after {max_attempts} attempts. Last error: {last_error}"

def perform_login(email, password, user_agent, base_headers, proxy_str, account, account_index):
    global GLOBAL_PROXY
    print(f"[{account_index}. {email}] Request: Login...")

    dynamic_headers_login = get_dynamic_headers(user_agent, "/api2/v2/users/login")
    if not dynamic_headers_login:
        print_status(account_index, email, "Login", False, "Failed to get dynamic headers")
        return False

    x_bc_value = dynamic_headers_login.get("X-Bc")
    x_hash_value = dynamic_headers_login.get("X-Hash")

    recaptcha_token_invisible, captcha_error = solve_recaptcha("v3", proxy_str)
    if not recaptcha_token_invisible:
        print_status(account_index, email, "Login (captcha v3)", False, f"{captcha_error}")
        return False
    else:
        print_status(account_index, email, "Captcha v3", True, "Successfully passed")

    login_headers = base_headers.copy()
    login_headers["Content-Type"] = "application/json"
    login_headers["app-token"] = dynamic_headers_login.get("App-Token")
    login_headers["sign"] = dynamic_headers_login.get("Sign")
    login_headers["time"] = str(dynamic_headers_login.get("Time"))
    login_headers["x-bc"] = x_bc_value
    login_headers["x-hash"] = x_hash_value
    login_headers["x-of-rev"] = dynamic_headers_login.get("X-Of-Rev")

    encodedPassword = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    post_data = {
        "email": email,
        "encodedPassword": encodedPassword,
        "e-recaptcha-response": recaptcha_token_invisible
    }
    session = requests.Session()
    proxies = get_proxies(proxy_str) if proxy_str else None

    try:
        response = session.post(
            "https://onlyfans.com/api2/v2/users/login",
            headers=login_headers,
            data=json.dumps(post_data),
            cookies=session.cookies.get_dict(),
            verify=False,
            proxies=proxies
        )
        response_json = response.json()
    except Exception as e:
        print_status(account_index, email, "Login (request)", False, f"Exception: {str(e)}")
        update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
        return False

    error_code = response_json.get("error", {}).get("code")
    if error_code == 102:
        recaptcha_token_normal, captcha_error = solve_recaptcha("v2", proxy_str)
        if not recaptcha_token_normal:
            print_status(account_index, email, "Login (captcha v2)", False, f"{captcha_error}")
            update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
            return False
        else:
            print_status(account_index, email, "Captcha v2", True, "Successfully passed")
        post_data = {
            "email": email,
            "encodedPassword": encodedPassword,
            "e-recaptcha-response": recaptcha_token_invisible,
            "ec-recaptcha-response": recaptcha_token_normal
        }

        dynamic_headers_login = get_dynamic_headers(user_agent, "/api2/v2/users/login")
        login_headers["Content-Type"] = "application/json"
        login_headers["app-token"] = dynamic_headers_login.get("App-Token")
        login_headers["sign"] = dynamic_headers_login.get("Sign")
        login_headers["time"] = str(dynamic_headers_login.get("Time"))
        login_headers["x-bc"] = x_bc_value
        login_headers["x-hash"] = dynamic_headers_login.get("X-Hash")
        login_headers["x-of-rev"] = dynamic_headers_login.get("X-Of-Rev")

        try:
            response = session.post(
                "https://onlyfans.com/api2/v2/users/login",
                headers=login_headers,
                data=json.dumps(post_data),
                cookies=session.cookies.get_dict(),
                verify=False,
                proxies=proxies
            )
            response_json = response.json()
        except Exception as e:
            print_status(account_index, email, "Login (2nd request)", False, f"Exception: {str(e)}")
            update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
            return False

    if response.status_code != 200 or response_json.get("error"):
        print_status(account_index, email, "Login", False, f"Response: {response_json}")
        update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
        return False

    final_cookies = session.cookies.get_dict()
    
    filtered_cookies = {k: v for k, v in final_cookies.items() if k in ["sess", "auth_id"]}
    cookie_str = '; '.join(f"{k}={v}" for k, v in filtered_cookies.items())

    dynamic_headers_me = get_dynamic_headers(user_agent, "/api2/v2/users/me")
    if not dynamic_headers_me:
        print_status(account_index, email, "GET /users/me", False, "Failed to get dynamic headers for /users/me")
        return False

    me_headers = base_headers.copy()
    me_headers["Content-Type"] = "application/json"
    me_headers["app-token"] = dynamic_headers_me.get("App-Token")
    me_headers["sign"] = dynamic_headers_me.get("Sign")
    me_headers["time"] = str(dynamic_headers_me.get("Time"))
    me_headers["x-bc"] = x_bc_value
    me_headers["x-hash"] = x_hash_value
    me_headers["x-of-rev"] = dynamic_headers_me.get("X-Of-Rev")

    try:
        response = session.get("https://onlyfans.com/api2/v2/users/me", headers=me_headers, verify=False, proxies=proxies)
        response_json_me = response.json()

    except Exception as e:
        print_status(account_index, email, "GET /users/me", False, f"Exception: {str(e)}")
        update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
        return False

    if not response_json_me.get("isAuth"):
        print_status(account_index, email, "GET /users/me", False, f"Response: {response_json_me}")
        update_csv_row(DATA_CSV_FILE, email, {"all_cookies": "", "x_bc": "", "x_hash": ""})
        return False
    else:
        print_status(account_index, email, "GET /users/me", True, "Logged and verificated login successfully")

    final_user_id = response_json_me.get("id", "")

    account.update({
        "user_agent": user_agent,
        "id": final_user_id,
        "all_cookies": cookie_str,
        "x_bc": x_bc_value,
        "x_hash": x_hash_value
    })
    update_csv_row(DATA_CSV_FILE, email, {
        "user_agent": user_agent,
        "id": final_user_id,
        "all_cookies": cookie_str,
        "x_bc": x_bc_value,
        "x_hash": x_hash_value
    })
    print_status(account_index, email, "Login", True)
    return True

def get_subscription_record(email, model_id):
    subs = read_subs_csv_file()
    for row in subs:
        if row.get("email") == email:
            subs_and_likes = row.get("subs_and_likes", [])
            
            if isinstance(subs_and_likes, str):
                subs_list = json.loads(subs_and_likes)
            else:
                subs_list = subs_and_likes
                
            for sub in subs_list:
                if str(sub.get("model_id")) == str(model_id):
                    return sub
    return None

def parse_cookies(cookies_raw):
    cookies_dict = {}
    if not cookies_raw:
        return cookies_dict
    
    for cookie in cookies_raw.split(";"):
        cookie = cookie.strip()
        if "=" in cookie:
            key, value = cookie.split("=", 1)
            if key in ["sess", "auth_id"]:
                cookies_dict[key] = value
    return cookies_dict

def process_subscriptions(account, account_index, userAg):
    global MODEL_ID, MODEL_NICKNAME, MAX_SUBS, CURRENT_SUBS, GLOBAL_PROXY

    email = account.get("email")
    password = account.get("password")

    print(f"[{account_index}. {email}] Request: Subscription...")

    if MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS:
        print_status(account_index, email, "Subscription", True, f"Subscription limit reached: {MAX_SUBS}")
        return True

    subs_record = get_subscription_record(email, MODEL_ID)
    if subs_record:
        print_status(account_index, email, "Subscription", True, "Account already subscribed to model, skipping")
        return True

    user_agent = account.get("user_agent") or userAg
    base_headers = {
        'Accept': 'application/json, text/plain, */*',
        "User-Agent": user_agent,
        'Referer': f"https://onlyfans.com/{MODEL_NICKNAME}",
    }

    proxy_str = account.get("proxy")
    proxies = get_proxies(proxy_str) if proxy_str else None

    cookies_raw = account.get("all_cookies")
    if not cookies_raw:
        print(f"[{account_index}. {email}] No cookies provided.")
        return False

    cookies_dict = parse_cookies(cookies_raw)
    if not cookies_dict.get("auth_id") or not cookies_dict.get("sess"):
        print_status(account_index, email, "Subscription", False, "Missing auth_id or sess cookie")
        return False

    subscribe_endpoint = f"/api2/v2/users/{MODEL_ID}/subscribe"

    x_bc_value = account.get("x_bc")
    x_hash_value = account.get("x_hash")

    if not x_bc_value or not x_hash_value:
        dynamic_headers_sub = get_dynamic_headers(user_agent, subscribe_endpoint)
        if not dynamic_headers_sub:
            print_status(account_index, email, "Subscription", False, "Failed to get dynamic headers")
            return False
        x_bc_value = dynamic_headers_sub.get("X-Bc")
        x_hash_value = dynamic_headers_sub.get("X-Hash")
        account["x_bc"] = x_bc_value
        account["x_hash"] = x_hash_value
        update_csv_row(DATA_CSV_FILE, email, {"x_bc": x_bc_value, "x_hash": x_hash_value})
    else:
        dynamic_headers_sub = get_dynamic_headers(user_agent, subscribe_endpoint)
        if not dynamic_headers_sub:
            print_status(account_index, email, "Subscription", False, "Failed to get dynamic headers")
            return False

    subscribe_headers = {**base_headers, **{
        "Content-Type": "application/json",
        "app-token": dynamic_headers_sub.get("App-Token"),
        "sign": dynamic_headers_sub.get("Sign"),
        "time": str(dynamic_headers_sub.get("Time")),
        "x-bc": x_bc_value, 
        "x-hash": x_hash_value,
        "x-of-rev": dynamic_headers_sub.get("X-Of-Rev"),
    }}

    try:
        response = requests.post(
            f"https://onlyfans.com{subscribe_endpoint}",
            headers=subscribe_headers,
            cookies=cookies_dict,
            json={"source": "profile"},
            proxies=proxies
        )
        resp_json = response.json()

        if resp_json.get("error"):
            print_status(account_index, email, "Subscription", False, f"Response error: {resp_json.get('error')}")
            return False

        print_status(account_index, email, "Subscription", True)
        add_subscription_record(email, MODEL_ID)
        CURRENT_SUBS += 1
        print(f"CURRENT SUBS: {CURRENT_SUBS}")
        success, message = save_subscription_to_db(email, password, proxy_str, MODEL_NICKNAME)
        print(f"{success}: {message}")
        return True
    except requests.RequestException as e:
        print_status(account_index, email, "Subscription", False, f"Request exception: {e}")
        return False

def process_likes(account, account_index, userAg):
    global MODEL_ID, MODEL_NICKNAME, MAX_LIKES, CURRENT_LIKES, GLOBAL_PROXY

    email = account.get("email")
    password = account.get("password")
    print(f"[{account_index}. {email}] Request: Likes...")

    if MAX_LIKES > 0 and CURRENT_LIKES >= MAX_LIKES:
        print_status(account_index, email, "Likes", True, f"Likes limit reached: {MAX_LIKES}")
        return True

    subs_record = get_subscription_record(email, MODEL_ID)
    if not subs_record:
        if not process_subscriptions(account, account_index, userAg):
            print_status(account_index, email, "Likes", False, "Failed to subscribe for likes")
            return False
        subs_record = get_subscription_record(email, MODEL_ID)

    liked_posts = subs_record.get("liked_posts", [])

    user_agent = account.get("user_agent") or userAg
    base_headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': user_agent,
        'Referer': f"https://onlyfans.com/{MODEL_NICKNAME}"
    }

    proxy_str = account.get("proxy")
    proxies = get_proxies(proxy_str) if proxy_str else None

    cookies_raw = account.get("all_cookies")
    if not cookies_raw:
        print(f"[{account_index}. {email}] No cookies provided.")
        return False

    cookies_dict = parse_cookies(cookies_raw)
    if not cookies_dict.get("auth_id") or not cookies_dict.get("sess"):
        print_status(account_index, email, "Likes", False, "Missing auth_id or sess cookie")
        return False

    x_bc_value = account.get("x_bc")
    x_hash_value = account.get("x_hash")

    if not x_bc_value or not x_hash_value:
        print_status(account_index, email, "Likes", False, "Missing x-bc or x-hash values")
        return False

    cookie_str = cookies_raw

    url_pinned = f"/api2/v2/users/{MODEL_ID}/posts?skip_users=all&pinned=1&counters=0&format=infinite"

    dynamic_headers_pinned = get_dynamic_headers(user_agent, url_pinned)
    if not dynamic_headers_pinned:
        print_status(account_index, email, "Likes (pinned headers)", False, "Failed to get dynamic headers for pinned posts")
        list_pinned = []
    else:
        headers_pinned = {**base_headers, **{
            "app-token": dynamic_headers_pinned.get("App-Token"),
            "sign": dynamic_headers_pinned.get("Sign"),
            "time": str(dynamic_headers_pinned.get("Time")),
            "x-bc": x_bc_value,  
            "x-hash": x_hash_value,  
            "x-of-rev": dynamic_headers_pinned.get("X-Of-Rev"),
            "Cookie": cookie_str
        }}

        try:
            response_pinned = requests.get(
                f"https://onlyfans.com{url_pinned}", 
                headers=headers_pinned, 
                verify=False, 
                proxies=proxies
            )
            data_pinned = response_pinned.json()
            list_pinned = data_pinned.get("list", [])
        except Exception as e:
            print_status(account_index, email, "Likes (pinned=1)", False, f"Exception: {str(e)}")
            list_pinned = []

    url_not_pinned = f"/api2/v2/users/{MODEL_ID}/posts?limit=100&order=publish_date_desc&skip_users=all&format=infinite&pinned=0&counters=1"

    dynamic_headers_not_pinned = get_dynamic_headers(user_agent, url_not_pinned)
    if not dynamic_headers_not_pinned:
        print_status(account_index, email, "Likes (not pinned headers)", False, "Failed to get dynamic headers for non-pinned posts")
        list_not_pinned = []
    else:
        headers_not_pinned = {**base_headers, **{
            "app-token": dynamic_headers_not_pinned.get("App-Token"),
            "sign": dynamic_headers_not_pinned.get("Sign"),
            "time": str(dynamic_headers_not_pinned.get("Time")),
            "x-bc": x_bc_value,  
            "x-hash": x_hash_value,  
            "x-of-rev": dynamic_headers_not_pinned.get("X-Of-Rev"),
            "Cookie": cookie_str
        }}

        try:
            response_not_pinned = requests.get(
                f"https://onlyfans.com{url_not_pinned}", 
                headers=headers_not_pinned, 
                verify=False, 
                proxies=proxies
            )
            data_not_pinned = response_not_pinned.json()
            list_not_pinned = data_not_pinned.get("list", [])
            print(f"[{account_index}. {email}] Number of non-pinned posts: {len(list_not_pinned)}")
        except Exception as e:
            print_status(account_index, email, "Likes (not pinned)", False, f"Exception: {str(e)}")
            list_not_pinned = []

    combined_posts = list_pinned + list_not_pinned
    if not combined_posts:
        print_status(account_index, email, "Likes", False, "No posts found")
        return False

    likes_count = 0
    for post in combined_posts:
        if MAX_LIKES > 0 and CURRENT_LIKES >= MAX_LIKES:
            print_status(account_index, email, "Likes", True, f"Likes limit reached: {MAX_LIKES}")
            break

        post_id = post.get("id")
        if not post_id:
            continue

        if post_id in liked_posts:
            print(f"[{account_index}. {email}] Post {post_id} already liked, skipping")
            continue

        favorites_url = f"/api2/v2/posts/{post_id}/favorites/{MODEL_ID}"

        dynamic_headers_like = get_dynamic_headers(user_agent, favorites_url)
        if not dynamic_headers_like:
            print_status(account_index, email, f"Likes for post {post_id}", False, "Failed to get dynamic headers for like")
            break

        headers_like = {**base_headers, **{
            "Content-Type": "application/json",
            "app-token": dynamic_headers_like.get("App-Token"),
            "sign": dynamic_headers_like.get("Sign"),
            "time": str(dynamic_headers_like.get("Time")),
            "x-bc": x_bc_value,  
            "x-hash": x_hash_value,  
            "x-of-rev": dynamic_headers_like.get("X-Of-Rev"),
            "Cookie": cookie_str
        }}

        full_favorites_url = f"https://onlyfans.com{favorites_url}"
        try:
            fav_response = requests.post(
                full_favorites_url, 
                headers=headers_like, 
                json={}, 
                verify=False, 
                proxies=proxies
            )
            fav_data = fav_response.json()

            if fav_data.get("error"):
                print_status(account_index, email, f"Likes for post {post_id}", False, f"Response: {fav_data}")
                break
            else:
                print_status(account_index, email, f"Likes for post {post_id}", True)
                liked_posts.append(post_id)
                update_subscription_record(email, MODEL_ID, liked_posts)
                likes_count += 1
                CURRENT_LIKES += 1
                print(f"CURRENT LIKES: {CURRENT_LIKES}")
                success, message = save_like_to_db(email, password, proxy_str, MODEL_NICKNAME)
                print(f"{success}: {message}")
        except Exception as e:
            print_status(account_index, email, f"Likes for post {post_id}", False, f"Exception: {str(e)}")
            break

    if likes_count > 0:
        return True
    return False

def process_account(account, option, account_index):
    print(f"\n=== Starting process for account #{account_index}: {account.get('email')} ===")
    global GLOBAL_PROXY

    email = account.get("email")
    password = account.get("password")
    proxy_str = account.get("proxy")
    userAg = generate_user_agent()

    x_bc = account.get("x_bc")
    x_hash = account.get("x_hash")
    
    if not x_bc or not x_hash:
        print(f"[{account_index}. {email}] No x-bc, x-hash -> performing login...")
        login_ok = perform_login(
            email, password,
            account.get("user_agent") or userAg,
            {
                'Accept': 'application/json, text/plain, */*',
                'User-Agent': account.get("user_agent") or userAg,
                'Referer': 'https://onlyfans.com/'
            },
            proxy_str,
            account,
            account_index
        )
        if not login_ok:
            print(f"[{account_index}. {email}] Login failed -> skipping this account.")
            return False
        else:
            user_id = account.get("id", "")
            x_bc = account.get("x_bc", "")
            x_hash = account.get("x_hash", "")
            print(f"[{account_index}. {email}] Login success. user_id = {user_id}, x-bc and x-hash obtained")
    else:
        print(f"[{account_index}. {email}] x-bc and x-hash exist -> checking /users/me ...")
        
        session = requests.Session()
        proxies = get_proxies(proxy_str) if proxy_str else None
        user_agent = account.get("user_agent") or userAg
        

        cookies_raw = account.get("all_cookies")

        cookies_dict = {}
        for cookie in cookies_raw.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, value = cookie.split("=", 1)
                if key in ["sess", "auth_id"]:
                    cookies_dict[key] = value

        cookie_str = f"sess={cookies_dict['sess']}; auth_id={cookies_dict['auth_id']}"

        dynamic_headers_me = get_dynamic_headers(user_agent, "/api2/v2/users/me")
        
        if not dynamic_headers_me:
            print(f"[{account_index}. {email}] Failed to get dynamic headers -> trying login anyway...")
            login_ok = perform_login(
                email, password,
                user_agent,
                {
                    'Accept': 'application/json, text/plain, */*',
                    'User-Agent': user_agent,
                    'Referer': 'https://onlyfans.com/'
                },
                proxy_str,
                account,
                account_index
            )
            if not login_ok:
                print(f"[{account_index}. {email}] Login failed -> skipping this account.")
                return False
        else:
            base_headers = {
                'Accept': 'application/json, text/plain, */*',
                'User-Agent': user_agent,
                'Referer': 'https://onlyfans.com/'
            }

            me_headers = base_headers.copy()
            me_headers["Content-Type"] = "application/json"
            me_headers["app-token"] = dynamic_headers_me.get("App-Token")
            me_headers["sign"] = dynamic_headers_me.get("Sign")
            me_headers["time"] = str(dynamic_headers_me.get("Time"))
            me_headers["x-bc"] = x_bc 
            me_headers["x-hash"] = x_hash  
            me_headers["x-of-rev"] = dynamic_headers_me.get("X-Of-Rev")
            me_headers["Cookie"] = cookie_str
            try:
                response = session.get(
                    "https://onlyfans.com/api2/v2/users/me",
                    headers=me_headers,
                    verify=False,
                    proxies=proxies
                )
                me_data = response.json()

                if not me_data.get("isAuth"):
                    print(f"[{account_index}. {email}] Authentication failed -> performing login...")
                    login_ok = perform_login(
                        email, password,
                        user_agent,
                        {
                            'Accept': 'application/json, text/plain, */*',
                            'User-Agent': user_agent,
                            'Referer': 'https://onlyfans.com/'
                        },
                        proxy_str,
                        account,
                        account_index
                    )
                    if not login_ok:
                        print(f"[{account_index}. {email}] Login failed -> skipping this account.")
                        return False
                else:
                    print(f"[{account_index}. {email}] Authentication successful with existing x-bc and x-hash.")

            except Exception as e:
                print(f"[{account_index}. {email}] Error checking /users/me: {e} -> performing login...")
                login_ok = perform_login(
                    email, password,
                    user_agent,
                    {
                        'Accept': 'application/json, text/plain, */*',
                        'User-Agent': user_agent,
                        'Referer': 'https://onlyfans.com/'
                    },
                    proxy_str,
                    account,
                    account_index
                )
                if not login_ok:
                    return False

    print(f"[{account_index}. {email}] Proceeding to { 'Likes' if option=='1' else 'Subscription' } ...")
    if option == "1":
        return process_likes(account, account_index, userAg)
    else:
        return process_subscriptions(account, account_index, userAg)

def clean_nickname(nickname):
    nickname = nickname.strip()
    if nickname.startswith("https://onlyfans.com/"):
        nickname = nickname[len("https://onlyfans.com/"):]
    if nickname.startswith("@"):
        nickname = nickname[1:]
    nickname = nickname.rstrip('/')
    return nickname

def check_key():
    key_file_path = "keys/key.txt"
    try:
        with open(key_file_path, "r", encoding="utf-8") as key_file:
            key_value = key_file.read().strip()
    except Exception as e:
        print("File not found")
        sys.exit(1)
    
    key_record = db.keys.find_one({"key": key_value})
    if not key_record:
        print("Key not found in database. Exiting.")
        sys.exit(1)

    def get_machine_id():
        mac = uuid.getnode()
    
        disk_info = psutil.disk_partitions()
        disk_serial = ""
        if disk_info:
            try:
                disk_serial = psutil.disk_usage(disk_info[0].mountpoint).total
            except:
                pass
        machine_id = str(mac) + str(disk_serial)
        return uuid.uuid5(uuid.NAMESPACE_DNS, machine_id).hex
    
    hwid = get_machine_id()
    
    try:
        ip_response = requests.get('https://api.ipify.org').text
    except Exception:
        ip_response = "unknown"
    
    db.keys.update_one(
        {"key": key_value},
        {
            "$inc": {"logins": 1},
            "$addToSet": {
                "hwid_list": hwid,
                "ip_list": ip_response
            }
        }
    )
    
    return key_record

def main():
    global MODEL_NICKNAME, MODEL_ID, MAX_LIKES, MAX_SUBS, CURRENT_LIKES, CURRENT_SUBS, GLOBAL_PROXY
    check_key()
    print("\n=== by @yen_ofsfs ===\n")
    MODEL_NICKNAME = clean_nickname(input("nickname: ").strip())
    global_user_agent = generate_user_agent()
    GLOBAL_PROXY = input("global proxy: ").strip()
    model_headers = get_dynamic_headers(global_user_agent, f"/api2/v2/users/{MODEL_NICKNAME}")
    if model_headers:
        proxies = get_proxies(GLOBAL_PROXY) if GLOBAL_PROXY else None
        try:
            response = requests.get(
                f"https://onlyfans.com/api2/v2/users/{MODEL_NICKNAME}",
                headers=model_headers,
                verify=False,
                proxies=proxies
            )
            model_data = response.json()
            MODEL_ID = model_data.get("id")
            if not MODEL_ID:
                logger.error(f"Model ID not found. Response: {model_data}")
                sys.exit(1)
            print(f"Model ID: {MODEL_ID}")
        except Exception as e:
            logger.error(f"Error getting model ID for {MODEL_NICKNAME}: {e}")
            sys.exit(1)
    else:
        logger.error("Could not get dynamic headers for model.")
        sys.exit(1)
    print("\nselect option")
    print("1. +likes")
    print("2. +subs")
    option = input("-> ").strip()
    MAX_LIKES = 0
    MAX_SUBS = 0
    CURRENT_LIKES = 0
    CURRENT_SUBS = 0
    if option == "1":
        max_likes_input = input("How many likes to make? (0 for unlimited): ").strip()
        try:
            MAX_LIKES = int(max_likes_input)
        except ValueError:
            MAX_LIKES = 0
    elif option == "2":
        max_subs_input = input("How many subscriptions to make? (0 for unlimited): ").strip()
        try:
            MAX_SUBS = int(max_subs_input)
        except ValueError:
            MAX_SUBS = 0
    else:
        print("Invalid option. Exit.")
        return
    try:
        worker_count_input = input("how many threads: ")
        if worker_count_input.strip():
            worker_count = int(worker_count_input)
            if worker_count < 1:
                worker_count = 1
        else:
            worker_count = 1
    except ValueError:
        worker_count = 1
    accounts = read_csv_file(DATA_CSV_FILE)
    if len(accounts) == 0:
        logger.error("No accounts found in data.csv. Add them manually.")
        return
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = []
        for i, account in enumerate(accounts, start=1):
            if (option == "1" and MAX_LIKES > 0 and CURRENT_LIKES >= MAX_LIKES) or \
               (option == "2" and MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS):
                break
            future = executor.submit(process_account, account, option, i)
            futures.append(future)
        for future in as_completed(futures):
            result = future.result()
            if result:
                if option == "1":
                    if MAX_LIKES > 0 and CURRENT_LIKES >= MAX_LIKES:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break
                elif option == "2":
                    if MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break
    completed_futures = [f for f in futures if f.done() and not f.cancelled()]
    success_count = sum(1 for f in completed_futures if f.result())
    fail_count = sum(1 for f in completed_futures if not f.result())
    print(f"\nProcessing completed.")
    if option == "1":
        print(f"Successful likes: {CURRENT_LIKES}/{MAX_LIKES if MAX_LIKES > 0 else 'unlimited'}")
    else:
        print(f"Successful subscriptions: {CURRENT_SUBS}/{MAX_SUBS if MAX_SUBS > 0 else 'unlimited'}")
    print(f"Total processed: {len(completed_futures)}, Successful: {success_count}, Errors: {fail_count}")

if __name__ == "__main__":
    main()
