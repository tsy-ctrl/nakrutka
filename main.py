import requests
import json
import base64
import time
import logging
import urllib3
import csv
import os
import certifi
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
from contextlib import nullcontext
import re

# Сохраняем оригинальный stdout
original_stdout = sys.stdout

# Создаем файл для логов
log_file = open('output.log', 'w', encoding='utf-8')

# Регулярное выражение для удаления ANSI-кодов цветов
ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Оригинальная функция print
original_print = print

# Переопределяем функцию print
def custom_print(*args, **kwargs):
    # Вызываем оригинальный print для вывода в консоль
    original_print(*args, **kwargs)
    
    # Собираем все аргументы в одну строку, как это делает print
    sep = kwargs.get('sep', ' ')
    end = kwargs.get('end', '\n')
    message = sep.join(str(arg) for arg in args) + end
    
    # Удаляем ANSI-коды цветов для записи в файл
    clean_message = ansi_escape.sub('', message)
    
    # Записываем в файл
    log_file.write(clean_message)
    log_file.flush()

# Заменяем стандартную функцию print на нашу
print = custom_print

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
    'password', 'email', 'proxy', 'user_agent', 'all_cookies', 'x_bc', 'x_hash'
]

DATA_CSV_FILE = "data/data.csv"
SUBS_CSV_FILE = "data/subs_data.csv"
SUBS_CSV_FIELDS = ["email", "subs_and_likes"]

csv_lock = threading.Lock()
lock = threading.Lock()

MODEL_ID = None
MODEL_NICKNAME = None
MAX_LIKES = 0
MAX_SUBS = 0
CURRENT_SUBS = 0
CURRENT_LIKES = 0
CUSTOM_ID = None
GLOBAL_PROXY = None
mongo_client = MongoClient("mongodb+srv://nakrutka:h2m9zTE9AHD2yknB@nakrutka.baw2l.mongodb.net/", 
                          tlsCAFile=certifi.where())

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

def save_like_to_db(email, password, proxy, model_nickname, likes_count):
    try:
        result = subs_and_likes_collection.update_one(
            {"email": email},
            {"$inc": {f"likes.{model_nickname}": likes_count},
             "$setOnInsert": {"subscriptions": []},
             "$set": {
                 "password": password,
                 "proxy": proxy,
                 "timestamp": datetime.now(UTC)
             }
            },
            upsert=True
        )
        return True, f"Likes updated ({likes_count}). Modified: {result.modified_count}, Upserted: {result.upserted_id is not None}"
    except Exception as e:
        logger.error(f"Error saving likes to MongoDB: {e}")
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

def read_subs_csv_file(filename=SUBS_CSV_FILE, use_lock=True):
    subs = []
    if os.path.exists(filename):
        try:
            # Use context manager for the lock if use_lock is True
            lock_context = csv_lock if use_lock else nullcontext()
            with lock_context:
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

def write_subs_csv_file(new_subs, filename=SUBS_CSV_FILE, use_lock=True):
    try:
        existing_subs = []
        if os.path.exists(filename):
            try:
                lock_context = csv_lock if use_lock else nullcontext()
                with lock_context:
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
        
        lock_context = csv_lock if use_lock else nullcontext()
        with lock_context:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["email", "subs_and_likes"])
                writer.writeheader()
                for row in all_subs:
                    row_copy = row.copy()
                    row_copy["subs_and_likes"] = json.dumps(row.get("subs_and_likes", {}))
                    writer.writerow(row_copy)
    except Exception as e:
        logger.error(f"Error updating {filename}: {e}")

def add_subscription_record(email, model_id):
    with csv_lock:
        subs = read_subs_csv_file(use_lock=False)  # Don't use lock inside the function
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
        write_subs_csv_file(subs, use_lock=False)  # Don't use lock inside the function

def update_subscription_record(email, model_id, liked_posts):
    with csv_lock:
        subs = read_subs_csv_file(use_lock=False)  # Don't use lock inside the function
        for row in subs:
            if row.get("email") == email:
                for sub in row.get("subs_and_likes", []):
                    if str(sub.get("model_id")) == str(model_id):
                        existing_posts = sub.get("liked_posts", [])
                        sub["liked_posts"] = list(set(existing_posts + liked_posts))
        write_subs_csv_file(subs, use_lock=False)  # Don't use lock inside the function

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

    account.update({
        "user_agent": user_agent,
        "all_cookies": cookie_str,
        "x_bc": x_bc_value,
        "x_hash": x_hash_value
    })
    update_csv_row(DATA_CSV_FILE, email, {
        "user_agent": user_agent,
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


def generate_temp_email():
    """Создать временную почту используя tempmail API"""
    try:
        response = requests.get("https://api.tempmail.lol/generate")
        if response.status_code == 200:
            data = response.json()
            email = data.get("address")
            token = data.get("token")
            return email, token
        return None, None
    except Exception as e:
        logger.error(f"Error generating temp email: {e}")
        return None, None

def wait_for_activation_email(token):
    """Ожидать письмо активации и извлечь ссылку активации"""
    max_attempts = 50
    attempts = 0
    
    while attempts < max_attempts:
        try:
            # Check inbox using the token
            response = requests.get(f"https://api.tempmail.lol/auth/{token}")
            
            if response.status_code == 200:
                data = response.json()
                messages = data.get('email', [])
                
                if messages and len(messages) > 0:
                    message = messages[0]
                    html_content = message.get('html', '')
                    
                    # Ищем ссылку активации
                    link_match = re.search(r'href=[\'"]?(https://onlyfans\.com/action/email/registration[^\'"]+)[\'"]?', html_content)
                    if link_match:
                        activation_link = link_match.group(1)
                        print(f"Activation link found: {activation_link}")
                        return activation_link
                    else:
                        print("Email received but activation link not found")
                        return None
            
            attempts += 1
            print(f"Waiting for activation email... (attempt {attempts}/{max_attempts})")
            time.sleep(3)
            
        except Exception as e:
            print(f"Error checking emails: {e}")
            attempts += 1
            time.sleep(3)

    print("Failed to find activation link after maximum attempts")
    return None

def generate_valid_visa_card():
    import random
    
    card_number = '4'
    
    for _ in range(14):
        card_number += str(random.randint(0, 9))
    
    total = 0
    for i in range(len(card_number)):
        digit = int(card_number[-(i+1)])
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    
    check_digit = (10 - (total % 10)) % 10
    
    card_number += str(check_digit)
    
    return card_number

def register_account(proxy_str, account_index):
    import random
    import string
    import base64
    import json
    import requests
    import re
    
    print(f"\n=== Starting registration for new account #{account_index} ===")
    
    # Генерация имени пользователя
    first_names = ["alex", "sam", "jordan", "taylor", "casey", "jamie", "robin", "morgan", "riley", "avery"]
    last_names = ["smith", "jones", "miller", "davis", "brown", "wilson", "taylor", "moore", "martin", "lee"]
    random_digits = ''.join(random.choice(string.digits) for _ in range(3))
    username = f"{random.choice(first_names)}_{random.choice(last_names)}{random_digits}"
    
    # Генерация пароля (только цифры, маленькие и большие буквы)
    password_length = random.randint(10, 14)
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    
    # Гарантируем наличие всех типов символов
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits)
    ]
    
    # Добавляем остальные символы
    for _ in range(password_length - 3):
        password.append(random.choice(lowercase + uppercase + digits))
    
    # Перемешиваем пароль
    random.shuffle(password)
    password = ''.join(password)
    
    # Генерация временной почты
    temp_email, email_token = generate_temp_email()
    if not temp_email:
        print_status(account_index, "New account", "Email generation", False, "Failed to generate temp email")
        return False, {}
    
    print_status(account_index, temp_email, "Generated temp email", True)
    
    # Создание User-Agent
    userAg = generate_user_agent()
    
    # Получение динамических заголовков для регистрации
    dynamic_headers_register = get_dynamic_headers(userAg, "/api2/v2/users/register")
    if not dynamic_headers_register:
        print_status(account_index, temp_email, "Registration", False, "Failed to get dynamic headers")
        return False, {}
    
    x_bc_value = dynamic_headers_register.get("X-Bc")
    x_hash_value = dynamic_headers_register.get("X-Hash")
    
    # Решение captcha v3
    recaptcha_token_invisible, captcha_error = solve_recaptcha("v3", proxy_str)
    if not recaptcha_token_invisible:
        print_status(account_index, temp_email, "Registration (captcha v3)", False, f"{captcha_error}")
        return False, {}
    else:
        print_status(account_index, temp_email, "Captcha v3", True, "Successfully passed")
    
    base_headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': userAg,
        'Referer': 'https://onlyfans.com/'
    }
    
    register_headers = base_headers.copy()
    register_headers["Content-Type"] = "application/json"
    register_headers["app-token"] = dynamic_headers_register.get("App-Token")
    register_headers["sign"] = dynamic_headers_register.get("Sign")
    register_headers["time"] = str(dynamic_headers_register.get("Time"))
    register_headers["x-bc"] = x_bc_value
    register_headers["x-hash"] = x_hash_value
    register_headers["x-of-rev"] = dynamic_headers_register.get("X-Of-Rev")
    
    encodedPassword = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    post_data = {
        "email": temp_email,
        "name": username,
        "encodedPassword": encodedPassword,
        "e-recaptcha-response": recaptcha_token_invisible
    }
    
    session = requests.Session()
    proxies = get_proxies(proxy_str) if proxy_str else None
    
    try:
        response = session.post(
            "https://onlyfans.com/api2/v2/users/register",
            headers=register_headers,
            data=json.dumps(post_data),
            cookies=session.cookies.get_dict(),
            verify=False,
            proxies=proxies
        )
        response_json = response.json()
    except Exception as e:
        print_status(account_index, temp_email, "Registration (request)", False, f"Exception: {str(e)}")
        return False, {}
    
    # Проверка на необходимость captcha v2
    error_code = response_json.get("error", {}).get("code")
    if error_code == 102:
        recaptcha_token_normal, captcha_error = solve_recaptcha("v2", proxy_str)
        if not recaptcha_token_normal:
            print_status(account_index, temp_email, "Registration (captcha v2)", False, f"{captcha_error}")
            return False, {}
        else:
            print_status(account_index, temp_email, "Captcha v2", True, "Successfully passed")
        
        post_data = {
            "email": temp_email,
            "name": username,
            "encodedPassword": encodedPassword,
            "e-recaptcha-response": recaptcha_token_invisible,
            "ec-recaptcha-response": recaptcha_token_normal
        }
    
        # Обновляем динамические заголовки для повторной попытки
        dynamic_headers_register = get_dynamic_headers(userAg, "/api2/v2/users/register")
        register_headers["app-token"] = dynamic_headers_register.get("App-Token")
        register_headers["sign"] = dynamic_headers_register.get("Sign")
        register_headers["time"] = str(dynamic_headers_register.get("Time"))
        register_headers["x-bc"] = x_bc_value
        register_headers["x-hash"] = dynamic_headers_register.get("X-Hash")
        register_headers["x-of-rev"] = dynamic_headers_register.get("X-Of-Rev")
    
        try:
            response = session.post(
                "https://onlyfans.com/api2/v2/users/register",
                headers=register_headers,
                data=json.dumps(post_data),
                cookies=session.cookies.get_dict(),
                verify=False,
                proxies=proxies
            )
            response_json = response.json()
        except Exception as e:
            print_status(account_index, temp_email, "Registration (2nd request)", False, f"Exception: {str(e)}")
            return False, {}
    
    if response.status_code != 200 or response_json.get("error"):
        print_status(account_index, temp_email, "Registration", False, f"Response: {response_json}")
        return False, {}
    
    print_status(account_index, temp_email, "Registration", True, "Account created successfully")
    
    # Получение ссылки активации
    activation_link = wait_for_activation_email(email_token)
    if not activation_link:
        print_status(account_index, temp_email, "Email activation", False, "Failed to get activation link")
        return False, {}

    code_match = re.search(r'/registration/([^?]+)', activation_link)
    signature_match = re.search(r'signature=([^&]+)', activation_link)
    
    if not code_match or not signature_match:
        print_status(account_index, temp_email, "Email activation", False, "Failed to extract code and signature from activation link")
        return False, {}
    
    code = code_match.group(1)
    signature = signature_match.group(1)
    
    initial_cookies = session.cookies.get_dict()
    filtered_cookies = {k: v for k, v in initial_cookies.items() if k in ["sess", "auth_id"]}
    cookie_str = '; '.join(f"{k}={v}" for k, v in filtered_cookies.items())
    
    api_path = f"/api2/v2/emails/confirm/registration?code={code}&signature={signature}"
    
    # Получение динамических заголовков для активации
    dynamic_headers_activation = get_dynamic_headers(userAg, api_path)
    
    if not dynamic_headers_activation:
        print_status(account_index, temp_email, "Email activation", False, "Failed to get dynamic headers for activation")
        return False, {}
    
    activation_headers = base_headers.copy()
    activation_headers["app-token"] = dynamic_headers_activation.get("App-Token")
    activation_headers["sign"] = dynamic_headers_activation.get("Sign")
    activation_headers["time"] = str(dynamic_headers_activation.get("Time"))
    activation_headers["x-bc"] = x_bc_value
    activation_headers["x-hash"] = x_hash_value
    activation_headers["x-of-rev"] = dynamic_headers_activation.get("X-Of-Rev")
    
    if cookie_str:
        activation_headers["Cookie"] = cookie_str
    
    try:
        activation_url = f"https://onlyfans.com/api2/v2/emails/confirm/registration?code={code}&signature={signature}"
        print(f"Calling activation API: {activation_url}")
        print(f"With headers: {activation_headers}")
        
        activation_response = session.get(
            activation_url,
            headers=activation_headers,
            verify=False,
            proxies=proxies,
            allow_redirects=True
        )
        
        try:
            activation_json = activation_response.json()
            print(f"Activation response: {activation_json}")
        except:
            print(f"Activation response is not JSON. Status: {activation_response.status_code}, Content: {activation_response.text[:200]}")
        
        if activation_response.status_code == 200:
            print_status(account_index, temp_email, "Account activation", True, "Account activated successfully")
        else:
            print_status(account_index, temp_email, "Account activation", False, f"Status code: {activation_response.status_code}")
            return False, {}
    except Exception as e:
        print_status(account_index, temp_email, "Account activation", False, f"Exception: {str(e)}")
        return False, {}
    
    account_data = {
        "password": password,
        "email": temp_email,
        "proxy": proxy_str,
        "user_agent": userAg,
        "all_cookies": cookie_str,
        "x_bc": x_bc_value,
        "x_hash": x_hash_value,
    }
    
    print(account_data)
    append_data_csv_row(account_data)

    return True, account_data

def append_data_csv_row(account_data):
    """Сохраняет данные аккаунта в CSV файл в папке data"""
    import os
    import csv
    
    # Создаем директорию data, если она не существует
    os.makedirs('data', exist_ok=True)
    
    csv_path = os.path.join('data', 'newdata.csv')
    
    # Проверяем, существует ли файл
    file_exists = os.path.isfile(csv_path)
    
    # Открываем файл для записи
    with open(csv_path, 'a', newline='') as csvfile:
        fieldnames = ['password', 'email', 'proxy', 'user_agent', 'all_cookies', 'x_bc', 'x_hash']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Записываем заголовки только если файл новый
        if not file_exists:
            writer.writeheader()
        
        # Записываем данные аккаунта
        writer.writerow({
            'password': account_data.get('password', ''),
            'email': account_data.get('email', ''),
            'proxy': account_data.get('proxy', ''),
            'user_agent': account_data.get('user_agent', ''),
            'all_cookies': account_data.get('all_cookies', ''),
            'x_bc': account_data.get('x_bc', ''),
            'x_hash': account_data.get('x_hash', '')
        })

def read_proxies_from_data_csv():
    """Читает прокси из существующего файла data/data.csv"""
    import os
    import csv
    
    csv_path = os.path.join('data', 'data.csv')
    proxies = []
    
    if os.path.isfile(csv_path):
        try:
            with open(csv_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row.get('proxy'):
                        proxies.append(row.get('proxy'))
        except Exception as e:
            logger.error(f"Error reading proxies from data.csv: {e}")
    
    return proxies

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


def process_subscriptions(account, account_index, userAg, visit_page = False):
    global MODEL_ID, MODEL_NICKNAME, MAX_SUBS, CURRENT_SUBS, GLOBAL_PROXY, CUSTOM_ID

    email = account.get("email")
    password = account.get("password")

    if MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS:
        print_status(account_index, email, "Subscription", False, f"Subscription limit reached: {MAX_SUBS}")
        return True

    subs_record = get_subscription_record(email, MODEL_ID)

    if subs_record:
        print_status(account_index, email, "Subscription", False, "Account already subscribed to model, skipping")
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

    if CUSTOM_ID:
        cookies_dict["c"] = f"{MODEL_ID}-{CUSTOM_ID}"
    
    x_bc_value = account.get("x_bc")
    x_hash_value = account.get("x_hash")

    if visit_page:
        try:
            model_page_endpoint = f"/api2/v2/users/{MODEL_NICKNAME}"
            
            # Get dynamic headers for model page
            dynamic_headers_page = get_dynamic_headers(user_agent, model_page_endpoint)
            if not dynamic_headers_page:
                print_status(account_index, email, "Page Visit", False, "Failed to get dynamic headers for model page")
                return False

            # Prepare headers for model page request
            page_headers = {**base_headers, **{
                "Content-Type": "application/json",
                "app-token": dynamic_headers_page.get("App-Token"),
                "sign": dynamic_headers_page.get("Sign"),
                "time": str(dynamic_headers_page.get("Time")),
                "x-bc": x_bc_value, 
                "x-hash": x_hash_value,
                "x-of-rev": dynamic_headers_page.get("X-Of-Rev"),
            }}

            # Send request to model's page
            page_response = requests.get(
                f"https://onlyfans.com{model_page_endpoint}",
                headers=page_headers,
                cookies=cookies_dict,
                proxies=proxies
            )
    
            if page_response.status_code != 200:
                print_status(account_index, email, "Page Visit", False, f"Failed to visit model page: {page_response.status_code}")
                return False
            
            print_status(account_index, email, "Page Visit", True)
        except Exception as e:
            print_status(account_index, email, "Page Visit", False, f"Error visiting model page: {e}")
            return False

    subscribe_endpoint = f"/api2/v2/users/{MODEL_ID}/subscribe"

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
        if not success:
            print(f"{success}: {message}")
        return True
    except requests.RequestException as e:
        print_status(account_index, email, "Subscription", False, f"Request exception: {e}")
        return False

def process_likes(account, account_index, userAg):
    global MODEL_ID, MODEL_NICKNAME, MAX_LIKES, CURRENT_LIKES, GLOBAL_PROXY

    email = account.get("email")
    password = account.get("password")

    if MAX_LIKES > 0 and CURRENT_LIKES >= MAX_LIKES:
        print_status(account_index, email, "Likes", False, f"Likes limit reached: {MAX_LIKES}")
        return True

    subs_record = get_subscription_record(email, MODEL_ID)
    if not subs_record:
        if not process_subscriptions(account, account_index, userAg):
            print_status(account_index, email, "Likes", False, "Failed to subscribe for likes")
            return False
        subs_record = get_subscription_record(email, MODEL_ID)

    liked_posts = subs_record.get("liked_posts", [])
    new_liked_posts = []  # Track new likes to update at the end

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
            print_status(account_index, email, "Likes", False, f"Likes limit reached: {MAX_LIKES}")
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
                new_liked_posts.append(post_id)  # Add to new likes list
                likes_count += 1
                CURRENT_LIKES += 1
                print(f"CURRENT LIKES: {CURRENT_LIKES}")
                # Removed save_like_to_db call from here
        except Exception as e:
            print_status(account_index, email, f"Likes for post {post_id}", False, f"Exception: {str(e)}")
            break

    # Update subscription record once after all likes are processed
    if new_liked_posts:
        all_liked_posts = list(set(liked_posts + new_liked_posts))
        update_subscription_record(email, MODEL_ID, all_liked_posts)
        
        # Save likes to DB once after all processing
        if likes_count > 0:
            success, message = save_like_to_db(email, password, proxy_str, MODEL_NICKNAME, likes_count)
            if not success:
                print(f"{success}: {message}")

    if likes_count > 0:
        return True
    return False

def process_account(account, option, account_index, page_visit=False):
    print(f"\n=== Starting process for account #{account_index}: {account.get('email')} ===")
    global GLOBAL_PROXY

    email = account.get("email")
    password = account.get("password")
    proxy_str = account.get("proxy", GLOBAL_PROXY)
    userAg = generate_user_agent()

    x_bc = account.get("x_bc")
    x_hash = account.get("x_hash")
    
    if not x_bc or not x_hash:
        print(f"[{account_index}. {email}] Performing login...")
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
            x_bc = account.get("x_bc", "")
            x_hash = account.get("x_hash", "")
            print(f"[{account_index}. {email}] Login success.")
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
    if option == "1":
        return process_likes(account, account_index, userAg)
    else:
        return process_subscriptions(account, account_index, userAg, page_visit)

def clean_nickname(nickname):
    nickname = nickname.strip()
    custom_id = None
    
    # Check if it's a URL and extract the relevant parts
    if nickname.startswith("https://onlyfans.com/"):
        nickname = nickname[len("https://onlyfans.com/"):]
    
    # Remove @ if present
    if nickname.startswith("@"):
        nickname = nickname[1:]
    
    # Check for /cXXX format and extract the number
    if '/' in nickname:
        parts = nickname.split('/')
        base_nickname = parts[0]
        
        # Check if the last part starts with 'c' followed by digits
        for part in parts[1:]:
            if part.startswith('c') and part[1:].isdigit():
                custom_id = part[1:]  # Save the numeric part without 'c'
                nickname = base_nickname  # Set nickname to the base part
                break
    
    nickname = nickname.rstrip('/')
    return nickname, custom_id

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
    global MODEL_NICKNAME, MODEL_ID, MAX_LIKES, MAX_SUBS, CURRENT_LIKES, CURRENT_SUBS, GLOBAL_PROXY, CUSTOM_ID, CURRENT_REGS
    check_key()
    print("\n=== by @yen_ofsfs ===\n")
    
    print("select operation")
    print("1. +likes")
    print("2. +subs")
    print("3. +subs (with page visit)")
    print("4. +accounts (register)")
    operation = input("-> ").strip()
    
    if operation not in ["1", "2", "3", "4"]:
        print("Invalid operation. Exit.")
        return
    
    if operation in ["1", "2", "3"]:
        GLOBAL_PROXY = input("global proxy: ").strip()
        input_nickname = input("nickname or link: ").strip()
        MODEL_NICKNAME, CUSTOM_ID = clean_nickname(input_nickname)
        
        if CUSTOM_ID:
            print(f"Nickname: {MODEL_NICKNAME}, Custom ID: {CUSTOM_ID}")
        else:
            print(f"Nickname: {MODEL_NICKNAME}")
        
        global_user_agent = generate_user_agent()
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
    
    MAX_LIKES = 0
    MAX_SUBS = 0
    MAX_REGS = 0
    CURRENT_LIKES = 0
    CURRENT_SUBS = 0
    CURRENT_REGS = 0
    
    if operation == "1":
        max_likes_input = input("How many likes to make? (0 for unlimited): ").strip()
        try:
            MAX_LIKES = int(max_likes_input)
        except ValueError:
            MAX_LIKES = 0
    elif operation in ["2", "3"]:
        max_subs_input = input("How many subscriptions to make? (0 for unlimited): ").strip()
        try:
            MAX_SUBS = int(max_subs_input)
        except ValueError:
            MAX_SUBS = 0
    elif operation == "4":
        max_regs_input = input("How many accounts to register? (0 for unlimited): ").strip()
        try:
            MAX_REGS = int(max_regs_input)
        except ValueError:
            MAX_REGS = 0
    
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
    
    if operation in ["1", "2", "3"]:
        accounts = read_csv_file(os.path.join('data', 'data.csv'))
        if len(accounts) == 0:
            logger.error("No accounts found in data/data.csv. Add them manually or register new ones.")
            return
        
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = []
            for i, account in enumerate(accounts, start=1):
                if MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS:
                    break
                
    
                page_visit = operation == "3"
                
                future = executor.submit(process_account, account, operation, i, page_visit)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if MAX_SUBS > 0 and CURRENT_SUBS >= MAX_SUBS:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break
        
        completed_futures = [f for f in futures if f.done() and not f.cancelled()]
        success_count = sum(1 for f in completed_futures if f.result())
        fail_count = sum(1 for f in completed_futures if not f.result())
        
        print(f"\nProcessing completed.")
        print(f"Successful subscriptions: {CURRENT_SUBS}/{MAX_SUBS if MAX_SUBS > 0 else 'unlimited'}")
        print(f"Total processed: {len(completed_futures)}, Successful: {success_count}, Errors: {fail_count}")
        
    elif operation == "4":
        existing_proxies = read_proxies_from_data_csv()
        
        if not existing_proxies:
            use_proxy_file = input("No proxies found in data.csv. Use proxy file for registrations? (y/n): ").strip().lower()
            if use_proxy_file == 'y':
                proxy_file = input("Enter proxy file path: ").strip()
                try:
                    with open(proxy_file, 'r') as f:
                        existing_proxies = [line.strip() for line in f.readlines() if line.strip()]
                    print(f"Loaded {len(existing_proxies)} proxies from file")
                except Exception as e:
                    print(f"Error loading proxy file: {e}")
                    existing_proxies = []
        else:
            print(f"Found {len(existing_proxies)} proxies in data/data.csv")
        
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = []
            account_index = 1
            
            while True:
                # Проверяем достижение желаемого количества успешных регистраций
                if MAX_REGS > 0 and CURRENT_REGS >= MAX_REGS:
                    break
                
                # Выбор прокси (сначала из data.csv, затем глобальный)
                current_proxy = ""
                if existing_proxies:
                    current_proxy = existing_proxies[(account_index-1) % len(existing_proxies)]  # Циклическое использование прокси
                
                future = executor.submit(register_and_process_account, current_proxy, account_index)
                futures.append(future)
                account_index += 1
                
                # Если запущено больше потоков, чем воркеров, ждем их завершения
                while len([f for f in futures if not f.done()]) >= worker_count:
                    for future in as_completed(futures):
                        result, _ = future.result()
                        if result:
                            CURRENT_REGS += 1
                            
                        futures.remove(future)
                        
                        if MAX_REGS > 0 and CURRENT_REGS >= MAX_REGS:
                            break
                    
                    if MAX_REGS > 0 and CURRENT_REGS >= MAX_REGS:
                        break
                
                if MAX_REGS > 0 and CURRENT_REGS >= MAX_REGS:
                    # Отменяем оставшиеся незавершенные задачи
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
            
            # Ожидаем завершения всех оставшихся потоков
            for future in as_completed(futures):
                result, _ = future.result()
                if result:
                    CURRENT_REGS += 1
                
                if MAX_REGS > 0 and CURRENT_REGS >= MAX_REGS:
                    break
        
        completed_futures = [f for f in futures if f.done() and not f.cancelled()]
        success_count = sum(1 for f in completed_futures if f.result()[0])
        fail_count = sum(1 for f in completed_futures if not f.result()[0])
        
        print(f"\nRegistration completed.")
        print(f"Successful registrations: {CURRENT_REGS}/{MAX_REGS if MAX_REGS > 0 else 'unlimited'}")
        print(f"Total attempted: {len(completed_futures)}, Successful: {success_count}, Errors: {fail_count}")

def register_and_process_account(proxy_str, account_index):
    success, account_data = register_account(proxy_str, account_index)
    if success:
        print(f"Registration #{account_index} completed successfully")
        return True, account_data
    print(f"Registration #{account_index} failed")
    return False, {}

if __name__ == "__main__":
    main()
