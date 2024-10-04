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

