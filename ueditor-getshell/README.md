ueGetshell.py - ueditor .net getshell漏洞检测工具
================================================

# 概述<br>
ueditor .net版本 getshell漏洞检测工具，支持单url、批量检测。<br>
注意代码中的remoteShell要改成自己的远程shell地址！<br>
漏洞详情参考 [ueditor getshell漏洞重现及分析](http://www.lsablog.com/networksec/penetration/ueditor-getshell-analysis/) 
<br><br>

# 快速开始<br>

python ueGetshell.py -h<br>
![](https://github.com/theLSA/ueditor-getshell/raw/master/demo/uegetshell00.png)  

单url检测：python ueGetshell.py -u http://www.vulndomain.com/controller.ashx -s 5<br>
![](https://github.com/theLSA/ueditor-getshell/raw/master/demo/uegetshell01.png)

批量检测：python ueGetshell.py -f urls.txt -t 10 -s 5<br>
![](https://github.com/theLSA/ueditor-getshell/raw/master/demo/uegetshell02.png)

# 反馈<br>
* 博客： http://www.lsablog.com/<br>
* gmail: lsasguge196@gmail.com<br>
* qq: 2894400469@qq.com<br>
* issues: https://github.com/theLSA/ueditor-getshell/issues<br>
