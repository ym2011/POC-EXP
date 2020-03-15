### python2多线程扫描Tomcat-Ajp协议文件读取漏洞
刷src分狗的福利
poc来源于[https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi/](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi/)，加以修改
## 操作
### 1、将需要扫描的域名/ip放于 ip.txt
ip.txt中不需要加协议，比如
```
127.0.0.1
www.baidu.com
www.google.com
```
### 2、python threading-find-port-8009.py
将会生成8009.txt，作用为扫描ip.txt中域名/ip找出开放8009端口
### 3、python threading-CNVD-2020-10487-Tomcat-Ajp-lfi.py
从8009.txt中筛选出符合漏洞的url,放置于vul.txt中
`最后vul.txt中存在的域名即为含有漏洞的域名`
亲测补天公益src有上百站点，教育src大概三百站点包含此漏洞
![](1.png)
### 4、测试
拿 CNVD-2020-10487-Tomcat-Ajp-lfi.py测试即可
`python CNVD-2020-10487-Tomcat-Ajp-lfi.p target.com`
## 本项目仅供学习，严禁用于非法操作
ps1:两个脚本的最后一行均为线程数-默认是20，可自行修改      
位于threading-find-port-8009.py 67行              
threading-CNVD-2020-10487-Tomcat-Ajp-lfi.py 341行         

```
thread_num=20
```


ps2:src域名收集文件夹中为本人收集的教育src和补天src的一些域名，可直接测试