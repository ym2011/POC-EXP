# CVE-2018-11776


2018年8月23日，Apache Strust2发布最新安全公告，Apache Struts2 存在远程代码执行的高危漏洞，该漏洞由Semmle Security Research team的安全研究员汇报，漏洞编号为CVE-2018-11776（S2-057）。Struts2在XML配置中如果namespace值未设置且（Action Configuration）中未设置或用通配符namespace时可能会导致远程代码执行。

**影响版本**

Struts 2.3 to 2.3.34

Struts 2.5 to 2.5.16


**修复版本**

Struts 2.3.35

Struts 2.5.17


**使用方法**

python3 s2-057.py {url} eg: python3 s2-057.py http://example.com


**漏洞验证**

使用seebug.org在线检测平台检测出某站存在struts s2-057漏洞

<img alt="default" src="https://raw.githubusercontent.com/jiguang7/CVE-2018-11776/master/seeebug-org-struts2.png">



使用s2-057.py 检测出某站存在struts s2-057漏洞

<img alt="default" src="https://raw.githubusercontent.com/jiguang7/CVE-2018-11776/master/s2-057-struts2.png">

