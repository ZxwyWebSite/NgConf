package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/ini.v1"
)

// ZxwyWebSite/NgConf
// 为海纳思盒子写的第二个程序
// 可以一键生成Nginx配置文件
// 还是能用就行，不做错误检测

// 全局变量
var version string = `1.0`
var nginx_site_path, php_fpm_path string = `/etc/nginx/sites-enabled`, `unix:/var/run/php/php7.4-fpm.sock`

// 初始化
func recover() {
	fmt.Print("\033[H\033[2J")
	fmt.Print(`
#  __    _    ______    ______    ______   __    _   _______  #
# |  \  | |  / _____\  / _____\  / ___  \ |  \  | | |  _____| #
# | \ \ | | | /  ___  | /       | /   \ | | \ \ | | | |____   #
# | |\ \| | | | |__ \ | |       | |   | | | |\ \| | |  ____|  #
# | | \ \ | | \___/ | | \_____  | \___/ | | | \ \ | | |       #
# |_|  \__|  \______/  \______/  \______/ |_|  \__| |_|       #
===============================================================
 Version ` + version + `  Github ZxwyWebSite/NgConf  Support HiNAS System
`)
	time.Sleep(1500 * time.Millisecond)
	//fmt.Print("\033[H\033[2J")
	fmt.Print("\n正在初始化，请稍候...\n\n")
	cfg := ini.Empty()
	cfg.Section(``).NewKey(`version`, version)
	// cfg.Section(`ngconf`).NewKey(`nginx_site_path`, nginx_site_path)
	// cfg.Section(`ngconf`).NewKey(`php_fpm_path`, php_fpm_path)
	// cfg.Section(`site`).NewKey(`enable_site`, ``)
	// cfg.Section(`site`).NewKey(`disable_site`, ``)
	err := cfg.SaveTo(`settings.ini`)
	if err != nil {
		fmt.Printf("初始化配置文件失败: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Println(`初始化成功，如不需要修改配置文件请再次运行。`)
		os.Exit(0)
	}
}

// 带参数启动(暂未完善)
// func etag() {
// 	for i, v := range os.Args {
// 		if i == 1 {
// 			switch v {
// 			case `uninstall`:
// 				fmt.Println(`敬请期待！`)
// 				os.Exit(0)
// 			case `recover`:
// 				recover()
// 			case `clear`:
// 				fmt.Println(`敬请期待！`)
// 				os.Exit(0)
// 			case `help`:
// 				fmt.Println(`敬请期待！`)
// 				os.Exit(0)
// 			case `version`:
// 				fmt.Println(version)
// 				os.Exit(0)
// 			default:
// 				fmt.Printf("非法参数：%v\n", v)
// 				os.Exit(0)
// 			}
// 		}
// 	}
// }

func head(path string) {
	fmt.Print("\033[H\033[2J")
	fmt.Print(`
# ` + path + ` | NgConf-CLI #
`)
}

func main() {
	//etag()
	// 载入配置文件
	cfg, err := ini.Load(`settings.ini`)
	if err != nil {
		// fmt.Printf("读取配置文件失败: %v", err)
		// 读取不到配置文件，默认第一次运行，执行初始化
		recover()
	}
	// 检查配置版本，以后可用于更新程序
	ver, err := cfg.Section(``).GetKey(`version`)
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		fmt.Println(`请检查settings.ini，如无数据，执行 "./ngconf recover" 重新初始化`)
		os.Exit(1)
	}
	fmt.Println(`key: `, ver)
	menu()
}

func menu() {
	var menuinput string
	for {
		head(`主菜单`)
		fmt.Print(`
1. 创建配置
2. 站点管理
3. Nginx状态
4. 卸载残留
5. 关于程序

0. 退出程序
`)
		fmt.Print("\n请输入选项: ")
		fmt.Scanln(&menuinput)
		switch menuinput {
		case `1`:
			newsite()
		case `2`:
			setsite()
		case `3`:
			nginx()
		case `4`:
			uninstall()
		case `5`:
			about()
		case `0`:
			os.Exit(0)
		default:
			fmt.Print("非法参数！")
			time.Sleep(300 * time.Millisecond)
			//menu()
		}
	}
}

func about() {
	head(`关于程序`)
	fmt.Println("\n当前版本：" + version)
	fmt.Println(`Github：ZxwyWebSite/NgConf`)
	fmt.Println(`专为海纳思系统开发，其它系统可能不兼容`)
	os.Exit(0)
}

// 创建站点
func newsite() {
	head(`创建站点`)
	fmt.Println("\n警告：此步骤没有数据验证，请严格按照示例格式填写，如不慎填写错误请 [Ctrl]+[C] 退出，或在二次确认时选 n")
	var site_domain, site_port, site_path, php_fpm, confirm string
	for {
		fmt.Print("\n请输入站点域名(ngconf.zxwy.tk): ")
		fmt.Scanln(&site_domain)
		fmt.Print("\n请输入站点端口(8001|留空默认80): ")
		fmt.Scanln(&site_port)
		if site_port == `` {
			site_port = `80`
		}
		fmt.Print("\n请输入站点目录(/var/www/html): ")
		fmt.Scanln(&site_path)
		fmt.Println("\n提示：默认开启php，请到main.conf中修改")
		fmt.Print("\nphp-fpm地址(unix:/var/run/php/php7.4-fpm.sock|留空默认): ")
		fmt.Scanln(&php_fpm)
		if php_fpm == `` {
			php_fpm = php_fpm_path
		}
		fmt.Println("\n提示：默认禁用ssl，请到main.conf中修改")
		fmt.Print("\n\n二次确认：\n  站点域名：", site_domain, "\n  站点端口：", site_port, "\n  站点目录：", site_path, "\n  php-fpm地址：", php_fpm)
		fmt.Print("\n\n是否确认生成配置(y|n): ")
		fmt.Scanln(&confirm)
		if confirm == `y` {
			break
		}
	}
	fmt.Println("\n开始生成配置文件，请稍候...")
	// 判断是否存在&创建站点目录 site/ngconf.zxwy.tk_80
	runpath, _ := os.Getwd()
	sitedir := runpath + `/site/` + site_domain + `_` + site_port
	_, err := os.Stat(sitedir)
	if err != nil {
		os.MkdirAll(sitedir, os.ModePerm)
	} else {
		fmt.Println(`文件夹 ` + sitedir + ` 已存在，继续创建可能覆盖数据，请手动删除文件夹后继续！`)
		os.Exit(1)
	}
	// 模板&生成配置数据
	// HTTPS配置 ssl.conf
	ssl := `    # HTTPS监听端口(如需设置默认站点这里也要加default_server)
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate ` + sitedir + `/cert.pem` + `;
    ssl_certificate_key ` + sitedir + `/cert.key` + `;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    add_header Strict-Transport-Security "max-age=31536000";
    error_page 497 https://$host$request_uri;

    # 非443端口访问重定向https(强制https)(默认开启)
    if ($server_port !~ 443){
        rewrite ^(/.*)$ https://$host$1 permanent;
    }`
	// 主配置文件 main.conf
	main := `server
{
    # ipv6监听默认开启，如不需要可自行注释，https配置文件里还有一个
    listen ` + site_port + `;
    listen [::]:` + site_port + `;
	# 站点域名
    server_name ` + site_domain + `;
	# 默认文档
    index index.php index.html index.htm default.php default.htm default.html;
	# 站点目录
    root ` + site_path + `;

    # SSL相关配置(默认关闭)
    # include ` + sitedir + `/ssl.conf` + `;

    # 错误页配置，可以注释、删除或修改
    #error_page 404 /404.html;
    #error_page 502 /502.html;

    # 反向代理规则(默认关闭，需要修改)
    # include ` + sitedir + `/proxy.conf` + `;

    # 启用PHP(默认开启)
    include ` + sitedir + `/php.conf` + `;

    # URL重写(伪静态)配置(默认关闭，需要修改)
    # include ` + sitedir + `/rewrite.conf` + `;

    #禁止访问的文件或目录
    location ~ ^/(\.user.ini|\.htaccess|\.git|\.env|\.svn|\.project|LICENSE|README.md)
    {
        return 404;
    }

    #一键申请SSL证书验证目录相关设置
    #location ~ \.well-known{
    #    allow all;
    #}

    #禁止在证书验证目录放入敏感文件
    if ( $uri ~ "^/\.well-known/.*\.(php|jsp|py|js|css|lua|ts|go|zip|tar\.gz|rar|7z|sql|bak)$" ) {
        return 403;
    }

    # 访问日志(默认开启)，如需禁用填写 /dev/null
    access_log  ` + sitedir + `/access.log` + `;
    error_log  ` + sitedir + `/error.log` + `;
}`
	// 伪静态 rewrite.conf
	rewrite := `# # 二级目录填写 location /path，示例配置仅供参考，请根据实际情况修改
# location / {
#     if (!-e $request_filename){
#         rewrite  ^(.*)$  /index.php$1  last;   break;
#     }
# }`
	// 反向代理 proxy.conf
	proxy := `# # 如需代理到二级目录可改为 location /path，示例配置仅供参考，请根据实际情况修改
# location /
# {
#   # 要代理的网站域名
#     proxy_pass https://translate.google.com;
#   # 如果是内网|本机地址，填 $host
#     proxy_set_header Host translate.google.com;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header Range $http_range;
#   proxy_set_header If-Range $http_if_range;
#     # proxy_set_header Cookie '你的cookie';
#     proxy_http_version 1.1;
#   # 字符串替换
#     # proxy_set_header Accept-Encoding "";
#   # sub_filter "Google 翻译" "Zxwy翻译";
#     # sub_filter_once off;
#   # 最大上传文件
#     # client_max_body_size 20000m;
# }`
	// php设置 php.conf
	php := `location ~ [^/]\.php(/|$)
{
    try_files $uri =404;
    fastcgi_pass  ` + php_fpm + `;
    fastcgi_index index.php;
	# fastcgi.conf
    fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
    fastcgi_param  QUERY_STRING       $query_string;
    fastcgi_param  REQUEST_METHOD     $request_method;
    fastcgi_param  CONTENT_TYPE       $content_type;
    fastcgi_param  CONTENT_LENGTH     $content_length;
    fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
    fastcgi_param  REQUEST_URI        $request_uri;
    fastcgi_param  DOCUMENT_URI       $document_uri;
    fastcgi_param  DOCUMENT_ROOT      $document_root;
    fastcgi_param  SERVER_PROTOCOL    $server_protocol;
    fastcgi_param  REQUEST_SCHEME     $scheme;
    fastcgi_param  HTTPS              $https if_not_empty;
    fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
    fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
    fastcgi_param  REMOTE_ADDR        $remote_addr;
    fastcgi_param  REMOTE_PORT        $remote_port;
    fastcgi_param  SERVER_ADDR        $server_addr;
    fastcgi_param  SERVER_PORT        $server_port;
    fastcgi_param  SERVER_NAME        $server_name;
    # PHP only, required if PHP was built with --enable-force-cgi-redirect
    fastcgi_param  REDIRECT_STATUS    200;
	# pathinfo.conf
    set $real_script_name $fastcgi_script_name;
    if ($fastcgi_script_name ~ "^(.+?\.php)(/.+)$") {
            set $real_script_name $1;
            set $path_info $2;
    }
    fastcgi_param SCRIPT_FILENAME $document_root$real_script_name;
    fastcgi_param SCRIPT_NAME $real_script_name;
    fastcgi_param PATH_INFO $path_info;
}`
	// 创建&写入配置文件
	f1, _ := os.Create(sitedir + `/main.conf`)
	defer f1.Close()
	f1.Write([]byte(main))
	f2, _ := os.Create(sitedir + `/rewrite.conf`)
	defer f2.Close()
	f2.Write([]byte(rewrite))
	f3, _ := os.Create(sitedir + `/proxy.conf`)
	defer f3.Close()
	f3.Write([]byte(proxy))
	f4, _ := os.Create(sitedir + `/access.log`)
	defer f4.Close()
	f5, _ := os.Create(sitedir + `/error.log`)
	defer f5.Close()
	f6, _ := os.Create(sitedir + `/cert.pem`)
	defer f6.Close()
	f7, _ := os.Create(sitedir + `/cert.key`)
	defer f7.Close()
	f8, _ := os.Create(sitedir + `/php.conf`)
	defer f8.Close()
	f8.Write([]byte(php))
	f9, _ := os.Create(sitedir + `/ssl.conf`)
	defer f9.Close()
	f9.Write([]byte(ssl))
	fmt.Println("\n生成完毕，请到站点管理启用站点。")
	fmt.Println("\n配置目录：" + sitedir)
	os.Exit(0)
}

func setsite() {
	head(`站点管理`)
	//fmt.Println(`敬请期待！`)
	var siteinput int
	var confirm string
	var sitename [20]string
	var siteactive [20]bool
	fmt.Print("\n扫描中，请稍候...\n\n")
	runpath, _ := os.Getwd()
	sitedir := runpath + `/site`
	files, _ := ioutil.ReadDir(sitedir)
	// 获取文件夹信息
	for num, file := range files {
		// 检测是否为目录
		if file.IsDir() {
			// 检测是否有效 (是否存在 main.conf)
			_, err := os.Stat(sitedir + `/` + file.Name() + `/main.conf`)
			if err == nil {
				fmt.Print(num, `  `+file.Name()+`  `)
				sitename[num] = file.Name()
				// 检测是否激活 (是否存在软链接)
				_, err := os.Stat(nginx_site_path + `/` + file.Name() + `.conf`)
				if err == nil {
					siteactive[num] = true
					fmt.Println(`已激活`)
				} else {
					siteactive[num] = false
					fmt.Println(`未激活`)
				}
			}
		}
	}
	//fmt.Println(`警告：这里也没有错误检测，请输入正确序号，然后二次确认`)
	fmt.Print("\n请输入站点序号：")
	fmt.Scanln(&siteinput)
	if sitename[siteinput] != `` {
		// 判断是否激活
		if siteactive[siteinput] {
			fmt.Println("\n将删除软链接 " + nginx_site_path + `/` + sitename[siteinput] + `.conf`)
			fmt.Print("\n二次确认(y|n): ")
			fmt.Scanln(&confirm)
			if confirm == `y` {
				os.Remove(nginx_site_path + `/` + sitename[siteinput] + `.conf`)
				fmt.Println("\n设置完毕，请到Nginx状态重载配置。")
			} else {
				fmt.Println("\n用户取消操作。")
			}
		} else {
			fmt.Println("\n将创建软链接 " + sitedir + `/` + sitename[siteinput] + `/main.conf => ` + nginx_site_path + `/` + sitename[siteinput] + `.conf`)
			fmt.Print("\n二次确认(y|n): ")
			fmt.Scanln(&confirm)
			if confirm == `y` {
				os.Symlink(sitedir+`/`+sitename[siteinput]+`/main.conf`, nginx_site_path+`/`+sitename[siteinput]+`.conf`)
				fmt.Println("\n设置完毕，请到Nginx状态重载配置。")
			} else {
				fmt.Println("\n用户取消操作。")
			}
		}
	} else {
		fmt.Println("\n站点序号不存在。")
		os.Exit(1)
	}
	// for n, f := range files {
	// 	if n == siteinput {
	// 		//fmt.Println(f.Name())
	// 		siteoutput = f.Name()
	// 		break
	// 	}
	// }
	// fmt.Print("\n将创建软链接 " + runpath + "/site/" + siteoutput + "/main.conf => " + nginx_site_path + `/` + siteoutput + ".conf\n")
	// fmt.Print("\n二次确认(y|n): ")
	// fmt.Scanln(&confirm)
	// if confirm == `y` {
	// 	os.Symlink(runpath+"/site/"+siteoutput+"/main.conf", nginx_site_path+`/`+siteoutput+".conf")
	// 	fmt.Println("\n设置完毕，请到Nginx状态重载配置。")
	// } else {
	// 	fmt.Println("\n用户取消操作。")
	// }
	os.Exit(0)
}

func nginx() {
	head(`Nginx状态`)
	//fmt.Println(`敬请期待！`)
	fmt.Print(`
暂不支持程序控制，请手动输入命令
状态：systemctl status nginx
启动：systemctl start nginx
关闭：systemctl stop nginx
重载：systemctl reload nginx
`)
	os.Exit(0)
}

func uninstall() {
	head(`卸载残留`)
	fmt.Println(`敬请期待！`)
	os.Exit(0)
}
