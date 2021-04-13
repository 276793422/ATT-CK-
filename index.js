/*
	翻译者：NemesisZoo
	QQ：276793422

	此文件功能，汉化 ATT&CK 主界面相关技术元素

	由于本人虽是技术开发，但是本人英语实在是差，所以本人是综合文档和帮助之后翻译的中文

	使用方法：
	1：将当前文件随意放置在web服务器任一位置
	2：在 ATT&CK 框架主界面 index.html 页面中，插入一条JS引用命令。
		<script type="text/javascript" src="index.js" ></script>

	本翻译文档是个外挂式的翻译文档，会自动去寻找相关元素，然后将指定元素位置的文案替换成相关中文，
	功能上很类似机翻插件的功能，但是我感觉，我作为一个安全开发，应该能比机翻准确一点吧。
	最后提供了一个选定技术上色功能，支持快速查看指定技术所在的位置，以及快速将技术ID的位置显示出来。

*/



var translate_str = '{' +
'    "btn btn-default dropdown-toggle":[' +
'        {"src":"layouts",                                  "ch":"布局",                        "en":"layouts"}' +
'    ],' +
'    "dropdown-item layout-button side":[' +
'        {"src":"side layout",                              "ch":"侧边布局",                    "en":"side layout"}' +
'    ],' +
'    "dropdown-item layout-button flat":[' +
'        {"src":"flat layout",                              "ch":"平滑布局",                    "en":"flat layout"}' +
'    ],' +
'    "btn btn-default":[' +
'        {"src":"show sub-techniques",                      "ch":"展示子技术",                  "en":"show sub-techniques"}, ' +
'        {"src":"hide sub-techniques",                      "ch":"隐藏子技术",                  "en":"hide sub-techniques"}' +
'    ],' +
'    "container text-center":[' +
'        {"src":"ATT&CK Matrix for Enterprise",             "ch":"企业安全ATT&CK矩阵",          "en":"ATT&CK Matrix for Enterprise"}' +
'    ],' +
'    "tactic name":[' +
'        {"src":"Reconnaissance",                           "ch":"信息收集",                    "en":"Reconnaissance"}, ' +
'        {"src":"Resource Development",                     "ch":"资源开发",                    "en":"Resource Development"}, ' +
'        {"src":"Initial Access",                           "ch":"初始访问",                    "en":"Initial Access"}, ' +
'        {"src":"Execution",                                "ch":"执行",                        "en":"Execution"}, ' +
'        {"src":"Persistence",                              "ch":"持久化",                      "en":"Persistence"}, ' +
'        {"src":"Privilege Escalation",                     "ch":"提权",                        "en":"Privilege Escalation"}, ' +
'        {"src":"Defense Evasion",                          "ch":"防御规避",                    "en":"Defense Evasion"}, ' +
'        {"src":"Credential Access",                        "ch":"凭证访问",                    "en":"Credential Access"}, ' +
'        {"src":"Discovery",                                "ch":"发现",                        "en":"Discovery"}, ' +
'        {"src":"Lateral Movement",                         "ch":"横向移动",                    "en":"Lateral Movement"}, ' +
'        {"src":"Collection",                               "ch":"收集",                        "en":"Collection"}, ' +
'        {"src":"Command and Control",                      "ch":"命令和控制",                  "en":"Command and Control"}, ' +
'        {"src":"Exfiltration",                             "ch":"泄露",                        "en":"Exfiltration"}, ' +
'        {"src":"Impact",                                   "ch":"影响",                        "en":"Impact"}, ' +
'        {"src":"",                                         "ch":"",                            "en":""}' +
'    ],' +
'    "tactic count":[' +
'        {"src":"techniques",                               "ch":"项技术",                      "en":"techniques"}, ' +
'        {"src":"",                                         "ch":"",                            "en":""}' +
'    ],' +
'    "technique-cell  supertechniquecell":[' +
'        {"src":"Active Scanning",                          "ch":"主动扫描",                    "en":"Active Scanning"}, ' +
'        {"src":"Gather Victim Identity Information",       "ch":"身份信息收集",                "en":"Gather Victim Identity Information"}, ' +
'        {"src":"Gather Victim Host Information",           "ch":"主机信息收集",                "en":"Gather Victim Host Information"}, ' +
'        {"src":"Gather Victim Network Information",        "ch":"网络信息收集",                "en":"Gather Victim Network Information"}, ' +
'        {"src":"Gather Victim Org Information",            "ch":"组织信息收集",                "en":"Gather Victim Org Information"}, ' +
'        {"src":"Phishing for Information",                 "ch":"钓鱼信息收集",                "en":"Phishing for Information"}, ' +
'        {"src":"Search Open Technical Databases",          "ch":"搜索开放信息",                "en":"Search Open Technical Databases"}, ' +
'        {"src":"Search Open Websites/Domains",             "ch":"搜索网站/域",                 "en":"Search Open Websites/Domains"}, ' +
'        {"src":"Acquire Infrastructure",                   "ch":"收购基础设施",                "en":"Acquire Infrastructure"}, ' +
'        {"src":"Compromise Accounts",                      "ch":"攻击账号",                    "en":"Compromise Accounts"}, ' +
'        {"src":"Compromise Infrastructure",                "ch":"攻击基础设施",                "en":"Compromise Infrastructure"}, ' +
'        {"src":"Develop Capabilities",                     "ch":"开发能力",                    "en":"Develop Capabilities"}, ' +
'        {"src":"Establish Accounts",                       "ch":"创建账户",                    "en":"Establish Accounts"}, ' +
'        {"src":"Obtain Capabilities",                      "ch":"获取能力",                    "en":"Obtain Capabilities"}, ' +
'        {"src":"Phishing",                                 "ch":"钓鱼",                        "en":"Phishing"}, ' +
'        {"src":"Supply Chain Compromise",                  "ch":"供应链攻击",                  "en":"Supply Chain Compromise"}, ' +
'        {"src":"Valid Accounts",                           "ch":"有效账户",                    "en":"Valid Accounts"}, ' +
'        {"src":"Command and Scripting Interpreter",        "ch":"命令、脚本解释器",            "en":"Command and Scripting Interpreter"}, ' +
'        {"src":"Inter-Process Communication",              "ch":"进程间通信",                  "en":"Inter-Process Communication"}, ' +
'        {"src":"Scheduled Task/Job",                       "ch":"计划任务",                    "en":"Scheduled Task/Job"}, ' +
'        {"src":"System Services",                          "ch":"系统服务",                    "en":"System Services"}, ' +
'        {"src":"User Execution",                           "ch":"用户执行",                    "en":"User Execution"}, ' +
'        {"src":"Remote Service Session Hijacking",         "ch":"远程服务会话劫持",            "en":"Remote Service Session Hijacking"}, ' +
'        {"src":"Remote Services",                          "ch":"远程服务",                    "en":"Remote Services"}, ' +
'        {"src":"Search Closed Sources",                    "ch":"搜索闭源",                    "en":"Search Closed Sources"}, ' +
'        {"src":"Use Alternate Authentication Material",    "ch":"使用替代认证",                "en":"Use Alternate Authentication Material"}, ' +
'        {"src":"Automated Exfiltration",                   "ch":"自动泄露",                    "en":"Automated Exfiltration"}, ' +
'        {"src":"Exfiltration Over Alternative Protocol",   "ch":"指定协议泄露",                "en":"Exfiltration Over Alternative Protocol"}, ' +
'        {"src":"Exfiltration Over Other Network Medium",   "ch":"其他网络媒体泄露",            "en":"Exfiltration Over Other Network Medium"}, ' +
'        {"src":"Exfiltration Over Physical Medium",        "ch":"物理设备泄露",                "en":"Exfiltration Over Physical Medium"}, ' +
'        {"src":"Exfiltration Over Web Service",            "ch":"网页服务器泄露",              "en":"Exfiltration Over Web Service"}, ' +
'        {"src":"Data Manipulation",                        "ch":"数据篡改",                    "en":"Data Manipulation"}, ' +
'        {"src":"Defacement",                               "ch":"污损",                        "en":"Defacement"}, ' +
'        {"src":"Disk Wipe",                                "ch":"磁盘擦除",                    "en":"Disk Wipe"}, ' +
'        {"src":"Endpoint Denial of Service",               "ch":"端拒绝服务",                  "en":"Endpoint Denial of Service"}, ' +
'        {"src":"Network Denial of Service",                "ch":"网络拒绝服务",                "en":"Network Denial of Service"}, ' +
'        {"src":"Account Discovery",                        "ch":"用户发现",                    "en":"Account Discovery"}, ' +
'        {"src":"Permission Groups Discovery",              "ch":"权限组发现",                  "en":"Permission Groups Discovery"}, ' +
'        {"src":"Software Discovery",                       "ch":"软件发现",                    "en":"Software Discovery"}, ' +
'        {"src":"Virtualization/Sandbox Evasion",           "ch":"虚拟化、沙箱规避",            "en":"Virtualization/Sandbox Evasion"}, ' +
'        {"src":"Application Layer Protocol",               "ch":"应用层协议",                  "en":"Application Layer Protocol"}, ' +
'        {"src":"Data Encoding",                            "ch":"数据编码",                    "en":"Data Encoding"}, ' +
'        {"src":"Data Obfuscation",                         "ch":"数据混淆",                    "en":"Data Obfuscation"}, ' +
'        {"src":"Dynamic Resolution",                       "ch":"动态解析",                    "en":"Dynamic Resolution"}, ' +
'        {"src":"Encrypted Channel",                        "ch":"加密频道",                    "en":"Encrypted Channel"}, ' +
'        {"src":"Proxy",                                    "ch":"代理",                        "en":"Proxy"}, ' +
'        {"src":"Traffic Signaling",                        "ch":"流量信号",                    "en":"Traffic Signaling"}, ' +
'        {"src":"Web Service",                              "ch":"Web服务",                     "en":"Web Service"}, ' +
'        {"src":"Archive Collected Data",                   "ch":"已归档整理的数据",            "en":"Archive Collected Data"}, ' +
'        {"src":"Data from Configuration Repository",       "ch":"配置库中的数据",              "en":"Data from Configuration Repository"}, ' +
'        {"src":"Data from Information Repositories",       "ch":"信息库中的数据",              "en":"Data from Information Repositories"}, ' +
'        {"src":"Data Staged",                              "ch":"数据暂存",                    "en":"Data Staged"}, ' +
'        {"src":"Email Collection",                         "ch":"Email收集",                   "en":"Email Collection"}, ' +
'        {"src":"Input Capture",                            "ch":"输入捕获",                    "en":"Input Capture"}, ' +
'        {"src":"Man-in-the-Middle",                        "ch":"中间人",                      "en":"Man-in-the-Middle"}, ' +
'        {"src":"Brute Force",                              "ch":"爆破",                        "en":"Brute Force"}, ' +
'        {"src":"Credentials from Password Stores",         "ch":"密码库中的凭证",              "en":"Credentials from Password Stores"}, ' +
'        {"src":"Modify Authentication Process",            "ch":"修改认证进程",                "en":"Modify Authentication Process"}, ' +
'        {"src":"OS Credential Dumping",                    "ch":"系统票据转存",                "en":"OS Credential Dumping"}, ' +
'        {"src":"Steal or Forge Kerberos Tickets",          "ch":"盗用、伪造Kerberos认证",      "en":"Steal or Forge Kerberos Tickets"}, ' +
'        {"src":"Unsecured Credentials",                    "ch":"不安全的凭据",                "en":"Unsecured Credentials"}, ' +
'        {"src":"Process Injection",                        "ch":"进程注入",                    "en":"Process Injection"}, ' +
'        {"src":"Hijack Execution Flow",                    "ch":"劫持执行流",                  "en":"Hijack Execution Flow"}, ' +
'        {"src":"Event Triggered Execution",                "ch":"事件触发执行",                "en":"Event Triggered Execution"}, ' +
'        {"src":"Create or Modify System Process",          "ch":"创建、修改系统进程",          "en":"Create or Modify System Process"}, ' +
'        {"src":"Boot or Logon Initialization Scripts",     "ch":"引导、登录时初始化的脚本",    "en":"Boot or Logon Initialization Scripts"}, ' +
'        {"src":"Boot or Logon Autostart Execution",        "ch":"引导、登录初自动执行",        "en":"Boot or Logon Autostart Execution"}, ' +
'        {"src":"Access Token Manipulation",                "ch":"访问令牌利用",                "en":"Access Token Manipulation"}, ' +
'        {"src":"Abuse Elevation Control Mechanism",        "ch":"提权控制利用",                "en":"Abuse Elevation Control Mechanism"}, ' +
'        {"src":"Account Manipulation",                     "ch":"账户操纵",                    "en":"Account Manipulation"}, ' +
'        {"src":"Create Account",                           "ch":"创建账户",                    "en":"Create Account"}, ' +
'        {"src":"Office Application Startup",               "ch":"Office启动",                  "en":"Office Application Startup"}, ' +
'        {"src":"Pre-OS Boot",                              "ch":"引导前",                      "en":"Pre-OS Boot"}, ' +
'        {"src":"Server Software Component",                "ch":"服务器软件组件",              "en":"Server Software Component"}, ' +
'        {"src":"Execution Guardrails",                     "ch":"执行保护",                    "en":"Execution Guardrails"}, ' +
'        {"src":"File and Directory Permissions Modification",    "ch":"文件、目录权限修改",         "en":"File and Directory Permissions Modification"}, ' +
'        {"src":"Hide Artifacts",                           "ch":"隐藏组件",                    "en":"Hide Artifacts"}, ' +
'        {"src":"Impair Defenses",                          "ch":"削弱防御",                    "en":"Impair Defenses"}, ' +
'        {"src":"Indicator Removal on Host",                "ch":"主机记录清除",                "en":"Indicator Removal on Host"}, ' +
'        {"src":"Masquerading",                             "ch":"伪装",                        "en":"Masquerading"}, ' +
'        {"src":"Modify Cloud Compute Infrastructure",      "ch":"修改云计算设备",              "en":"Modify Cloud Compute Infrastructure"}, ' +
'        {"src":"Modify System Image",                      "ch":"修改系统镜像",                "en":"Modify System Image"}, ' +
'        {"src":"Network Boundary Bridging",                "ch":"网络边界桥",                  "en":"Network Boundary Bridging"}, ' +
'        {"src":"Obfuscated Files or Information",          "ch":"文件、信息混淆",              "en":"Obfuscated Files or Information"}, ' +
'        {"src":"Signed Binary Proxy Execution",            "ch":"签名文件代理执行",            "en":"Signed Binary Proxy Execution"}, ' +
'        {"src":"Signed Script Proxy Execution",            "ch":"签名脚本代理执行",            "en":"Signed Script Proxy Execution"}, ' +
'        {"src":"Subvert Trust Controls",                   "ch":"破坏信任控制器",              "en":"Subvert Trust Controls"}, ' +
'        {"src":"Trusted Developer Utilities Proxy Execution",    "ch":"信任开发工具代理执行",       "en":"Trusted Developer Utilities Proxy Execution"}, ' +
'        {"src":"Weaken Encryption",                        "ch":"削弱加密",                    "en":"Weaken Encryption"}, ' +
'        {"src":"",                                         "ch":"",                            "en":""}' +
'    ],' +
'    "technique-cell ":[' +
'        {"src":"Scanning IP Blocks",                       "ch":"IP扫描",                      "en":"Scanning IP Blocks"}, ' +
'        {"src":"Vulnerability Scanning",                   "ch":"漏扫",                        "en":"Vulnerability Scanning"}, ' +
'        {"src":"Shared Modules",                           "ch":"共享模块",                    "en":"Shared Modules"}, ' +
'        {"src":"Credentials",                              "ch":"证书",                        "en":"Credentials"}, ' +
'        {"src":"Email Addresses",                          "ch":"电子邮箱",                    "en":"Email Addresses"}, ' +
'        {"src":"Employee Names",                           "ch":"员工名字",                    "en":"Employee Names"}, ' +
'        {"src":"Hardware",                                 "ch":"硬件",                        "en":"Hardware"}, ' +
'        {"src":"Software",                                 "ch":"软件",                        "en":"Software"}, ' +
'        {"src":"Firmware",                                 "ch":"固件",                        "en":"Firmware"}, ' +
'        {"src":"Client Configurations",                    "ch":"客户端配置",                  "en":"Client Configurations"}, ' +
'        {"src":"Domain Properties",                        "ch":"域信息",                      "en":"Domain Properties"}, ' +
'        {"src":"Network Trust Dependencies",               "ch":"网络可信依赖",                "en":"Network Trust Dependencies"}, ' +
'        {"src":"Network Topology",                         "ch":"网络拓扑结构",                "en":"Network Topology"}, ' +
'        {"src":"IP Addresses",                             "ch":"IP地址",                      "en":"IP Addresses"}, ' +
'        {"src":"Network Security Appliances",              "ch":"网络安全设备",                "en":"Network Security Appliances"}, ' +
'        {"src":"Business Relationships",                   "ch":"商业关系",                    "en":"Business Relationships"}, ' +
'        {"src":"Determine Physical Locations",             "ch":"物理地址",                    "en":"Determine Physical Locations"}, ' +
'        {"src":"Identify Business Tempo",                  "ch":"业务节奏",                    "en":"Identify Business Tempo"}, ' +
'        {"src":"Identify Roles",                           "ch":"角色",                        "en":"Identify Roles"}, ' +
'        {"src":"Search Victim-Owned Websites",             "ch":"拥有网站",                    "en":"Search Victim-Owned Websites"}, ' +
'        {"src":"External Remote Services",                 "ch":"外部远程服务",                "en":"External Remote Services"}, ' +
'        {"src":"Replication Through Removable Media",      "ch":"移动设备复制",                "en":"Replication Through Removable Media"}, ' +
'        {"src":"Trusted Relationship",                     "ch":"信任关系",                    "en":"Trusted Relationship"}, ' +
'        {"src":"Hardware Additions",                       "ch":"添加硬件",                    "en":"Hardware Additions"}, ' +
'        {"src":"Drive-by Compromise",                      "ch":"Drive-by攻击",                "en":"Drive-by Compromise"}, ' +
'        {"src":"Exploit Public-Facing Application",        "ch":"对外开放程序利用",            "en":"Exploit Public-Facing Application"}, ' +
'        {"src":"Exploitation for Client Execution",        "ch":"客户端执行程序利用",          "en":"Exploitation for Client Execution"}, ' +
'        {"src":"Shared Modules",                           "ch":"共享模块",                    "en":"Shared Modules"}, ' +
'        {"src":"Software Deployment Tools",                "ch":"软件部署工具",                "en":"Software Deployment Tools"}, ' +
'        {"src":"Exploitation of Remote Services",          "ch":"远程服务利用",                "en":"Exploitation of Remote Services"}, ' +
'        {"src":"Internal Spearphishing",                   "ch":"内部鱼叉攻击",                "en":"Internal Spearphishing"}, ' +
'        {"src":"Lateral Tool Transfer",                    "ch":"横向工具转移",                "en":"Lateral Tool Transfer"}, ' +
'        {"src":"Windows Management Instrumentation",       "ch":"WMI",                         "en":"Windows Management Instrumentation"}, ' +
'        {"src":"Taint Shared Content",                     "ch":"污染共享内容",                "en":"Taint Shared Content"}, ' +
'        {"src":"Data Transfer Size Limits",                "ch":"数据传输大小限制",            "en":"Data Transfer Size Limits"}, ' +
'        {"src":"Exfiltration Over C2 Channel",             "ch":"C2通道泄露",                  "en":"Exfiltration Over C2 Channel"}, ' +
'        {"src":"Scheduled Transfer",                       "ch":"预定转移",                    "en":"Scheduled Transfer"}, ' +
'        {"src":"Transfer Data to Cloud Account",           "ch":"数据上云",                    "en":"Transfer Data to Cloud Account"}, ' +
'        {"src":"Account Access Removal",                   "ch":"账户权限移除",                "en":"Account Access Removal"}, ' +
'        {"src":"Data Destruction",                         "ch":"数据销毁",                    "en":"Data Destruction"}, ' +
'        {"src":"Data Encrypted for Impact",                "ch":"加密数据",                    "en":"Data Encrypted for Impact"}, ' +
'        {"src":"Firmware Corruption",                      "ch":"固件损坏",                    "en":"Firmware Corruption"}, ' +
'        {"src":"Inhibit System Recovery",                  "ch":"阻止系统恢复",                "en":"Inhibit System Recovery"}, ' +
'        {"src":"Resource Hijacking",                       "ch":"资源劫持",                    "en":"Resource Hijacking"}, ' +
'        {"src":"Service Stop",                             "ch":"停止服务",                    "en":"Service Stop"}, ' +
'        {"src":"System Shutdown/Reboot",                   "ch":"系统关机、重启",              "en":"System Shutdown/Reboot"}, ' +
'        {"src":"Process Discovery",                        "ch":"进程发现",                    "en":"Process Discovery"}, ' +
'        {"src":"Query Registry",                           "ch":"注册表查询",                  "en":"Query Registry"}, ' +
'        {"src":"Remote System Discovery",                  "ch":"远程系统发现",                "en":"Remote System Discovery"}, ' +
'        {"src":"System Owner/User Discovery",              "ch":"系统所有者、用户发现",        "en":"System Owner/User Discovery"}, ' +
'        {"src":"System Service Discovery",                 "ch":"系统服务发现",                "en":"System Service Discovery"}, ' +
'        {"src":"System Time Discovery",                    "ch":"系统时间发现",                "en":"System Time Discovery"}, ' +
'        {"src":"Application Window Discovery",             "ch":"程序窗口发现",                "en":"Application Window Discovery"}, ' +
'        {"src":"Browser Bookmark Discovery",               "ch":"浏览器收藏夹发现",            "en":"Browser Bookmark Discovery"}, ' +
'        {"src":"Cloud Infrastructure Discovery",           "ch":"云设备发现",                  "en":"Cloud Infrastructure Discovery"}, ' +
'        {"src":"Cloud Service Dashboard",                  "ch":"云服务面板",                  "en":"Cloud Service Dashboard"}, ' +
'        {"src":"Cloud Service Discovery",                  "ch":"云服务发现",                  "en":"Cloud Service Discovery"}, ' +
'        {"src":"Domain Trust Discovery",                   "ch":"域信任发现",                  "en":"Domain Trust Discovery"}, ' +
'        {"src":"File and Directory Discovery",             "ch":"文件、目录发现",              "en":"File and Directory Discovery"}, ' +
'        {"src":"Network Service Scanning",                 "ch":"网络服务扫描",                "en":"Network Service Scanning"}, ' +
'        {"src":"Network Share Discovery",                  "ch":"网络共享发现",                "en":"Network Share Discovery"}, ' +
'        {"src":"Network Sniffing",                         "ch":"网络嗅探",                    "en":"Network Sniffing"}, ' +
'        {"src":"Password Policy Discovery",                "ch":"密码策略发现",                "en":"Password Policy Discovery"}, ' +
'        {"src":"Peripheral Device Discovery",              "ch":"外部设备发现",                "en":"Peripheral Device Discovery"}, ' +
'        {"src":"System Information Discovery",             "ch":"系统信息发现",                "en":"System Information Discovery"}, ' +
'        {"src":"System Network Configuration Discovery",   "ch":"系统网络配置发现",            "en":"System Network Configuration Discovery"}, ' +
'        {"src":"System Network Connections Discovery",     "ch":"系统网络链接发现",            "en":"System Network Connections Discovery"}, ' +
'        {"src":"Web Protocols",                            "ch":"Web协议",                     "en":"Web Protocols"}, ' +
'        {"src":"File Transfer Protocols",                  "ch":"文件传输协议",                "en":"File Transfer Protocols"}, ' +
'        {"src":"Mail Protocols",                           "ch":"邮件协议",                    "en":"Mail Protocols"}, ' +
'        {"src":"Communication Through Removable Media",    "ch":"移动媒体通信",                "en":"Communication Through Removable Media"}, ' +
'        {"src":"Standard Encoding",                        "ch":"标准编码",                    "en":"Standard Encoding"}, ' +
'        {"src":"Non-Standard Encoding",                    "ch":"非标准编码",                  "en":"Non-Standard Encoding"}, ' +
'        {"src":"Junk Data",                                "ch":"垃圾数据",                    "en":"Junk Data"}, ' +
'        {"src":"Steganography",                            "ch":"加密",                        "en":"Steganography"}, ' +
'        {"src":"Protocol Impersonation",                   "ch":"协议模拟",                    "en":"Protocol Impersonation"}, ' +
'        {"src":"Security Software Discovery",              "ch":"安全软件发现",                "en":"Security Software Discovery"}, ' +
'        {"src":"Fallback Channels",                        "ch":"备用频道",                    "en":"Fallback Channels"}, ' +
'        {"src":"Ingress Tool Transfer",                    "ch":"入口工具转移",                "en":"Ingress Tool Transfer"}, ' +
'        {"src":"Multi-Stage Channels",                     "ch":"多级通道",                    "en":"Multi-Stage Channels"}, ' +
'        {"src":"Non-Application Layer Protocol",           "ch":"非应用层协议",                "en":"Non-Application Layer Protocol"}, ' +
'        {"src":"Non-Standard Port",                        "ch":"非常规端口",                  "en":"Non-Standard Port"}, ' +
'        {"src":"Protocol Tunneling",                       "ch":"协议隧道",                    "en":"Protocol Tunneling"}, ' +
'        {"src":"Remote Access Software",                   "ch":"远程访问软件",                "en":"Remote Access Software"}, ' +
'        {"src":"Audio Capture",                            "ch":"捕获音频",                    "en":"Audio Capture"}, ' +
'        {"src":"Automated Collection",                     "ch":"自动收集",                    "en":"Automated Collection"}, ' +
'        {"src":"Clipboard Data",                           "ch":"剪贴板数据",                  "en":"Clipboard Data"}, ' +
'        {"src":"Data from Cloud Storage Object",           "ch":"云上的数据",                  "en":"Data from Cloud Storage Object"}, ' +
'        {"src":"Data from Local System",                   "ch":"本地系统中的数据",            "en":"Data from Local System"}, ' +
'        {"src":"Data from Network Shared Drive",           "ch":"网络共享设备中的数据",        "en":"Data from Network Shared Drive"}, ' +
'        {"src":"Data from Removable Media",                "ch":"移动介质中的数据",            "en":"Data from Removable Media"}, ' +
'        {"src":"Man in the Browser",                       "ch":"浏览器跳板",                  "en":"Man in the Browser"}, ' +
'        {"src":"Screen Capture",                           "ch":"截屏",                        "en":"Screen Capture"}, ' +
'        {"src":"Video Capture",                            "ch":"截视频",                      "en":"Video Capture"}, ' +
'        {"src":"Exploitation for Credential Access",       "ch":"凭证访问利用",                "en":"Exploitation for Credential Access"}, ' +
'        {"src":"Forced Authentication",                    "ch":"强制身份验证",                "en":"Forced Authentication"}, ' +
'        {"src":"Steal Application Access Token",           "ch":"盗用程序令牌",                "en":"Steal Application Access Token"}, ' +
'        {"src":"Steal Web Session Cookie",                 "ch":"盗用Web Cookie",              "en":"Steal Web Session Cookie"}, ' +
'        {"src":"Two-Factor Authentication Interception",   "ch":"2FA拦截",                     "en":"Two-Factor Authentication Interception"}, ' +
'        {"src":"Group Policy Modification",                "ch":"组策略修改",                  "en":"Group Policy Modification"}, ' +
'        {"src":"Exploitation for Privilege Escalation",    "ch":"提权利用",                    "en":"Exploitation for Privilege Escalation"}, ' +
'        {"src":"BITS Jobs",                                "ch":"后台智能传输服务",            "en":"BITS Jobs"}, ' +
'        {"src":"Browser Extensions",                       "ch":"浏览器扩展",                  "en":"Browser Extensions"}, ' +
'        {"src":"Compromise Client Software Binary",        "ch":"篡改客户端二进制文件",        "en":"Compromise Client Software Binary"}, ' +
'        {"src":"Implant Container Image",                  "ch":"植入容器镜像",                "en":"Implant Container Image"}, ' +
'        {"src":"Deobfuscate/Decode Files or Information",  "ch":"解密、解码文件、信息",        "en":"Deobfuscate/Decode Files or Information"}, ' +
'        {"src":"Direct Volume Access",                     "ch":"直接卷访问",                  "en":"Direct Volume Access"}, ' +
'        {"src":"Exploitation for Defense Evasion",         "ch":"防御绕过利用",                "en":"Exploitation for Defense Evasion"}, ' +
'        {"src":"Indirect Command Execution",               "ch":"间接命令执行",                "en":"Indirect Command Execution"}, ' +
'        {"src":"Modify Registry",                          "ch":"修改注册表",                  "en":"Modify Registry"}, ' +
'        {"src":"Rogue Domain Controller",                  "ch":"流氓域控",                    "en":"Rogue Domain Controller"}, ' +
'        {"src":"Template Injection",                       "ch":"模板注入",                    "en":"Template Injection"}, ' +
'        {"src":"Unused/Unsupported Cloud Regions",         "ch":"未使用、不支持的云地区",      "en":"Unused/Unsupported Cloud Regions"}, ' +
'        {"src":"XSL Script Processing",                    "ch":"XSL脚本处理",                 "en":"XSL Script Processing"}, ' +
'        {"src":"",                                         "ch":"",                            "en":""}' +
'    ],' +
'    "version": "0.1"' +
'}';

var translate = JSON.parse(translate_str);

var strLanguage = 'ch';

function GetTranslate(table, src, type="ch") {
    for (var i = translate[table].length - 1; i >= 0; i--) {
        if (src == translate[table][i].src) {
            return translate[table][i][type];
        }
    }
    return src;
}

//	处理按钮
function RemakeButton() {
    strTable = 'btn btn-default dropdown-toggle';
    tactics = document.getElementsByClassName(strTable);
    tactics[0].textContent = GetTranslate(strTable, tactics[0].textContent, strLanguage);

    strTable = 'dropdown-item layout-button side';
    tactics = document.getElementsByClassName(strTable);
    if (tactics.length == 0) {
    	tactics = document.getElementsByClassName(strTable) + " active";
    }
    tactics[0].text = GetTranslate(strTable, $.trim(tactics[0].text), strLanguage);

    strTable = 'dropdown-item layout-button flat';
    tactics = document.getElementsByClassName(strTable);
    if (tactics.length == 0) {
    	tactics = document.getElementsByClassName(strTable) + " active";
    }
    tactics[0].text = GetTranslate(strTable, $.trim(tactics[0].text), strLanguage);

    strTable = 'btn btn-default'
    tactics = document.getElementsByClassName(strTable);
    for (var i = 0; i < tactics.length; i++) {
    	tactics[i].textContent = GetTranslate(strTable, tactics[i].textContent, strLanguage);
    }
}

//	修改标题Title
function RemakeCenterTitle() {
    var strTable = 'container text-center';
    var tactics = document.getElementsByClassName(strTable);
    tactics[0].firstChild.nextSibling.textContent = GetTranslate(strTable, tactics[0].firstChild.nextSibling.textContent, strLanguage);
    return true;
}

//  修改技能组名
function RemakeTacticName() {
    var strTable = 'tactic name';
    var tactics = document.getElementsByClassName(strTable);
    for (i = 0; i < tactics.length; i++) {
        var text = tactics[i].firstChild.text;
        if (strLanguage != 'en') {
            tactics[i].firstChild.title += " (" + text + ")";
        }
        tactics[i].firstChild.text = GetTranslate(strTable, text, strLanguage);
    }
    return true;
}

//	修改技术数量文案
function RemakeTacticCount() {
    var strTable = 'tactic count';
    var strKey = 'techniques';
    var tactics = document.getElementsByClassName(strTable);
    for (i = 0; i < tactics.length; i++) {
        tactics[i].textContent = tactics[i].textContent.replace(strKey, GetTranslate(strTable, strKey, strLanguage));
    }
    return true;
}

//	修改技术大项名称
function RemakeTechniqueCell() {
    var strTable = 'technique-cell  supertechniquecell';
    var tactics = document.getElementsByClassName(strTable);
    for (i = 0; i < tactics.length; i++) {
        var group = tactics[i].firstChild.nextSibling.text.split(" (");
        if (strLanguage != 'en') {
            tactics[i].firstChild.nextSibling.title += " (" + group[0] + ")";
        }
        if (group.length == 1) {
       	    tactics[i].firstChild.nextSibling.text = GetTranslate(strTable, group[0], strLanguage);
        } else {
            //	永远都进这里
            tactics[i].firstChild.nextSibling.text = GetTranslate(strTable, group[0], strLanguage) + " (" + group[1];
        }
    }
    return true;
}

//	修改技术大项名称，无子项的
function RemakeTechniqueCell2() {
	var strTable = 'technique-cell ';
    var tactics = document.getElementsByClassName(strTable);
    for (i = 0; i < tactics.length; i++) {
        var group = tactics[i].firstChild.nextSibling.text.split(" (");
        if (strLanguage != 'en') {
            tactics[i].firstChild.nextSibling.title += " (" + group[0] + ")";
        }
        if (group.length == 1) {
            //	永远都进这里
       	    tactics[i].firstChild.nextSibling.text = GetTranslate(strTable, group[0], strLanguage);
        } else {
            tactics[i].firstChild.nextSibling.text = GetTranslate(strTable, group[0], strLanguage) + " (" + group[1];
        }
    }
    return true;
}

//	设置背景色
function SetBackgroundColor(tables) {
    //	style="background:#00FF00"
    var tactics1 = document.getElementsByClassName('technique-cell  supertechniquecell');
    var tactics2 = document.getElementsByClassName('technique-cell ');
    for (var index = 0; index < tables.length; index++) {
        var tb = tables[index];
	    for (i = 0; i < tactics1.length; i++) {
	        var strObject = tactics1[i].firstChild.nextSibling.getAttribute('data-original-title');
	        if (strObject.substr(0, tb.length) == tb) {
	        	//	去掉子项
	            if (strObject.length > tb.length && strObject.substr(tb.length, 1) != ".") {
	                tactics1[i].setAttribute('style', 'background:#00FF00');
	            }
	        }
	    }
	    for (i = 0; i < tactics2.length; i++) {
	        var strObject = tactics2[i].firstChild.nextSibling.getAttribute('data-original-title');
	        if (strObject.substr(0, tb.length) == tb) {
	        	//	去掉子项
	            if (strObject.length > tb.length && strObject.substr(tb.length, 1) != ".") {
	                tactics2[i].setAttribute('style', 'background:#00FF00');
	            }
	        }
	    }
    }
    return true;
}

//	插入查询
function InsertSearchButton() {
    var strTable = 'matrix-controls';
    var tactics = document.getElementsByClassName(strTable);

    var div = document.createElement('div');
    div.className = "btn-toolbar";
    div.innerHTML=
    '    <div class="btn-group mr-2" role="group">' +
    '        <input id="search_input" type="text" name="wd" id="wd" data-control="balloon">' +
    '        <button type="button" class="btn btn-default" onclick="InsertSearch()">查询位置</button>' +
    '    </div>';

    tactics[0].appendChild(div);
}

function showCard() {
	RemakeButton();
    RemakeCenterTitle();
    RemakeTacticName();
    RemakeTacticCount();
    RemakeTechniqueCell();
    RemakeTechniqueCell2();
    InsertSearchButton();
    return true;
}

window.onload = showCard;

function InsertSearch() {
	var str = document.getElementById('search_input').value;
	var strarr = str.split(',');
	for (var i = 0; i < strarr.length; i++) {
		var strtmp = strarr[i];
		strtmp = strtmp.replace(/\s*/g,"");
		if (strtmp[0] == 'T') {

		} else if (strtmp[0] == 't') {
			strtmp = strtmp.replace("t","T");
		} else {
			strtmp = "T" + strtmp;
		}
		strarr[i] = strtmp;
	}
	SetBackgroundColor(strarr);
}


































