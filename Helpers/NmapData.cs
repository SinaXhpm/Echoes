using System;
using System.Collections.Generic;

namespace Echoes.Helpers;

/// <summary>
/// Static, AOT-safe reference data for the scanner: port → service names, nmap's frequency-ordered top ports for
/// TCP and for UDP (so "top-100" scans the 100 ports most often found open for each protocol, as nmap's
/// --top-ports does — the TCP list is the wrong one for a UDP scan), and the -T0..-T5 timing templates.
/// The port lists and most names come from nmap-services; a short curated map overrides labels that are historic
/// and misleading today (8888 "sun-answerbook", 3000 "ppp").
/// </summary>
public static class NmapData
{
    // Modern names that win over nmap-services' labels (and cover a few ports outside the top lists).
    private static readonly Dictionary<int, string> Curated = new()
    {
        [7] = "echo", [9] = "discard", [13] = "daytime", [17] = "qotd", [19] = "chargen",
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp",
        [37] = "time", [43] = "whois", [49] = "tacacs", [53] = "domain", [67] = "dhcps",
        [68] = "dhcpc", [69] = "tftp", [70] = "gopher", [79] = "finger", [80] = "http",
        [88] = "kerberos-sec", [102] = "iso-tsap", [110] = "pop3", [111] = "rpcbind",
        [113] = "ident", [119] = "nntp", [123] = "ntp", [135] = "msrpc", [137] = "netbios-ns",
        [138] = "netbios-dgm", [139] = "netbios-ssn", [143] = "imap", [161] = "snmp",
        [162] = "snmptrap", [179] = "bgp", [194] = "irc", [389] = "ldap", [427] = "svrloc",
        [443] = "https", [445] = "microsoft-ds", [464] = "kpasswd", [465] = "smtps",
        [500] = "isakmp", [523] = "ibm-db2", [540] = "uucp", [548] = "afp", [554] = "rtsp",
        [587] = "submission", [593] = "http-rpc-epmap", [623] = "ipmi", [631] = "ipp",
        [636] = "ldaps", [646] = "ldp", [873] = "rsync", [902] = "vmware-auth", [989] = "ftps-data",
        [990] = "ftps", [993] = "imaps", [995] = "pop3s", [1080] = "socks",
        [1099] = "rmiregistry", [1194] = "openvpn", [1241] = "nessus", [1311] = "dell-openmanage",
        [1433] = "ms-sql-s", [1434] = "ms-sql-m", [1521] = "oracle", [1604] = "citrix-ica",
        [1701] = "l2tp", [1723] = "pptp", [1812] = "radius", [1813] = "radius-acct", [1883] = "mqtt",
        [1900] = "upnp", [2049] = "nfs", [2082] = "cpanel", [2083] = "cpanel-ssl", [2086] = "whm",
        [2087] = "whm-ssl", [2095] = "webmail", [2096] = "webmail-ssl", [2181] = "zookeeper",
        [2222] = "ssh-alt", [2375] = "docker", [2376] = "docker-ssl", [2483] = "oracle-db",
        [2484] = "oracle-db-ssl", [3000] = "http-alt", [3128] = "squid-http", [3260] = "iscsi",
        [3268] = "globalcat-ldap", [3306] = "mysql", [3389] = "ms-wbt-server", [3478] = "stun",
        [3690] = "svn", [4369] = "epmd", [4500] = "nat-t-ike", [4786] = "smart-install", [4899] = "radmin",
        [5000] = "upnp", [5060] = "sip", [5061] = "sips", [5222] = "xmpp-client", [5223] = "xmpp-client-ssl",
        [5269] = "xmpp-server", [5353] = "mdns", [5432] = "postgresql", [5601] = "kibana", [5672] = "amqp",
        [5683] = "coap", [5900] = "vnc", [5938] = "teamviewer", [5984] = "couchdb", [5985] = "wsman",
        [5986] = "wsmans", [6379] = "redis", [6443] = "kubernetes-api", [6514] = "syslog-tls",
        [6667] = "irc", [6697] = "ircs-tls", [6881] = "bittorrent", [7443] = "https-alt", [7474] = "neo4j",
        [7547] = "cwmp", [7687] = "bolt", [8000] = "http-alt", [8008] = "http", [8009] = "ajp13",
        [8080] = "http-proxy", [8081] = "http-alt", [8086] = "influxdb", [8089] = "splunkd",
        [8091] = "couchbase", [8096] = "jellyfin", [8123] = "home-assistant", [8140] = "puppet",
        [8291] = "winbox", [8333] = "bitcoin", [8443] = "https-alt", [8500] = "consul", [8530] = "wsus",
        [8545] = "ethereum-rpc", [8728] = "mikrotik-api", [8834] = "nessus-web", [8888] = "http-alt",
        [8983] = "solr", [9000] = "cslistener", [9042] = "cassandra", [9090] = "prometheus",
        [9092] = "kafka", [9100] = "jetdirect", [9200] = "elasticsearch", [9300] = "elasticsearch",
        [9418] = "git", [9443] = "https-alt", [10000] = "webmin", [10250] = "kubelet",
        [11211] = "memcached", [15672] = "rabbitmq-mgmt", [25565] = "minecraft", [27017] = "mongodb",
        [27018] = "mongodb", [32400] = "plex", [51820] = "wireguard",
    };

    // nmap-services names for the top-1000 TCP ports ("port=name ...").
    private const string TcpNames =
        "1=tcpmux 3=compressnet 7=echo 9=discard 13=daytime 17=qotd 19=chargen 20=ftp-data 21=ftp 22=ssh 23=telnet " +
        "24=priv-mail 25=smtp 26=rsftp 33=dsp 37=time 42=nameserver 43=whois 49=tacacs 53=domain 70=gopher 79=finger " +
        "80=http 81=hosts2-ns 82=xfer 83=mit-ml-dev 84=ctf 85=mit-ml-dev 88=kerberos-sec 89=su-mit-tg 90=dnsix " +
        "99=metagram 100=newacct 106=pop3pw 109=pop2 110=pop3 111=rpcbind 113=ident 119=nntp 125=locus-map 135=msrpc " +
        "139=netbios-ssn 143=imap 144=news 146=iso-tp0 161=snmp 163=cmip-man 179=bgp 199=smux 211=914c-g 212=anet " +
        "222=rsh-spx 256=fw1-secureremote 259=esro-gen 264=bgmp 280=http-mgmt 311=asip-webadmin 366=odmr 389=ldap " +
        "406=imsp 407=timbuktu 416=silverplatter 417=onmux 425=icad-el 427=svrloc 443=https 444=snpp 445=microsoft-ds " +
        "458=appleqtc 464=kpasswd5 465=smtps 481=dvs 497=retrospect 500=isakmp 512=exec 513=login 514=shell 515=printer " +
        "524=ncp 541=uucp-rlogin 543=klogin 544=kshell 545=ekshell 548=afp 554=rtsp 555=dsf 563=snews 587=submission " +
        "593=http-rpc-epmap 616=sco-sysmgr 617=sco-dtmgr 625=apple-xsrvr-admin 631=ipp 636=ldapssl 646=ldp 648=rrp " +
        "666=doom 667=disclose 668=mecomm 683=corba-iiop 687=asipregistry 691=resvc 700=epp 705=agentx 711=cisco-tdp " +
        "714=iris-xpcs 749=kerberos-adm 765=webster 777=multiling-http 783=spamassassin 787=qsc 800=mdbs_daemon " +
        "801=device 808=ccproxy-http 873=rsync 888=accessbuilder 898=sun-manageconsole 900=omginitialrefs 901=samba-swat " +
        "902=iss-realsecure 903=iss-console-mgr 911=xact-backup 912=apex-mesh 990=ftps 992=telnets 993=imaps 995=pop3s " +
        "999=garcon 1000=cadlock 1001=webpush 1002=windows-icfw 1010=surf 1021=exp1 1022=exp2 1023=netvenuechat 1024=kdm " +
        "1025=NFS-or-IIS 1026=LSA-or-nterm 1027=IIS 1029=ms-lsa 1030=iad1 1031=iad2 1032=iad3 1033=netinfo " +
        "1034=zincite-a 1035=multidropper 1036=nsstp 1037=ams 1038=mtqp 1039=sbl 1040=netsaint 1041=danf-ak2 1042=afrog " +
        "1043=boinc 1044=dcutility 1045=fpitp 1046=wfremotertm 1047=neod1 1048=neod2 1049=td-postman " +
        "1050=java-or-OTGfileshare 1051=optima-vnet 1052=ddt 1053=remote-as 1054=brvread 1055=ansyslmd 1056=vfo " +
        "1057=startron 1058=nim 1059=nimreg 1060=polestar 1061=kiosk 1062=veracity 1063=kyoceranetdev 1064=jstel " +
        "1065=syscomlan 1066=fpo-fns 1067=instl_boots 1068=instl_bootc 1069=cognex-insight 1070=gmrupdateserv " +
        "1071=bsquare-voip 1072=cardax 1073=bridgecontrol 1074=warmspotMgmt 1075=rdrmshc 1076=sns_credit 1077=imgames " +
        "1078=avocent-proxy 1079=asprovatalk 1080=socks 1081=pvuniwien 1082=amt-esd-prot 1083=ansoft-lm-1 " +
        "1084=ansoft-lm-2 1085=webobjects 1086=cplscrambler-lg 1087=cplscrambler-in 1088=cplscrambler-al 1089=ff-annunc " +
        "1090=ff-fms 1091=ff-sm 1092=obrpd 1093=proofd 1094=rootd 1095=nicelink 1096=cnrprotocol 1097=sunclustermgr " +
        "1098=rmiactivation 1099=rmiregistry 1100=mctp 1102=adobeserver-1 1104=xrl 1105=ftranhc 1106=isoipsigport-1 " +
        "1107=isoipsigport-2 1108=ratio-adp 1110=nfsd-status 1111=lmsocialserver 1112=msql 1113=ltp-deepspace " +
        "1114=mini-sql 1117=ardus-mtrns 1119=bnetgame 1121=rmpp 1122=availant-mgr 1123=murray 1124=hpvmmcontrol " +
        "1126=hpvmmdata 1130=casp 1131=caspssl 1132=kvm-via-ip 1137=trim 1138=encrypted_admin 1141=mxomss 1145=x9-icue " +
        "1147=capioverlan 1148=elfiq-repl 1149=bvtsonar 1151=unizensus 1152=winpoplanmess 1154=resacommunity 1163=sddp " +
        "1164=qsm-proxy 1165=qsm-gui 1166=qsm-remote 1169=tripwire 1174=fnet-remote-ui 1175=dossier 1183=llsurfup-http " +
        "1185=catchpole 1186=mysql-cluster 1187=alias 1192=caids-sensor 1198=cajo-discovery 1199=dmidi 1201=nucleus-sand " +
        "1213=mpc-lifenet 1216=etebac5 1217=hpss-ndapi 1218=aeroflight-ads 1233=univ-appserver 1234=hotline " +
        "1236=bvcontrol 1244=isbconference1 1247=visionpyramid 1248=hermes 1259=opennl-voice 1271=excw 1272=cspmlockmgr " +
        "1277=miva-mqs 1287=routematch 1296=dproxy 1300=h323hostcallsc 1301=ci3-software-1 1309=jtag-server 1310=husky " +
        "1311=rxmon 1322=novation 1328=ewall 1334=writesrv 1352=lotusnotes 1417=timbuktu-srv1 1433=ms-sql-s " +
        "1434=ms-sql-m 1443=ies-lm 1455=esl-lm 1461=ibm_wrless_lan 1494=citrix-ica 1500=vlsi-lm 1501=sas-3 1503=imtc-mcs " +
        "1521=oracle 1524=ingreslock 1533=virtual-places 1556=veritas_pbx 1580=tn-tl-r1 1583=simbaexpress 1594=sixtrak " +
        "1600=issd 1641=invision 1658=sixnetudr 1666=netview-aix-6 1687=nsjtp-ctrl 1688=nsjtp-data 1700=mps-raft " +
        "1717=fj-hdnet 1718=h323gatedisc 1719=h323gatestat 1720=h323q931 1721=caicci 1723=pptp 1755=wms 1761=landesk-rc " +
        "1782=hp-hcip 1801=msmq 1805=enl-name 1812=radius 1839=netopia-vo1 1840=netopia-vo2 1862=mysql-cm-agent " +
        "1863=msnp 1864=paradym-31 1875=westell-stats 1900=upnp 1914=elm-momentum 1935=rtmp 1947=sentinelsrm " +
        "1971=netop-school 1972=intersys-cache 1974=drp 1984=bigbrother 1998=x25-svc-port 1999=tcp-id-port " +
        "2000=cisco-sccp 2001=dc 2002=globe 2003=finger 2004=mailbox 2005=deslogin 2006=invokator 2007=dectalk 2008=conf " +
        "2009=news 2010=search 2013=raid-am 2020=xinupageserver 2021=servexec 2022=down 2030=device2 2033=glogger " +
        "2034=scoremgr 2035=imsldoc 2038=objectmanager 2040=lam 2041=interbase 2042=isis 2043=isis-bcast 2045=cdfunc " +
        "2046=sdfunc 2047=dls 2048=dls-monitor 2049=nfs 2065=dlsrpn 2068=avocentkvm 2099=h2250-annex-g 2100=amiganetfs " +
        "2103=zephyr-clt 2105=eklogin 2106=ekshell 2107=msmq-mgmt 2111=kx 2119=gsigatekeeper 2121=ccproxy-ftp " +
        "2126=pktcable-cops 2135=gris 2144=lv-ffx 2160=apc-2160 2161=apc-agent 2170=eyetv 2179=vmrdp 2190=tivoconnect " +
        "2191=tvbus 2200=ici 2222=EtherNetIP-1 2251=dif-port 2260=apc-2260 2288=netml 2301=compaqdiag 2323=3d-nfsd " +
        "2366=qip-login 2381=compaq-https 2382=ms-olap3 2383=ms-olap4 2393=ms-olap1 2394=ms-olap2 2399=fmpro-fdal " +
        "2401=cvspserver 2492=groove 2500=rtsserv 2522=windb 2525=ms-v-worlds 2557=nicetec-mgmt 2601=zebra 2602=ripd " +
        "2604=ospfd 2605=bgpd 2607=connection 2608=wag-service 2638=sybase 2701=sms-rcinfo 2702=sms-xfer " +
        "2710=sso-service 2717=pn-requester 2718=pn-requester2 2725=msolap-ptp2 2800=acc-raid 2809=corbaloc 2811=gsiftp " +
        "2869=icslap 2875=dxmessagebase2 2909=funk-dialout 2910=tdaccess 2920=roboeda 2967=symantec-av 2968=enpp " +
        "2998=iss-realsec 3000=ppp 3001=nessus 3003=cgms 3005=deslogin 3006=deslogind 3011=trusted-web " +
        "3017=event_listener 3030=arepa-cas 3031=eppc 3052=powerchute 3071=csd-mgmt-port 3077=orbix-loc-ssl " +
        "3128=squid-http 3168=poweronnud 3211=avsecuremgmt 3221=xnm-clear-text 3260=iscsi 3261=winshadow " +
        "3268=globalcatLDAP 3269=globalcatLDAPssl 3283=netassistant 3300=ceph 3301=tarantool 3306=mysql 3322=active-net " +
        "3323=active-net 3324=active-net 3325=active-net 3333=dec-notes 3351=btrieve 3367=satvid-datalnk " +
        "3369=satvid-datalnk 3370=satvid-datalnk 3371=satvid-datalnk 3372=msdtc 3389=ms-wbt-server 3390=dsc 3476=nppmp " +
        "3493=nut 3517=802-11-iapp 3527=beserver-msg-q 3551=apcupsd 3580=nati-svrloc 3659=apple-sasl 3689=rendezvous " +
        "3690=svn 3703=adobeserver-3 3737=xpanel 3766=sitewatch-s 3784=bfd-control 3800=pwgpsi 3801=ibm-mgr 3809=apocd " +
        "3814=neto-dcs 3826=wormux 3827=netmpi 3828=neteh 3851=spectraport 3869=ovsam-mgmt 3871=avocent-adsap " +
        "3878=fotogcad 3880=igrs 3889=dandv-tester 3905=mupdate 3914=listcrt-port-2 3918=pktcablemmcops " +
        "3920=exasoftport1 3945=emcads 3971=lanrevserver 3986=mapper-ws_ethd 3995=iss-mgmt-ssl 3998=dnx " +
        "4000=remoteanything 4001=newoak 4002=mlchat-proxy 4003=pxc-splr-ft 4004=pxc-roid 4005=pxc-pin 4006=pxc-spvr " +
        "4045=lockd 4111=xgrid 4125=rww 4126=ddrepl 4129=nuauth 4224=xtell 4242=vrml-multi-use 4279=vrml-multi-use " +
        "4321=rwhois 4343=unicall 4443=pharos 4444=krb524 4445=upnotifyp 4446=n1-fwp 4449=privatewire 4550=gds-adppiw-db " +
        "4567=tram 4662=edonkey 4848=appserv-http 4899=radmin 4900=hfcs 4998=maybe-veritas 5000=upnp 5001=commplex-link " +
        "5002=rfe 5003=filemaker 5004=avt-profile-1 5009=airport-admin 5030=surfpass 5033=jtnetd-server 5050=mmcc " +
        "5051=ida-agent 5054=rlm-admin 5060=sip 5061=sip-tls 5080=onscreen 5087=biotic 5100=admd 5101=admdog 5102=admeng " +
        "5120=barracuda-bbs 5190=aol 5200=targus-getdata 5221=3exmp 5222=xmpp-client 5225=hp-server 5226=hp-status " +
        "5269=xmpp-server 5280=xmpp-bosh 5298=presence 5357=wsdapi 5405=pcduo 5414=statusd 5431=park-agent " +
        "5432=postgresql 5500=hotline 5510=secureidprop 5550=sdadmind 5555=freeciv 5560=isqlplus 5566=westec-connect " +
        "5631=pcanywheredata 5633=beorl 5666=nrpe 5678=rrac 5679=activesync 5718=dpm 5730=unieng 5800=vnc-http " +
        "5801=vnc-http-1 5802=vnc-http-2 5859=wherehoo 5900=vnc 5901=vnc-1 5902=vnc-2 5903=vnc-3 5904=ag-swim " +
        "5906=rpas-c2 5907=dsd 5910=cm 5911=cpdlc 5963=indy 5985=wsman 5986=wsmans 5987=wbem-rmi 5988=wbem-http " +
        "5989=wbem-https 5998=ncd-diag 5999=ncd-conf 6000=X11 6001=X11:1 6002=X11:2 6003=X11:3 6004=X11:4 6005=X11:5 " +
        "6006=X11:6 6007=X11:7 6009=X11:9 6025=x11 6059=X11:59 6100=synchronet-db 6101=backupexec 6106=isdninfo " +
        "6112=dtspc 6123=backup-express 6346=gnutella 6389=clariion-evr01 6502=netop-rc 6510=mcer-port 6543=mythtv " +
        "6547=powerchuteplus 6566=sane-port 6567=esp 6580=parsec-master 6666=irc 6667=irc 6668=irc 6669=irc 6689=tsa " +
        "6699=napster 6788=smc-http 6789=ibm-db2-admin 6881=bittorrent-tracker 6901=jetstream 6969=acmsoda " +
        "7000=afs3-fileserver 7001=afs3-callback 7002=afs3-prserver 7004=afs3-kaserver 7007=afs3-bos 7019=doceri-ctl " +
        "7025=vmsvc-2 7070=realserver 7100=font-service 7200=fodms 7201=dlip 7402=rtps-dd-mt 7443=oracleas-https " +
        "7627=soap-http 7676=imqbrokerd 7741=scriptview 7777=cbt 7778=interwise 7800=asr 7937=nsrexecd 7938=lgtomapper " +
        "7999=irdmi2 8000=http-alt 8001=vcom-tunnel 8002=teradataordbms 8007=ajp12 8008=http 8009=ajp13 8010=xmpp " +
        "8021=ftp-proxy 8022=oa-system 8042=fs-agent 8080=http-proxy 8081=blackice-icecap 8082=blackice-alerts " +
        "8083=us-srv 8084=websnp 8086=d-s-n 8087=simplifymedia 8088=radan-http 8090=opsmessaging 8100=xprint-server " +
        "8181=intermapper 8192=sophos 8193=sophos 8194=sophos 8200=trivnet1 8291=winbox 8292=blp3 8300=tmi 8333=bitcoin " +
        "8383=m2mservices 8400=cvd 8402=abarsd 8443=https-alt 8500=fmtp 8600=asterix 8800=sunwebadmin 8873=dxspider " +
        "8888=sun-answerbook 8899=ospf-lite 9000=cslistener 9001=tor-orport 9002=dynamid 9009=pichat 9010=sdr " +
        "9011=d-star 9040=tor-trans 9050=tor-socks 9080=glrpc 9081=cisco-aqos 9090=zeus-admin 9091=xmltec-xmlmail " +
        "9100=jetdirect 9101=jetdirect 9102=jetdirect 9103=jetdirect 9111=DragonIDSConsole 9200=wap-wsp 9207=wap-vcal-s " +
        "9418=git 9500=ismserver 9535=man 9593=cba8 9594=msgsys 9595=pds 9618=condor 9666=zoomcp 9876=sd 9877=x510 " +
        "9878=kca-service 9898=monkeycom 9900=iua 9929=nping-echo 9998=distinct32 9999=abyss 10000=snet-sensor-mgmt " +
        "10001=scp-config 10002=documentum 10003=documentum_s 10004=emcrmirccd 10009=swdtp-sv 10010=rxapi " +
        "10082=amandaidx 11110=sgi-soap 11111=vce 11967=sysinfo-sp 12000=cce4x 12345=netbus 13722=netbackup " +
        "13782=netbackup 13783=netbackup 14000=scotty-ft 15000=hydap 15002=onep-tls 15660=bex-xr 16000=fmsas " +
        "16001=fmsascon 16080=osxwebadmin 16992=amt-soap-http 16993=amt-soap-https 19283=keysrvr 19315=keyshadow " +
        "20000=dnp 20005=btx 20222=ipulse-ics 27000=flexlm0 30000=ndmps 31337=Elite 32768=filenet-tms 32769=filenet-rpc " +
        "32770=sometimes-rpc3 32771=sometimes-rpc5 32772=sometimes-rpc7 32773=sometimes-rpc9 32774=sometimes-rpc11 " +
        "32775=sometimes-rpc13 32776=sometimes-rpc15 32777=sometimes-rpc17 32778=sometimes-rpc19 32779=sometimes-rpc21 " +
        "32780=sometimes-rpc23 38292=landesk-cba 42510=caerpc 44442=coldfusion-auth 44443=coldfusion-auth " +
        "49400=compaqdiag 50000=ibm-db2 50002=iiimsf 62078=iphone-sync ";

    // nmap-services names for the top-200 UDP ports (514/udp is syslog, 514/tcp shell).
    private const string UdpNames =
        "7=echo 9=discard 13=daytime 17=qotd 19=chargen 21=ftp 22=ssh 23=telnet 37=time 42=nameserver 49=tacacs " +
        "53=domain 67=dhcps 68=dhcpc 69=tftp 80=http 88=kerberos-sec 111=rpcbind 120=cfdptkt 123=ntp 135=msrpc " +
        "136=profile 137=netbios-ns 138=netbios-dgm 139=netbios-ssn 158=pcmail-srv 161=snmp 162=snmptrap 177=xdmcp " +
        "192=osu-nms 199=smux 389=ldap 407=timbuktu 427=svrloc 443=https 445=microsoft-ds 464=kpasswd5 497=retrospect " +
        "500=isakmp 514=syslog 515=printer 517=talk 518=ntalk 520=route 593=http-rpc-epmap 623=asf-rmcp " +
        "626=serialnumberd 631=ipp 664=secure-aux-bus 683=corba-iiop 800=mdbs_daemon 989=ftps-data 990=ftps 996=vsinet " +
        "997=maitrd 998=puparp 999=applix 1008=ufsd 1021=exp1 1022=exp2 1025=blackjack 1026=win-rpc 1028=ms-lsa " +
        "1029=solid-mux 1030=iad1 1031=iad2 1032=iad3 1033=netinfo-local 1034=activesync-notify 1036=nsstp 1038=mtqp " +
        "1039=sbl 1041=danf-ak2 1043=boinc 1044=dcutility 1045=fpitp 1049=td-postman 1068=instl_bootc 1419=timbuktu-srv3 " +
        "1433=ms-sql-s 1434=ms-sql-m 1645=radius 1646=radacct 1701=L2TP 1718=h225gatedisc 1719=h323gatestat 1782=hp-hcip " +
        "1812=radius 1813=radacct 1885=vrtstrapserver 1900=upnp 2000=cisco-sccp 2002=globe 2048=dls-monitor 2049=nfs " +
        "2148=veritas-ucl 2222=msantipiracy 2223=rockwell-csp2 2967=symantec-av 3052=apc-3052 3130=squid-ipc " +
        "3283=netassistant 3389=ms-wbt-server 3456=IISrpc-or-vat 3659=apple-sasl 3703=adobeserver-3 4000=icq 4045=lockd " +
        "4444=krb524 4500=nat-t-ike 4672=rfa 5000=upnp 5001=commplex-link 5060=sip 5093=sentinel-lm 5351=nat-pmp " +
        "5353=zeroconf 5355=llmnr 5500=securid 5632=pcanywherestat 6000=X11 6001=X11:1 6346=gnutella 9200=wap-wsp " +
        "9876=sd 10000=ndmp 10080=amanda 17185=wdbrpc 19283=keysrvr 20031=bakbonenetvault 31337=BackOrifice 32768=omad " +
        "32769=filenet-rpc 32770=sometimes-rpc4 32771=sometimes-rpc6 32772=sometimes-rpc8 32773=sometimes-rpc10 " +
        "39213=sygatefw ";

    private static Dictionary<int, string>? _tcp, _udp;

    private static Dictionary<int, string> Parse(string s)
    {
        var map = new Dictionary<int, string>();
        foreach (var item in s.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = item.IndexOf('=');
            if (eq > 0 && int.TryParse(item.AsSpan(0, eq), out int port)) map[port] = item[(eq + 1)..];
        }
        return map;
    }

    /// <summary>Well-known service name for a port, or "unknown".</summary>
    public static string ServiceName(int port, ScanProto proto = ScanProto.Tcp)
    {
        if (proto == ScanProto.Udp && (_udp ??= Parse(UdpNames)).TryGetValue(port, out var u)) return u;
        if (Curated.TryGetValue(port, out var c)) return c;
        return (_tcp ??= Parse(TcpNames)).TryGetValue(port, out var t) ? t : "unknown";
    }

    // nmap's --top-ports order: open frequency, highest first.
    private static readonly int[] TopTcp =
    {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
        1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1049, 1053,
        1054, 1056, 1064, 1065, 2967, 3703, 17, 808, 3689, 1031, 1044, 1071, 5901, 100, 9102, 1039, 2869, 4001, 5120, 8010,
        9000, 2105, 636, 1038, 2601, 1, 7000, 1066, 1069, 625, 311, 280, 254, 4000, 1761, 5003, 2002, 1998, 2005, 1032,
        1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401, 902, 4045, 787, 7937, 1058, 2383, 32771, 1033, 1040, 1059, 50000, 5555,
        10001, 1494, 3, 593, 2301, 3268, 7938, 1022, 1234, 1035, 1036, 1037, 1074, 8002, 9001, 464, 497, 1935, 2003, 6666,
        6543, 24, 1352, 3269, 1111, 407, 500, 20, 2006, 1034, 1218, 3260, 15000, 4444, 264, 33, 2004, 1042, 42510, 999,
        3052, 1023, 222, 1068, 888, 7100, 563, 1717, 992, 2008, 32770, 7001, 32772, 2007, 8082, 5550, 512, 1043, 2009, 5801,
        1700, 2701, 7019, 50001, 4662, 2065, 42, 2010, 161, 2602, 3333, 9535, 5100, 2604, 4002, 5002, 1047, 1051, 1052, 1055,
        1060, 1062, 1311, 2702, 3283, 4443, 5225, 5226, 6059, 6789, 8089, 8192, 8193, 8194, 8651, 8652, 8701, 9415, 9593, 9594,
        9595, 16992, 16993, 20828, 23502, 32769, 33354, 35500, 52869, 55555, 55600, 64623, 64680, 65000, 65389, 1067, 13782, 366, 5902, 9050,
        85, 1002, 5500, 1863, 1864, 5431, 8085, 10243, 45100, 49999, 51103, 49, 90, 6667, 1503, 6881, 27000, 340, 1500, 8021,
        2222, 5566, 8088, 8899, 9071, 1501, 5102, 6005, 9101, 9876, 32773, 32774, 163, 5679, 146, 648, 1666, 901, 83, 3476,
        5004, 5214, 8001, 8083, 8084, 9207, 14238, 30, 912, 12345, 2030, 2605, 6, 541, 4, 1248, 3005, 8007, 306, 880,
        2500, 1086, 1088, 1097, 2525, 4242, 8291, 9009, 52822, 900, 6101, 2809, 7200, 211, 800, 987, 1083, 12000, 32775, 705,
        711, 20005, 6969, 13783, 1045, 1046, 1057, 1061, 1063, 1070, 1072, 1073, 1075, 1077, 1078, 1079, 1081, 1082, 1085, 1093,
        1094, 1096, 1098, 1099, 1100, 1104, 1106, 1107, 1108, 1148, 1169, 1272, 1310, 1687, 1718, 1783, 1840, 1947, 2100, 2119,
        2135, 2144, 2160, 2190, 2260, 2381, 2399, 2492, 2607, 2718, 2811, 2875, 3017, 3031, 3071, 3211, 3300, 3301, 3323, 3325,
        3351, 3367, 3404, 3551, 3580, 3659, 3766, 3784, 3801, 3827, 3998, 4003, 4126, 4129, 4449, 5030, 5222, 5269, 5414, 5633,
        5718, 5810, 5825, 5877, 5910, 5911, 5925, 5959, 5960, 5961, 5962, 5985, 5986, 5987, 5988, 5989, 6123, 6129, 6156, 6389,
        6580, 6788, 6901, 7106, 7625, 7627, 7741, 7777, 7778, 7911, 8086, 8087, 8181, 8222, 8333, 8400, 8402, 8600, 8649, 8873,
        8994, 9002, 9010, 9011, 9080, 9220, 9290, 9485, 9500, 9502, 9503, 9618, 9900, 9968, 10002, 10012, 10024, 10025, 10566, 10616,
        10617, 10621, 10626, 10628, 10629, 11110, 11967, 13456, 14000, 14442, 15002, 15003, 15660, 16001, 16016, 16018, 17988, 19101, 19801, 19842,
        20000, 20031, 20221, 20222, 21571, 22939, 24800, 25734, 27715, 28201, 30000, 30718, 31038, 32781, 32782, 33899, 34571, 34572, 34573, 40193,
        48080, 49158, 49159, 49160, 50003, 50006, 50800, 57294, 58080, 60020, 63331, 65129, 89, 691, 212, 1001, 1999, 2020, 32776, 2998,
        6003, 7002, 50002, 32, 898, 2033, 3372, 5510, 99, 425, 749, 5903, 43, 458, 5405, 6106, 6502, 7007, 13722, 1087,
        1089, 1124, 1152, 1183, 1186, 1247, 1296, 1334, 1580, 1782, 2126, 2179, 2191, 2251, 2522, 3011, 3030, 3077, 3261, 3369,
        3370, 3371, 3493, 3546, 3737, 3828, 3851, 3871, 3880, 3918, 3995, 4006, 4111, 4446, 5054, 5200, 5280, 5298, 5822, 5859,
        5904, 5915, 5922, 5963, 7103, 7402, 7435, 7443, 7512, 8011, 8090, 8100, 8180, 8254, 8500, 8654, 9091, 9110, 9666, 9877,
        9943, 9944, 9998, 10004, 10778, 15742, 16012, 18988, 19283, 19315, 19780, 24444, 27352, 27353, 27355, 32784, 49163, 49165, 49175, 50389,
        50636, 51493, 55055, 56738, 61532, 61900, 62078, 1021, 9040, 32777, 32779, 616, 666, 700, 2021, 32778, 84, 545, 1112, 1524,
        2040, 4321, 5802, 38292, 49400, 1084, 1600, 2048, 2111, 3006, 32780, 2638, 6547, 6699, 9111, 16080, 555, 667, 720, 801,
        1443, 1533, 2034, 2106, 5560, 6007, 1090, 1091, 1114, 1117, 1119, 1122, 1131, 1138, 1151, 1175, 1199, 1201, 1271, 1862,
        2323, 2393, 2394, 2608, 2725, 2909, 3003, 3168, 3221, 3322, 3324, 3390, 3517, 3527, 3800, 3809, 3814, 3826, 3869, 3878,
        3889, 3905, 3914, 3920, 3945, 3971, 4004, 4005, 4279, 4445, 4550, 4567, 4848, 4900, 5033, 5061, 5080, 5087, 5221, 5440,
        5544, 5678, 5730, 5811, 5815, 5850, 5862, 5906, 5907, 5950, 5952, 6025, 6100, 6510, 6565, 6566, 6567, 6689, 6692, 6779,
        6792, 6839, 7025, 7496, 7676, 7800, 7920, 7921, 7999, 8022, 8042, 8045, 8093, 8099, 8200, 8290, 8292, 8300, 8383, 8800,
        9003, 9081, 9099, 9200, 9418, 9575, 9878, 9898, 9917, 10003, 10009, 10180, 10215, 11111, 12174, 12265, 14441, 15004, 16000, 16113,
        17877, 18040, 18101, 19350, 25735, 26214, 27356, 30951, 32783, 32785, 40911, 41511, 44176, 44501, 49161, 49167, 49176, 50300, 50500, 52673,
        52848, 54045, 54328, 55056, 56737, 57797, 60443, 70, 417, 617, 714, 722, 777, 981, 1009, 2022, 4224, 4998, 6346, 301,
        524, 668, 765, 1076, 2041, 5999, 10082, 259, 416, 1007, 1417, 1434, 1984, 2038, 2068, 4343, 6009, 7004, 44443, 109,
        687, 726, 911, 1010, 1461, 2035, 2046, 4125, 6006, 7201, 9103, 125, 481, 683, 903, 1011, 1455, 2013, 2043, 2047,
        6668, 6669, 256, 406, 783, 843, 2042, 2045, 5998, 9929, 31337, 44442, 1092, 1095, 1102, 1105, 1113, 1121, 1123, 1126,
        1130, 1132, 1137, 1141, 1145, 1147, 1149, 1154, 1163, 1164, 1165, 1166, 1174, 1185, 1187, 1192, 1198, 1213, 1216, 1217,
        1233, 1236, 1244, 1259, 1277, 1287, 1300, 1301, 1309, 1322, 1328, 1556, 1583, 1594, 1641, 1658, 1688, 1719, 1721, 1805,
        1812, 1839, 1875, 1914, 1971, 1972, 1974, 2099, 2170, 2196, 2200, 2288, 2366, 2382, 2557, 2710, 2800, 2910, 2920, 2968,
    };

    private static readonly int[] TopUdp =
    {
        631, 161, 137, 123, 138, 1434, 445, 135, 67, 53, 139, 500, 68, 520, 1900, 4500, 514, 49152, 162, 69,
        5353, 111, 49154, 1701, 998, 996, 997, 999, 3283, 49153, 1812, 136, 2222, 2049, 32768, 5060, 1025, 1433, 3456, 80,
        20031, 1026, 7, 1646, 1645, 593, 518, 2048, 626, 1027, 177, 1719, 427, 497, 4444, 1023, 65024, 19, 9, 49193,
        1029, 49, 88, 1028, 17185, 1718, 49186, 2000, 31337, 49192, 49201, 515, 2223, 443, 49181, 1813, 120, 158, 49200, 3703,
        32815, 17, 5000, 32771, 33281, 1030, 623, 1022, 32769, 5632, 10000, 49156, 49182, 49191, 49194, 9200, 30718, 49185, 49188, 49190,
        49211, 5001, 5355, 32770, 34555, 34861, 37444, 1032, 3130, 4045, 1031, 49158, 49196, 37, 2967, 4000, 989, 3659, 4672, 34862,
        23, 49162, 49187, 49189, 49195, 2148, 41524, 10080, 32772, 407, 42, 33354, 1034, 49180, 49199, 1001, 3389, 6346, 21, 13,
        517, 1068, 990, 1041, 1045, 1782, 6001, 19283, 49171, 49179, 49184, 49202, 49205, 49208, 49209, 49210, 9876, 39213, 800, 389,
        464, 1036, 1038, 1039, 1419, 192, 199, 44968, 1008, 49159, 49166, 1024, 1033, 19682, 22986, 22, 2002, 664, 1021, 11487,
        49163, 49165, 49168, 49172, 58002, 1043, 683, 1019, 1044, 1049, 1885, 3052, 5093, 5351, 6000, 7938, 5500, 16680, 27892, 32773,
    };

    /// <summary>The <paramref name="n"/> most-common ports of a protocol (nmap --top-ports N).</summary>
    public static List<int> TopPorts(int n, ScanProto proto = ScanProto.Tcp)
    {
        int[] src = proto == ScanProto.Udp ? TopUdp : TopTcp;
        return new List<int>(src.AsSpan(0, Math.Clamp(n, 0, src.Length)).ToArray());
    }

    // -T0..-T5. MaxRetries is the base number of retransmissions for a silent port; RetryCap is how far that may
    // grow on a host that drops probes (nmap's adaptive max-retries: a port that only answered on its 3rd try lets
    // the other silent ports of that host have as many). UdpRecheck caps the paced re-check of silent UDP ports on
    // a host that rate-limits its ICMP errors (see ScanEngine).
    public static readonly TimingTemplate[] Timings =
    {
        new(0, "T0 · Paranoid",   1,   6000, 2, 10, 1000),
        new(1, "T1 · Sneaky",     3,   5000, 2, 10, 1000),
        new(2, "T2 · Polite",     10,  3000, 2, 10, 1000),
        new(3, "T3 · Normal",     64,  1500, 1, 10, 1000),
        new(4, "T4 · Aggressive", 200, 800,  1, 6,  300),
        new(5, "T5 · Insane",     400, 400,  0, 2,  100),
    };

    public static TimingTemplate Timing(int level)
    {
        foreach (var t in Timings) if (t.Level == level) return t;
        return Timings[3];
    }
}

public sealed record TimingTemplate(int Level, string Label, int Concurrency, int TimeoutMs, int MaxRetries,
                                    int RetryCap, int UdpRecheck)
{
    public override string ToString() => Label;
}
