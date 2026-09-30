@echo off
rem Preferred-IP report run for Windows probers (see install.ps1). Mirrors echprobe-report.service;
rem settings come from env.example. Set -report-source to this prober's own name.
"%~dp0echprobe.exe" -doh https://edge.1molchuan.top/dns-query -resolve-doh https://223.5.5.5/dns-query ^
 -rank cf.090227.xyz,cmcc.090227.xyz,cu.090227.xyz,ct.090227.xyz,skk.moe,yx.cloudflare.182682.xyz,cfip.xxxxxxxx.tk,www.visa.com.hk,openai.com,cloudflare-ip.mofashi.ltd,saas.sin.fan,cf.877774.xyz,cf.0sm.com,cf.130519.xyz,ip.164746.xyz,www.visa.com.sg,www.visa.com.tw,icook.tw,icook.hk,japan.com,www.digitalocean.com,www.shopify.com,www.udemy.com,www.hugedomains.com,www.ipget.net,www.gov.ua ^
 -rank-target x.com,linux.do -rounds 12 -timeout 6s ^
 -per-domain 12 -parallel 8 -sample-cidrs 104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,162.158.0.0/15,188.114.96.0/20,190.93.240.0/20 -sample-n 40 ^
 -report https://edge.1molchuan.top/admin/preferred -report-source school -report-top 48 -report-min 2 -report-ttl 4200 ^
 -history "%~dp0history.json" -admin-token-file "%~dp0token" -log "%~dp0echprobe.log" -budget 20m
