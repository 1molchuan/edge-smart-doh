@echo off
rem Site check for Windows probers (see install-sitecheck.ps1). Mirrors echprobe-sitecheck.service.
"%~dp0echprobe.exe" -doh https://edge.1molchuan.top/dns-query ^
 -sitecheck https://linux.do/srv/status,https://linux.do/about.json ^
 -site-report https://edge.1molchuan.top/admin/site -site-ttl 2700 -report-source school ^
 -history "%~dp0history.json" -sample-cidrs 104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,162.158.0.0/15,188.114.96.0/20,190.93.240.0/20 -sample-n 30 ^
 -timeout 10s -parallel 8 -budget 8m -admin-token-file "%~dp0token" -log "%~dp0sitecheck.log"
