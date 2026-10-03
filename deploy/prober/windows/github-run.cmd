@echo off
rem GitHub preferred-IP report run for Windows probers (see install.ps1). Mirrors echprobe-github.service.
"%~dp0echprobe.exe" -doh https://edge.1molchuan.top/dns-query -github https://raw.hellogithub.com/hosts,https://gitlab.com/ineo6/hosts/-/raw/master/next-hosts,%~dp0github-extra-hosts ^
 -github-hosts github.com,gist.github.com,api.github.com,codeload.github.com,raw.githubusercontent.com,objects.githubusercontent.com,avatars.githubusercontent.com,camo.githubusercontent.com,media.githubusercontent.com,user-images.githubusercontent.com,private-user-images.githubusercontent.com,cloud.githubusercontent.com,desktop.githubusercontent.com,favicons.githubusercontent.com,github.githubassets.com,release-assets.githubusercontent.com,gist.githubusercontent.com ^
 -rounds 3 -parallel 4 -timeout 6s ^
 -github-report https://edge.1molchuan.top/admin/github -report-source school -github-ttl 4200 ^
 -admin-token-file "%~dp0token" -log "%~dp0github.log"
