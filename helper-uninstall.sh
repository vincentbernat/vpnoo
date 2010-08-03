# Uninstall helper tool

sudo launchctl unload -w /Library/LaunchDaemons/net.orangeportails.vpnoo.plist
sudo rm /Library/LaunchDaemons/net.orangeportails.vpnoo.plist
sudo rm /Library/PrivilegedHelperTools/net.orangeportails.vpnoo
sudo rm /var/run/net.orangeportails.vpnoo.socket
