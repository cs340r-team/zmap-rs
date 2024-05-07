ip=$(ip route show | grep default | awk '{print $3}')
mac=$(arp -n | grep $ip | awk '{print $3}')
echo "Gateway IP: $ip"
echo "Gateway MAC: $mac"
