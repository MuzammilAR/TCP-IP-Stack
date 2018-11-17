default:
	sudo iptables -F
	sudo ethtool --offload eth0 rx off tx off
	sudo ethtool -K eth0 gso off
	sudo ethtool -K eth0 gro off
	rm -f rawhttpget
	cp rawhttpget.py rawhttpget
	chmod +x rawhttpget
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
clean:
	rm -f rawhttpget
