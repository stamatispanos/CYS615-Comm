#! /bin/bash

# Initialiazation


mainmenu () {

	printf "Press 1 to 'Allow unrestricted access to loopback interface (input/output)'\n"
	printf "Press 2 to 'Protect your system from SYN flood with a limiton the number of packets'\n"
	printf "Press 3 to 'Protect from ICMP flood attack with a limit on the number of packets of your choice'\n"
	printf "Press 4 to 'Reject packets that pretend to be originating from your own IP'\n"
	printf "Press 5 to 'Reject packets that pretend to be coming from any class C private network'\n"
	printf "Press 6 to 'Reject packets that pretend to be originating from your loopback address'\n"
	printf "Press 7 to 'Allow only access to google.com and the European University from your browser. Log\nany other movement of packets as well as any unauthorized access to web pages'\n"
	printf "Press 8 to 'Allow your pc to send ICMP packets'\n"
	printf "Press 9 to 'Allow access to the mail server (smtp)'\n"
	printf "Press 0 to run all previous commands\n"
	printf "Press x to exit\n"

	read -n 1 -p "input Selection:" mainmenuinput
	printf "\n"

	if [ "$mainmenuinput" = "1" ]; then 
		iptables -A INPUT -i lo -j ACCEPT
		iptables -A OUTPUT -o lo -j ACCEPT
		clear 
		printf "Policy 1 added succesfully!\n\n"
		
		elif [ "$mainmenuinput" = "2" ]; then
			iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN
			clear 
			printf "Policy 2 added succesfully!\n\n"
		
		elif [ "$mainmenuinput" = "3" ]; then
			# Limit the incoming ICMP ping requests and log
			iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
			iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
			iptables -A INPUT -p icmp -j DROP
			iptables -A OUTPUT -p icmp -j ACCEPT
			clear 
			printf "Policy 3 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "4" ]; then
		       iptables -t filter -A INPUT -i eth1 -s 10.10.1.48 -d 10.10.1.48  -j REJECT
		       clear 
			printf "Policy 4 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "5" ]; then

		       iptables -t filter -A INPUT -i eth1 -p tcp -s 192.168.0.0/16  -j REJECT
		       iptables -t filter -A INPUT -i eth1 -p tcp -s 169.254.0.0/16  -j REJECT
		       clear 
			printf "Policy 5 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "6" ]; then
			iptables -A INPUT -i lo -j ACCEPT
		       iptables -t filter -A INPUT -i eth1 -p tcp -s 127.0.0.0/8  -j REJECT
		       clear 
			printf "Policy 6 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "7" ]; then
		       iptables -I INPUT 1 -i lo -j ACCEPT
			iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

			# to find the google.com cidr
			# host -t a www.google.com
			# whois X.X.X.X | grep CIDR
			#
			iptables -A OUTPUT -p tcp -d 172.217.0.0/16 --dport 80 -j ACCEPT
			iptables -A OUTPUT -p tcp -d 172.217.0.0/16 --dport 443 -j ACCEPT

			iptables -A OUTPUT -p tcp -d euc.ac.cy --dport 80 -j ACCEPT
			iptables -A OUTPUT -p tcp -d euc.ac.cy --dport 443 -j ACCEPT

			iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

			iptables -A OUTPUT -p tcp --dport 80 -j LOG --log-prefix UnauthorizedAccess
			iptables -A OUTPUT -p tcp --dport 80 -j DROP

			iptables -A OUTPUT -p tcp --dport 443 -j LOG --log-prefix UnauthorizedAccess
			iptables -A OUTPUT -p tcp --dport 443 -j DROP

			clear 
			printf "Policy 7 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "8" ]; then
		       iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
			iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
			clear 
			printf "Policy 8 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "9" ]; then
		       # Allow smtp
			iptables -A OUTPUT -p tcp --sport 25 -j ACCEPT
			iptables -A OUTPUT -p tcp --sport 587 -j ACCEPT

			# Allow responds 
			iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
			clear 
			printf "Policy 9 added succesfully!\n\n"
			
		elif [ "$mainmenuinput" = "0" ]; then
		       # policy 1 begin
		       	iptables -A INPUT -i lo -j ACCEPT
			iptables -A OUTPUT -o lo -j ACCEPT
		       # policy 1 end
		       
		       # policy 2 begin
		       iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN
		       # policy 2 end
		       
       		       # policy 3 begin
			# Limit the incoming ICMP ping requests and log
			iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
			iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
			iptables -A INPUT -p icmp -j DROP
			iptables -A OUTPUT -p icmp -j ACCEPT
		       # policy 3 end
		       
			# policy 4 begin
		       iptables -t filter -A INPUT -i eth1 -s 10.10.1.48 -d 10.10.1.48  -j REJECT
		       # policy 4 end
		       
			# policy 5 begin
		       iptables -t filter -A INPUT -i eth1 -p tcp -s 192.168.0.0/16  -j REJECT
		       iptables -t filter -A INPUT -i eth1 -p tcp -s 169.254.0.0/16  -j REJECT
		       # policy 5 end
		       
			# policy 6 begin
			iptables -A INPUT -i lo -j ACCEPT
		       iptables -t filter -A INPUT -i eth1 -p tcp -s 127.0.0.0/8  -j REJECT
		       # policy 6 end
			# policy 7 begin
		        iptables -I INPUT 1 -i lo -j ACCEPT
			iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

			# to find the google.com cidr
			# host -t a www.google.com
			# whois X.X.X.X | grep CIDR
			#
			iptables -A OUTPUT -p tcp -d 172.217.0.0/16 --dport 80 -j ACCEPT
			iptables -A OUTPUT -p tcp -d 172.217.0.0/16 --dport 443 -j ACCEPT

			iptables -A OUTPUT -p tcp -d euc.ac.cy --dport 80 -j ACCEPT
			iptables -A OUTPUT -p tcp -d euc.ac.cy --dport 443 -j ACCEPT

			iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

			iptables -A OUTPUT -p tcp --dport 80 -j LOG --log-prefix UnauthorizedAccess
			iptables -A OUTPUT -p tcp --dport 80 -j DROP

			iptables -A OUTPUT -p tcp --dport 443 -j LOG --log-prefix UnauthorizedAccess
			iptables -A OUTPUT -p tcp --dport 443 -j DROP

		       # policy 7 end
		       
			# policy 8 begin
		        iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
			iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
		       # policy 8 end
		       
			# policy 9 begin
		       # Allow smtp
			iptables -A OUTPUT -p tcp --sport 25 -j ACCEPT
			iptables -A OUTPUT -p tcp --sport 587 -j ACCEPT

			# Allow responds 
			iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
		       # policy 9 end
			 clear 
			printf "All Policies applied succesfully!\n\n"
		elif [ "$mainmenuinput" = "x" ]; then
			printf "Quit script."
		       exit 0
		elif [ "$mainmenuinput" = "X" ]; then
			printf "Quit script."
		       exit 0
		else 
			printf "You have entered an invalid selection!\n"
			printf "Please try again!\n"
			printf "\n"
			printf "Press any key to continue...\n"
			read -n 1
			clear
			mainmenu


	fi
}
while : 
do 
	mainmenu
	sleep 1;
done
