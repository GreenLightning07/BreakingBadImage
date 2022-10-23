#!/bin/bash

total_found=0
total_percent=""
total_pen=0

pam_configed=false
encrypt_set=false

score_report="/home/heisenburg/Desktop/ScoreReport.html"

function update-found
{
	#updates vuln found counts in score report
	total_percent=$(awk -vn=$total_found 'BEGIN{print(n*2.00)}')
	echo $total_percent
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/50<\/h3>/g" $score_report
        sed -i "s/id=\"total_percent\".*/id=\"total_percent\">$total_percent%<\/h3>/g" $score_report
	echo $total_pen
	if ( $total_pen > 0 ); then
		sed -i "s/id=\"p0\"style=\"display:block\"/id=\"p0\"style=\"display:none\"/g" $score_report
	else if ( $total_pen == 0 ); then
		sed -i "s/id=\"p0\"style=\"display:none\"/id=\"p0\"style=\"display:block\"/g" $score_report
	fi
}

function show-vuln()
{
	#allows vuln name to be seen in score report
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found+=$4))
	#replaces placeholder name with actual vuln name (obfuscation)
	sed -i "s/$2/$3/g" $score_report
	notify-send "Congrats!" "You Gained Points"
	update-found
}

function hide-vuln()
{
	#hides vuln name from score report
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
	((total_found-=$4))
	#replaces placeholder name (people should keep their own notes on the points they've gained)
	sed -i "s/$2/$3/g" $score_report
	notify-send "Uh Oh!" "You Lost Points"
	update-found
}

function penalty()
{
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found-=$4))
	((total_pen+=1))
		
        #replaces placeholder name (people should keep their own notes on the points they've gained)
        sed -i "s/$2/$3/g" $score_report
        notify-send "Uh Oh!" "You Lost Points"
        update-found

}

function remove-penalty()
{
	#allows vuln name to be seen in score report
        sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
        ((total_found+=$4))
	((total_pen-1))
	
        #replaces placeholder name with actual vuln name (obfuscation)
        sed -i "s/$2/$3/g" $score_report
        notify-send "Congrats!" "You Gained Points"
        update-found

}

function notify-send()
{
    #Detect the name of the display in use
    local display=":$(ls /tmp/.X11-unix/* | sed 's#/tmp/.X11-unix/X##' | head -n 1)"

    #Detect the user using such display
    local user=$(who | grep '('$display')' | awk '{print $1}' | head -n 1)

    #Detect the id of the user
    local uid=$(id -u $user)

    sudo -u $user DISPLAY=$display DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus notify-send "$@"
}

function check()
{
	if ( eval $1 ); then
		if ( cat $score_report | grep "id=\"$2\"" | grep "display:none" ); then
			show-vuln "$2" "Vuln$2;" "$3" "$4"
		fi
	elif ( cat $score_report | grep "id=\"$2\"" | grep "display:block" ); then
		hide-vuln "$2" "$3" "Vuln$2;" "$4"
	fi
}

function check-pen()
{
	if ( eval $1 ); then
		if ( cat $score_report | grep "id=\"$2\"" | grep "display:none" ); then
			penalty "$2" "$2;" "$3" "$4"
		fi
	elif ( cat $score_report | grep "id=\"$2\"" | grep "display:block" ); then
		remove-penalty "$2" "$3" "$2;" "$4"
	fi
}

update-found

while true
do
	#penalties
	check-pen '! netstat -tulpn | grep apache2 | cut -d " " -f16 | grep ":80"$' 'p1' 'Apache2 is Disabled or Running on Wrong Port -10' '10'
	check-pen '! netstat -tulpn | grep mysql | cut -d " " -f16 | grep ":3306"$' 'p2' 'MySQL is Disabled or Running on Wrong Port -10' '10'
	check-pen '! cat /etc/group | grep "sudo:x:" | grep "heisenburg"' 'p3' 'heisenburg is Not an Admin -5' '5'
	check-pen '! cat /etc/group | grep "sudo:x:" | grep "jesse"' 'p4' 'jesse is Not an Admin -5' '5'
	check-pen '! cat /etc/group | grep "sudo:x:" | grep "saul"' 'p5' 'saul is Not an Admin -5' '5'
	check-pen '! cat /etc/group | grep "sudo:x:" | grep "gus"' 'p6' 'gus is Not an Admin -5' '5'
	check-pen '! cat /etc/passwd | grep "heisenburg"' 'p7' 'User heisenburg was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "jesse"' 'p8' 'User jesse was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "saul"' 'p9' 'User saul was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "gus"' 'p10' 'User gus was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "mike"' 'p11' 'User mike was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "badger"' 'p12' 'User badger was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "skinnypete"' 'p13' 'User skinnypete was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "skylar"' 'p14' 'User skylar was Removed -3' '3'
	check-pen '! cat /etc/passwd | grep "todd"' 'p15' 'User todd was Removed -3' '3'
	
	#forensics 5pts each
	check 'cat /home/heisenburg/Desktop/Forensics1 | grep "41943040"' '1' 'Forensics 1 Correct +5' '5'
	check 'cat /home/heisenburg/Desktop/Forensics2 | grep "2.4.41"' '2' 'Forensics 2 Correct +5' '5'
	check 'cat /home/heisenburg/Desktop/Forensics3 | grep "OrderArchive"' '3' 'Forensics 3 Correct +5' '5'
	
	#linux vulns
	check '! cat /etc/passwd | grep "gale"' '4' 'Hidden User gale is Removed +1' '1'
	check '! cat /etc/passwd | grep "hank" && ! cat /etc/group | grep "sudo" | grep "hank"' '5' 'Unauthorized Admin hank Removed +1' '1'
	check 'cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Download-Upgradeable-Packages" | grep "1" && cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Unattended-Upgrade" | grep "1"' '6' 'Automatically Download and Install Security Updates +1' '1'
	check 'service auditd status | grep "running"' '7' 'Audit Policies Enabled +5' '5'
	check 'cat /etc/pam.d/common-password | grep "pam_unix.so" | grep -iF "sha256" || cat /etc/pam.d/common-password | grep "pam_unix.so" | grep -iF "sha512"' '8' 'Correct Encrypt Method Set +2' '2'
	check 'cat /etc/pam.d/common-password | grep "cracklib.so" | grep "ucredit=-1" | grep "dcredit=-1" | grep "ocredit=-1" | grep "lcredit=-1"' '9' 'Enforce Complex Passwords +2' '2'
	check '! cat /etc/sudoers.d/README | grep ^"%sudo" | grep "NOPASSWD"' '10' 'Removed Nopasswd Rights +3' '3'
	check 'ufw status verbose | grep "Logging" | grep "high"' '11' 'UFW Logging High +2' '2'
	check 'cat /etc/sysctl.conf | grep "kernel.randomize_va_space" | grep "1"' '12' 'ASLR is Enabled +3' '3'
	check 'cat /etc/security/limits.conf | grep "*" | grep "hard" | grep "nproc" | grep "2048"' '13' 'Forkbomb Protection Enabled +3' '3'
	check '! ls /etc/fonts/conf.d | grep "abcd.py"' '14' 'Malicious Python Script Removed +4' '4'
	check 'ls -al /etc/passwd | cut -d " " -f 3 | grep "root"' '15' 'Correct Owner Set on \/etc\/passwd +2' '2'
	check '! dpkg -l | grep "hashdeep"' '16' 'HashDeep is Removed +4' '4'
	check '! dpkg -l | grep "netcat"' '17' 'Netcat is Removed +1' '1'
	check '! service nginx status | grep "running"' '18' 'Service NGINX is Stopped or Removed +1' '1'	
	#wait 10 seconds
	sleep 10
done
