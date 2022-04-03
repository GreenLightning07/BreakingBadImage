#!/bin/bash

total_found=0
linux_found=0
apache_found=0
mysql_found=0
vsftp_found=0
openvpn_found=0

score_report="/home/po/Desktop/ScoreReport.html"

function update-found
{
	total_found=$((linux_found + apache_found + mysql_found + vsftp_found + openvpn_found))
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/200<\/center><\/h3>/g" $score_report
        sed -i "s/id=\"linux_found\".*/id=\"linux_found\">LINUX ($linux_found\/30)<\/button>/g" $score_report

	echo $total_found
}

function show-vuln()
{
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	(($2++))
	notify-send "Congrats!" "You Gained Points"
	update-found
}

function hide-vuln()
{
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
	(($2--))
	notify-send "Uh Oh!" "You Lost Points"
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

update-found

while true
do
	if ( ! cat /etc/passwd | grep "kai" ); then
		if ( cat $score_report | grep 'id="l1"' | grep "display:none" ); then
			show-vuln "l1" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l1"' | grep "display:block" ); then
		hide-vuln "l1" "linux_found"
	fi

	if ( ! cat /etc/passwd | grep "tailung" ); then
		if ( cat $score_report | grep 'id="l2"' | grep "display:none" ); then
			show-vuln "l2" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l2"' | grep "display:block" ); then
		hide-vuln "l2" "linux_found"
	fi

	if ( ! cat /etc/group | grep "sudo" | grep "tigress" ); then
		if ( cat $score_report | grep 'id="l3"' | grep "display:none" ); then
			show-vuln "l3" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l3"' | grep "display:block" ); then
		hide-vuln "l3" "linux_found"
	fi

	if ( cat /etc/group | grep "sudo" | grep "po" ); then
		if ( cat $score_report | grep 'id="l4"' | grep "display:none" ); then
			show-vuln "l4" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l4"' | grep "display:block" ); then
		hide-vuln "l4" "linux_found"
	fi

	if ( ! cat /etc/shadow | grep "po" | grep "$1$RNW/raIJ$yQAKMclO2hNgJIz4flS2z0" ); then
		if ( cat $score_report | grep 'id="l5"' | grep "display:none" ); then
			show-vuln "l5" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l5"' | grep "display:block" ); then
		hide-vuln "l5" "linux_found"
	fi

	if ( ls -al /etc | grep -v gshadow | grep shadow$ | grep ^"-rw-------" || ls -al /etc | grep -v gshadow | grep shadow$ | grep ^"-rw-r-----" ); then
		if ( cat $score_report | grep 'id="l6"' | grep "display:none" ); then
			show-vuln "l6" "linux_found"
		fi
	elif ( cat $score_report | grep 'id="l6"' | grep "display:block" ); then
		hide-vuln "l6" "linux_found"
	fi

sleep 10
done
