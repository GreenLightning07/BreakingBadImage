#!/bin/bash

total_found=0
linux_found=0
apache_found=0
mysql_found=0
vsftp_found=0
openvpn_found=0

pam_configed=false
encrypt_set=false

score_report="/home/po/Desktop/ScoreReport.html"

function update-found
{
	#updates vuln found counts in score report
	total_found=$((linux_found + apache_found + mysql_found + vsftp_found + openvpn_found))
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/200<\/center><\/h3>/g" $score_report
        sed -i "s/id=\"linux_found\".*/id=\"linux_found\">LINUX ($linux_found\/30)<\/button>/g" $score_report
}

function show-vuln()
{
	#allows vuln name to be seen in score report
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	(($2++))
	#replaces placeholder name with actual vuln name (obfuscation)
	sed -i "s/$3/$4/g" $score_report
	notify-send "Congrats!" "You Gained Points"
	update-found
}

function hide-vuln()
{
	#hides vuln name from score report
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
	(($2--))
	#replaces placeholder name (people should keep their own notes on the points they've gained)
	sed -i "s/$3/$4/g" $score_report
	notify-send "Uh Oh!" "You Lost Points"
	update-found
}

function penalty()
{
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found-=$4))
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
        #replaces placeholder name with actual vuln name (obfuscation)
        sed -i "s/$2/$3/g" $score_report
        notify-send "Congrats!" "You Gained Points"
        update-found

}

function check()
{
	if ( eval $1 ); then
		if ( cat $score_report | grep "id=\"$2\"" | grep "display:none" ); then
			show-vuln "$2" $3 "Vuln$2;" "$4" "$5"
		fi
	elif ( cat $score_report | grep "id=\"$2\"" | grep "display:block" ); then
		hide-vuln "$2" "$3" "$4" "Vuln$2;" "$5" 
	fi
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
	if ( cat /etc/pam.d/common-password | grep "pam_unix.so" | grep "remember=5" | grep "minlen=8" ); then
		if ( cat /etc/pam.d/common-password | grep "pam_cracklib.so" | grep "ucredit=-1" | grep "lcredit=-1" | grep "dcredit=-1" | grep "ocredit=-1" ); then
			pam_configed=true
		fi
	else
		pam_configed=false
	fi

	check "! cat /etc/passwd | grep kai" "l1" "linux_found" "Removed unauthorized user Kai" "1;"  "1"	

sleep 10
done
