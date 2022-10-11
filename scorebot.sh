#!/bin/bash

total_found=0
total_percent=""

pam_configed=false
encrypt_set=false

score_report="/home/heisenburg/Desktop/ScoreReport.html"

function update-found
{
	#updates vuln found counts in score report
	total_percent=$(awk -vn=$total_found 'BEGIN{print(n*2.86)}')
	echo $total_percent
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/35<\/h3>/g" $score_report
        sed -i "s/id=\"total_percent\".*/id=\"total_percent\">$total_percent%<\/h3>/g" $score_report
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

update-found

while true
do
	#forensics 5pts each
	check 'cat /home/heisenburg/Desktop/Forensics1 | grep "41943040"' '1' 'Forensics 1 Correct +5' '5'
	check 'cat /home/heisenburg/Desktop/Forensics2 | grep "2.4.41"' '2' 'Forensics 2 Correct +5' '5'
	check 'cat /home/heisenburg/Desktop/Forensics3 | grep "OrderArchive"' '3' 'Forensics 3 Correct +5' '5'
	
	#linux vulns
	check '! cat /etc/passwd | grep "gale"' '4' 'Hidden User gale is Removed +1' '1'
	check '! cat /etc/passwd | grep "hank" && ! cat /etc/group | grep "sudo" | grep "hank"' '5' 'Unauthorized Admin hank Removed +1' '1'
	check 'cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Download-Upgradeable-Packages" | grep "1" && cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Unattended-Upgrade" | grep "1"' '6' 'Automatically Download and Install Security Updates +1' '1'
	check 'service auditd status | grep "running"' 'Audit Policies Enabled +5' '5'
	
	#wait 10 seconds
	sleep 10
done
