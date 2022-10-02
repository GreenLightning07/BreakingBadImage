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
			show-vuln "$2" "Vuln$2;" "$3" "$4"
		fi
	elif ( cat $score_report | grep "id=\"$2\"" | grep "display:block" ); then
		hide-vuln "$2" "$3" "Vuln$2;" "$4"
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

	if ( ! cat /etc/passwd | grep "kai" ); then
		if ( cat $score_report | grep 'id="l1"' | grep "display:none" ); then
			show-vuln "l1" "linux_found" "Linux1;" "Removed unauthorized user Kai"
		fi
	elif ( cat $score_report | grep 'id="l1"' | grep "display:block" ); then
		hide-vuln "l1" "linux_found" "Removed unauthorized user Kai" "Linux1;"
	fi

	if ( ! cat /etc/passwd | grep "tailung" ); then
		if ( cat $score_report | grep 'id="l2"' | grep "display:none" ); then
			show-vuln "l2" "linux_found" "Linux2;" "Removed unauthorized hidden user TaiLung"
		fi
	elif ( cat $score_report | grep 'id="l2"' | grep "display:block" ); then
		hide-vuln "l2" "linux_found" "Removed unauthorized hidden user TaiLung" "Linux2;"
	fi

	if ( ! cat /etc/group | grep "sudo" | grep "tigress" ); then
		if ( cat $score_report | grep 'id="l3"' | grep "display:none" ); then
			show-vuln "l3" "linux_found" "Linux3;" "Removed unauthorized admin Tigress"
		fi
	elif ( cat $score_report | grep 'id="l3"' | grep "display:block" ); then
		hide-vuln "l3" "linux_found" "Removed unauthorized admin Tigress" "Linux3;"
	fi

	if ( cat /etc/group | grep "sudo" | grep "po" ); then
		if ( cat $score_report | grep 'id="l4"' | grep "display:none" ); then
			show-vuln "l4" "linux_found" "Linux4;" "Added authorized admin Po"
		fi
	elif ( cat $score_report | grep 'id="l4"' | grep "display:block" ); then
		hide-vuln "l4" "linux_found" "Added authorized admin Po" "Linux4;"
	fi

	if ( ! cat /etc/shadow | grep "po" | grep '$1$9GzrkEx5$QDnXTw3G.aKOHpyQxHZh.0' && $pam_configed && $encrypt_set ); then
		if ( cat $score_report | grep 'id="l5"' | grep "display:none" ); then
			show-vuln "l5" "linux_found" "Linux5;" "Secure password set for Po"
		fi
	elif ( cat $score_report | grep 'id="l5"' | grep "display:block" ); then
		hide-vuln "l5" "linux_found" "Secure password set for Po" "Linux5;"
	fi

	if ( ls -al /etc/shadow | grep ^"-rw-------" || ls -al /etc/shadow | grep ^"-rw-r-----" ); then
		if ( cat $score_report | grep 'id="l6"' | grep "display:none" ); then
			show-vuln "l6" "linux_found" "Linux6;" "Correct file permnissions set on /etc/shadow"
		fi
	elif ( cat $score_report | grep 'id="l6"' | grep "display:block" ); then
		hide-vuln "l6" "linux_found" "Correct file permnissions set on /etc/shadow" "Linux6;"
	fi

	if ( ls -al /var | grep tmp | grep rwt ); then
		if ( cat $score_report | grep 'id="l7"' | grep "display:none" ); then
			show-vuln "l7" "linux_found" "Linux7;" "Stickybit set on /var/tmp"
		fi
	elif ( cat $score_report | grep 'id="l7"' | grep "display:block" ); then
		hide-vuln "l7" "linux_found" "Stickybit set on /var/tmp " "Linux7;"
	fi

	if ( ls -o /etc | grep "fstab" | grep "root" ); then
		if ( cat $score_report | grep 'id="l8"' | grep "display:none" ); then
			show-vuln "l8" "linux_found" "Linux8;" "Correct owner on /etc/fstab"
		fi
	elif ( cat $score_report | grep 'id="l8"' | grep "display:block" ); then
		hide-vuln "l8" "linux_found" "Correct owner on /etc/fstab" "Linux8;"
	fi

	if ( ! cat /home/po/.mozilla/firefox/hs3wo7ii.default-release/prefs.js | grep 'user_pref("dom.disable_open_during_load", false);' ); then
		if ( cat $score_report | grep 'id="l9"' | grep "display:none" ); then
			show-vuln "l9" "linux_found" "Linux9;" "Block popups in Firefox"
		fi
	elif ( cat $score_report | grep 'id="l9"' | grep "display:block" ); then
		hide-vuln "l9" "linux_found" "Block popups in Firefox" "Linux9;"
	fi

	if ( ! find / | grep "goofylilscript" ); then
		if ( cat $score_report | grep 'id="l10"' | grep "display:none" ); then
			show-vuln "l10" "linux_found" "Linux10;" "Removed malicious python script"
		fi
	elif ( cat $score_report | grep 'id="l10"' | grep "display:block" ); then
		hide-vuln "l10" "linux_found" "Removed malicious python script" "Linux10;"
	fi

	if ( cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep "90" ); then
		if ( cat $score_report | grep 'id="l11"' | grep "display:none" ); then
			show-vuln "l11" "linux_found" "Linux11;" "Correct max password life set"
		fi
	elif ( cat $score_report | grep 'id="l11"' | grep "display:block" ); then
		hide-vuln "l11" "linux_found" "Correct max password life set" "Linux11;"
	fi

	if ( cat /etc/login.defs | grep ^"ENCRYPT_METHOD" | grep "SHA512" && cat /etc/pam.d/common-password | grep "pam_unix.so" | grep "SHA512" ); then
		if ( cat $score_report | grep 'id="l12"' | grep "display:none" ); then
			show-vuln "l12" "linux_found" "Linux12;" "Correct encrypt type set"
			encrypt_set=true
		fi
	elif ( cat $score_report | grep 'id="l12"' | grep "display:block" ); then
		hide-vuln "l12" "linux_found" "Correct encrypt type set" "Linux12;"
	fi

	if ( cat /etc/pam.d/common-password | grep "pam_cracklib.so" | grep "dcredit=-1" ); then
		if ( cat $score_report | grep 'id="l13"' | grep "display:none" ); then
			show-vuln "l13" "linux_found" "Linux13;" "Require digits in passwords"
		fi
	elif ( cat $score_report | grep 'id="l13"' | grep "display:block" ); then
		hide-vuln "l13" "linux_found" "Require digits in passwords" "Linux13;"
	fi

	if ( cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Download-Upgradeable-Packages \"1\";" && cat /etc/apt/apt.conf.d/20auto-upgrades | grep "APT::Periodic::Unattended-Upgrade \"1\";" ); then
		if ( cat $score_report | grep 'id="l14"' | grep "display:none" ); then
			show-vuln "l14" "linux_found" "Linux14;" "Automatically download and install security updates"
		fi
	elif ( cat $score_report | grep 'id="l14"' | grep "display:block" ); then
		hide-vuln "l14" "linux_found" "Automatically download and install security updates" "Linux14;"
	fi

	if ( ! dpkg -l | grep "netcat"); then
		if ( cat $score_report | grep 'id="l15"' | grep "display:none" ); then
			show-vuln "l15" "linux_found" "Linux15;" "Netcat is removed"
		fi
	elif ( cat $score_report | grep 'id="l15"' | grep "display:block" ); then
		hide-vuln "l15" "linux_found" "Netcat is removed" "Linux15;"
	fi

	if ( ! dpkg -l | grep "samba" | grep -v "python" ); then
		if ( cat $score_report | grep 'id="l16"' | grep "display:none" ); then
			show-vuln "l16" "linux_found" "Linux16;" "Samba is removed"
		fi
	elif ( cat $score_report | grep 'id="l16"' | grep "display:block" ); then
		hide-vuln "l16" "linux_found" "Samba is removed" "Linux16;"
	fi

	if ( ufw status | grep -w "active" ); then
		if ( cat $score_report | grep 'id="l17"' | grep "display:none" ); then
			show-vuln "l17" "linux_found" "Linux17;" "UFW is enabled"
		fi
	elif ( cat $score_report | grep 'id="l17"' | grep "display:block" ); then
		hide-vuln "l17" "linux_found" "UFW is enabled" "Linux17;"
	fi

	if ( ufw status verbose | grep "Logging:" | grep "on" | grep "high" ); then
		if ( cat $score_report | grep 'id="l18"' | grep "display:none" ); then
			show-vuln "l18" "linux_found" "Linux18;" "UFW logging set to high"
		fi
	elif ( cat $score_report | grep 'id="l18"' | grep "display:block" ); then
		hide-vuln "l18" "linux_found" "UFW logging set to high" "Linux18;"
	fi

sleep 10
done
