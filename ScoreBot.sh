#!/bin/bash

total_found=0
linux_found=0
apache_found=0
mysql_found=0
vsftp_found=0
openvpn_found=0

score_report="/home/po/Desktop/ScoreReport.html"

function Update_Found
{
	total_found=$((linux_found + apache_found + mysql_found + vsftp_found + openvpn_found))
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/200<\/center><\/h3>/g" $score_report
        sed -i "s/id=\"linux_found\".*/id=\"linux_found\">LINUX ($linux_found\/30)<\/button>/g" $score_report

	echo $total_found
}

function Show_Vuln()
{
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
}

function Hide_Vuln()
{
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
}

Update_Found

while true
do
	if ( ! cat /etc/passwd | grep "kai" ); then
		if ( cat $score_report | grep 'id="l1"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l1"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l1"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l1"
		Update_Found
	fi

	if ( ! cat /etc/passwd | grep "tailung" ); then
		if ( cat $score_report | grep 'id="l2"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l2"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l2"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l2"
		Update_Found
	fi

	if ( ! cat /etc/group | grep "sudo" | grep "tigress" ); then
		if ( cat $score_report | grep 'id="l3"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l3"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l3"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l3"
		Update_Found
	fi

	if ( cat /etc/group | grep "sudo" | grep "po" ); then
		if ( cat $score_report | grep 'id="l4"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l4"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l4"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l4"
		Update_Found
	fi

	if ( ! cat /etc/shadow | grep "po" | grep "$1$RNW/raIJ$yQAKMclO2hNgJIz4flS2z0" ); then
		if ( cat $score_report | grep 'id="l5"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l5"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l5"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l5"
		Update_Found
	fi

	if ( ls -al /etc | grep -v gshadow | grep shadow$ | grep ^"-rw-------" || ls -al /etc | grep -v gshadow | grep shadow$ | grep ^"-rw-r-----" ); then
		if ( cat $score_report | grep 'id="l6"' | grep "display:none" ); then
			((linux_found++))
			Show_Vuln "l6"
			Update_Found
		fi
	elif ( cat $score_report | grep 'id="l6"' | grep "display:block" ); then
		((linux_found--))
		Hide_Vuln "l6"
		Update_Found
	fi

sleep 10
done
