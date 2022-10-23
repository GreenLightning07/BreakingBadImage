#! /bin/bash

sleep 10
git clone -b misc https://github.com/GreenLightning07/CyberImage.git
chmod +x CyberImage/changes.sh
chmod +x CyberImage/scorebot.sh
mv CyberImage/scorebot.sh /var/local/scorebot.sh
mv CyberImage/ScoreReport.html /home/cyber/Desktop/ScoreReport.html
mv CyberImage/README.html /home/cyber/Desktop/README.html
mv CyberImage/Contact.html /home/cyber/Desktop/Contact.html
CyberImage/changes.sh
sudo /var/local/scorebot.sh
