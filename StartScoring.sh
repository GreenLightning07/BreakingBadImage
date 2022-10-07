#! /bin/bash

sleep 10
git clone -b misc https://github.com/GreenLightning07/BreakingBadImage.git
chmod +x BreakingBadImage/changes.sh
chmod +x BreakingBadImage/scorebot.sh
mv BreakingBadImage/scorebot.sh /var/local/scorebot.sh
mv BreakingBadImage/ScoreReport.html /home/walter/Desktop/ScoreReport.html
mv BreakingBadImage/README.html /home/walter/Desktop/README.html
BreakingBadImage/changes.sh
sudo /var/local/scorebot.sh
