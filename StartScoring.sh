#! /bin/bash

sleep 10
git clone -b misc https://github.com/GreenLightning07/KungFuPandaImage.git
chmod +x KungFuPandaImage/changes.sh
chmod +x KungFuPandaImage/scorebot.sh
mv KungFuPandaImage/scorebot.sh /var/local/scorebot.sh
mv KungFuPandaImage/ScoreReport.html /home/po/Desktop/ScoreReport.html
mv KungFuPandaImage/README.html /home/po/Desktop/README.html
KungFuPandaImage/changes.sh
sudo /var/local/scorbot.sh
