cp -Rf andraxbin/* /opt/ANDRAX/bin/

chmod -R 755 /opt/ANDRAX/bin

rm -rf /opt/ANDRAX/wifitap

cp -Rf $(pwd) /opt/ANDRAX/wifitap
