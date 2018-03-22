#!/bin/sh
# description: Starts the Citadel Server
#
#
case "$1" in
start)
/var/citadel/webcit/webcit -d -p2000
echo "."
;;
stop)
/usr/bin/killall webcit
echo "."
;;
restart)
/usr/bin/killall webcit
/var/citadel/webcit/webcit -d -p2000
echo "."
;;
*)
echo "Usage: $0 {start|stop|restart}"
exit 1
;;
esac
