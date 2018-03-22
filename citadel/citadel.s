#!/bin/sh
# description: Starts the Citadel Server
#
#
case "$1" in
start)
/var/citadel/citserver -d
;;
stop)
/usr/bin/killall citserver
;;
restart)
/usr/bin/killall citserver
/var/citadel/citserver -d
;;
*)
echo "Usage: $0 {start|stop|restart}"
exit 1
;;
esac
