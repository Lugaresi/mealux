#!/bin/sh
# description: Starts the Thermal Monitoring Daemon
#
#
case "$1" in
start)
/usr/sbin/thermald --dbus-enable
;;
stop)
/usr/bin/killall thermald
;;
restart)
/usr/bin/killall thermald
/usr/sbin/thermald --dbus-enable
;;
*)
echo "Usage: $0 {start|stop|restart}"
exit 1
;;
esac
