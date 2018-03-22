#!/bin/bash

. /etc/rc.conf

case "$1" in
  start)
    su - rtorrent -c 'screen -d -m -S rtorrent rtorrent' &> /dev/null
    ;;
  stop)
    killall -s 2 rtorrent &> /dev/null
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  *)
    echo "usage: $0 {start|stop|restart}"
esac
exit 0
