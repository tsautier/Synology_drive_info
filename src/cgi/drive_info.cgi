#!/bin/sh
printf "Content-Type: text/plain; charset=utf-8\r\n\r\n"
exec /var/packages/drive_info/target/bin/drive_info.sh 2>&1
