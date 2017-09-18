#!/bin/bash  
#This shell script is for ping the pointed ip
#./test 192.168.2.1 3
date=`date +%s%N`
echo $date >>/tmp/tmp
order=`ping $1 -c $2 >/tmp/$date`
loss=`cat /tmp/$date|grep "transmitted" |awk -F "," '{print $3}'|awk -F " " {'print $1'}| sed 's/%//g'`
test=`cat /tmp/$date |grep "100%"`
if [ -n "$test" ]; then 
    loss=100
    mdev=99
    avg=99
else
    mdev=`cat /tmp/$date|grep "rtt" |awk -F "=" {'print $2'}|awk -F "/" {'print $4'}|awk -F " " {'print $1'}`
    avg=`cat /tmp/$date|grep "rtt" |awk -F "=" {'print $2'}|awk -F "/" {'print $2'}`
fi
#rm /tmp/$date
echo $avg 
echo $mdev
echo $loss
