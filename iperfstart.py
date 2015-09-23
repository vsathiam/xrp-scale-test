import calendar
import time
import os
from parser import *

start_time_offset = []
server_ip = "148.147.61.57"
LOG_FILE = server_ip+".json"

cmd = "iperf3 -c %s -t 120 -J --logfile %s" % (server_ip, LOG_FILE)
start_time = calendar.timegm(time.localtime())

print "Start Time", start_time

os.system(cmd)

time.sleep(3)

parse = parser(start_time)

parse.extract("/Users/vsathiam/Documents/Scripts/xrp-scale-test/%s" % LOG_FILE)









