from wap import *
import threading


wap_ip = ["10.140.33.101", "10.140.33.104", "10.140.33.106", "10.140.33.107", "10.140.33.108", 
          "10.140.33.110", "10.140.33.111", "10.140.33.113", "10.140.33.114", "10.140.33.115", 
          "10.140.33.116", "10.140.33.119", "10.140.33.121", "10.140.33.122", "10.140.33.123", 
          "10.140.33.124", "10.140.33.125", "10.140.33.127", "10.140.33.128", "10.140.33.130", 
          "10.140.33.131", "10.140.33.132", "10.140.33.133", "10.140.33.135", "10.140.33.138", 
          "10.140.33.139", "10.140.33.140", "10.140.33.141", "10.140.33.142", "10.140.33.146", 
          "10.140.33.152", "10.140.33.153", "10.140.33.155", "10.140.33.162", "10.140.33.163", 
          "10.140.33.164", "10.140.33.166", "10.140.33.168", "10.140.33.170", "10.140.33.172", 
          "10.140.33.173", "10.140.33.175", "10.140.33.176", "10.140.33.177", "10.140.33.178", 
          "10.140.33.179", "10.140.33.180", "10.140.33.182", "10.140.33.183", "10.140.33.184", 
          "10.140.33.185", "10.140.33.186", "10.140.33.190", "10.140.33.191", "10.140.33.192", 
          "10.140.33.193", "10.140.33.194", "10.140.33.195", "10.140.33.196", "10.140.33.197", 
          "10.140.33.198", "10.140.33.201", "10.140.33.202", "10.140.33.203", "10.140.33.204", 
          "10.140.33.205", "10.140.33.208", "10.140.33.209", "10.140.33.210", "10.140.33.211", 
          "10.140.33.212", "10.140.33.213", "10.140.33.214", "10.140.33.215", "10.140.33.217", 
          "10.140.33.218", "10.140.33.219", "10.140.33.220", "10.140.33.222", "10.140.33.223", 
          "10.140.33.224", "10.140.33.225", "10.140.33.227", "10.140.33.228", "10.140.33.229", 
          "10.140.33.231", "10.140.33.232", "10.140.33.233", "10.140.33.234", "10.140.33.235", 
          "10.140.33.236", "10.140.33.238", "10.140.33.239", "10.140.33.240"]

#wap_ip = ["10.140.33.189"]

def apiniticpu(ap_ip, commands):
    remote_conn = wap(username = "admin", password = "admin", ap_ip =ap_ip, timeout = 8)
    remote_conn.establish_connection()

    for command_string in commands:
        try:
            output = remote_conn.send_command(command_string)
        except:
                print "Unable to send command:", command_string
        

commands = ["configure", "boot-env", "edit bootargs console=ttyS0,115200n8 root=/dev/ram rw quiet  console=ttyS0,115200n8 root=/dev/ram rw quiet  CLIOPTS=b", "save", "show top -b -n 1"]

#ap_ip = "192.168.1.10"

#for ip in wap_ip:
    #apiniticpu(ip, commands)

threads = []

for ip in wap_ip:
    th = threading.Thread(target=apiniticpu, args = (ip, commands))
    th.start()
    threads.append(th)

for th in threads:
    th.join()