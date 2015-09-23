from wap import *
import threading


# Log into the Access Point using the default username and password (admin/admin)
# Execute the command string - show top -b -n 1
# Write the results of show top to a file (Path is set static - )
# It also parses the the results file (of show top) and parses "Software Interrupts, Timestamp and Free Memmory"
# Output of the above is stored as a CSV file


def callaps(ap_ip, iterations, iteration_interval):     
                iteration_counter = 0
                timestring = time.strftime("%m.%d.%y-%H.%M.%S", time.localtime())
                filename = os.path.join("/Users/vsathiam/Documents/LOGS","WAP-sta-top-"+ap_ip+"-"+timestring+".txt")
                command_string="show top -b -n 1"


                while iteration_counter < iterations:
                                remote_conn = wap(username = "admin", password = "admin", ap_ip = ap_ip, timeout = 8)
                                remote_conn.establish_connection()
                                try:
                                                output = remote_conn.send_command(command_string)
                                except:
                                                print "Unable to send command"
                                                return
                                if iteration_counter==0:
                                                #remote_conn.writefile(command_string,filename)
                                                remote_conn.writefile(ap_ip,filename)
                                try:
                                                remote_conn.appendfile(output, filename)
                                except:
                                                print "Unable to append output to file"
                                                return
                                time.sleep(1)
                                remote_conn.disconnect()
                                time.sleep(iteration_interval)
                                iteration_counter += 1

                try:               
                                csvfile = remote_conn.parse_file_process(filename)
                except:
                                print "Unable to parse file"
                                return
                remote_conn.generate_chart(csvfile, ap_ip)
                



# Modify the IP address prefix of the Access Points   

#ip_prefix = "192.168.1."
#ip_prefix = "10.140.33."

# Modify in the range command, the 4th octet of the IP 
# If the access point IP ranges from 192.168.1.10 to 192.168.1.20, modify
# the range command to (10,21)

#for suffix in range(104,105):
                #ap_ip = ip_prefix+str(suffix)
                #th = threading.Thread(target=callaps, args = (ap_ip, 2, 10))
                #th.start()
                #threads.append(th)
                
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


threads = []

for ip in wap_ip:
                th = threading.Thread(target=callaps, args = (ip, 2, 10))
                th.start()
                threads.append(th)

for th in threads:
                th.join()
