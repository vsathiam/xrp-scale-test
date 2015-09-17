from wap import *
import threading


# Log into the Access Point using the default username and password (admin/admin)
# Execute the command string - show top -b -n 1
# Write the results of show top to a file (Path is set static - )
# It also parses the the results file (of show top) and parses "Software Interrupts, Timestamp and Free Memmory"
# Output of the above is stored as a CSV file


def callaps(ap_ip, iterations, iteration_interval):     
                iteration_counter = 0
                timestring = time.strftime("%m.%d.%y-%H.%M.S", time.localtime())
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
                                                remote_conn.writefile(command_string,filename)
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
                

threads = []


# Modify the IP address prefix of the Access Points   

#ip_prefix = "192.168.1."
ip_prefix = "10.140.33."

# Modify in the range command, the 4th octet of the IP 
# If the access point IP ranges from 192.168.1.10 to 192.168.1.20, modify
# the range command to (10,21)

for suffix in range(104,105):
                ap_ip = ip_prefix+str(suffix)
                th = threading.Thread(target=callaps, args = (ap_ip, 2, 10))
                th.start()
                threads.append(th)
              

for th in threads:
                th.join()


