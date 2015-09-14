from wap import *
import threading


#remote_conn = wap(username = "admin", password = "admin", ap_ip = "192.168.1.10", timeout = 8)
#remote_conn.establish_connection()

#try:
    #output = remote_conn.send_command(command_string="show stations all")
#except:
        #print "Unable to send command show stations all"
        
#try:
    #output = remote_conn.send_command(command_string="show stations counts")
#except:
        #print "Unable to send command show stations count"




def callaps(ap_ip, iterations, iteration_interval):     
    iteration_counter = 0
    timestring = time.strftime("%m.%d.%y-%H.%M.%S", time.localtime())
    filename = os.path.join("/Users/vsathiam/Documents/LOGS","WAP-sta-count-"+ap_ip+"-"+timestring+".txt")
    
    command_string="show stations counts"


    while iteration_counter < iterations:
        remote_conn = wap(username = "admin", password = "admin", ap_ip = ap_ip, timeout = 8)
        remote_conn.establish_connection()
        try:
            output = remote_conn.send_command(command_string)
        except:
            print "Unable to send command", command_string
            return
        if iteration_counter==0:
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
        csvfile = remote_conn.parse_file_apcount(filename)
    except:
            print "Unable to parse file"
            return
    

    
threads = []


# Modify the IP address prefix of the Access Points   

ip_prefix = "10.140.33."
#ip_prefix = "192.168.1."

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


