import paramiko
import time
import socket
import os.path
import re, sys
import csv

class wap(object):


        def __init__(self, username, password, ap_ip, timeout,MAX_BUFFER=65535):

                self.username = username
                self.password = password
                self.hostname = ap_ip
                self.timeout = timeout
                self.MAX_BUFFER = MAX_BUFFER



        def establish_connection(self, sleep_time=3, verbose=False, timeout=8):
                '''
                Establish SSH connection to WAP 

                '''

                # Create instance of SSHClient object
                self.remote_conn_pre = paramiko.SSHClient()

                # Automatically add untrusted hosts (make sure appropriate for your environment)
                self.remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # initiate SSH connection
                try:
                        self.remote_conn_pre.connect(hostname=self.hostname, port=22,
                                                     username=self.username, password=self.password, timeout=self.timeout)
                except socket.error:
                        msg = "Connection to device timed-out"
                        return "Failed"

                # Use invoke_shell to establish an 'interactive session'
                self.remote_conn = self.remote_conn_pre.invoke_shell()

                if verbose:
                        print("Interactive SSH session established")

                time.sleep(sleep_time)
                
                # Strip any initial data and send command
                if self.remote_conn.recv_ready():
                        return self.remote_conn.recv(self.MAX_BUFFER).decode('utf-8')

                else:
                        i = 0
                        while i <= 10:
                                # Send a newline if no data is present
                                self.remote_conn.sendall('\n')
                                time.sleep(.5)
                                if self.remote_conn.recv_ready():
                                        return self.remote_conn.recv(self.MAX_BUFFER).decode('utf-8')
                                else:
                                        i += 1
                        return ""


        def clear_buffer(self):
                '''
                Read any data available in the channel up to MAX_BUFFER
                
                '''

                if self.remote_conn.recv_ready():
                        return self.remote_conn.recv(self.MAX_BUFFER).decode('utf-8')
                else:
                        print "Nothing to clear"
                        return None


        def send_command(self, command_string, delay_factor=.5, max_loops=30):
                '''
                Execute command_string on the SSH channel.

                Use delay based mechanism to obtain output.  

                delay_factor can be used to increase the delays.

                max_loops can be used to increase the number of times it reads the data buffer

                Returns the output of the command.
                '''

                debug = False
                output = ''

                if debug:
                        print('In send_command')

                self.clear_buffer()

                # Ensure there is a newline at the end of the command
                command_string = command_string.rstrip("\n")
                command_string += '\n'

                if debug:
                        print("Command is: {0}".format(command_string))


                self.remote_conn.sendall(command_string)

                time.sleep(1*delay_factor)
                not_done = True
                i = 1

                while (not_done) and (i <= max_loops):
                        time.sleep(1*delay_factor)
                        i += 1
                        # Keep reading data as long as available (up to max_loops)
                        if self.remote_conn.recv_ready():
                                output += self.remote_conn.recv(self.MAX_BUFFER).decode('utf-8')
                                if "--MORE--" in output:
                                        self.remote_conn.sendall(chr(32))                      
                        else:
                                not_done = False
                                #print "In Not Done"

                if debug:
                        print(output)
                return output

        def disconnect(self):
                '''
                Gracefully close the SSH connection
                '''
                self.remote_conn_pre.close()

        
        def writefile(self,ap_ip, filename):
                '''
                Write AP IP Address to text file
                '''
                with open(filename, 'w') as f:
                        f.write("++ Executing Command on AP: %s " % ap_ip+"\n")


        def appendfile(self,output, filename):
                '''
                Append show Command output to file
                '''
                with open(filename, 'a') as f:
                        f.write("="*10+" "+time.strftime("%Y:%m:%d %H:%M:%S", time.localtime())+" "+"="*10+"\n")
                        f.write(output+"\n")
                        f.write("="*37+"\n")

        def write_csv(self,filename,rows):
                '''
                Write CSV file containing results of TOP
                '''

                with open(filename, "ab") as csv_file:
                        writer = csv.writer(csv_file,delimiter=',', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(rows)


        def parse_file_process(self,filename):
                '''
                Parse Software Interrupts and Free Memory from show top -b -n 1 results
                
                
                A171434033AB9# show top -b -n 1
                top - 19:46:56 up 29 min,  1 user,  load average: 5.00, 4.97, 4.21
                Tasks:  68 total,   1 running,  67 sleeping,   0 stopped,   0 zombie
                Cpu(s):  1.4%us,  0.9%sy,  0.1%ni, 97.3%id,  0.3%wa,  0.0%hi,  0.0%si,  0.0%st
                Mem:    983984k total,   469232k used,   514752k free,       88k buffers
                Swap:        0k total,        0k used,        0k free,   217460k cached
                
                  PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
                 2787 A1714340  20   0  3280 1236  980 R    4  0.1   0:00.04 top
                    1 A1714340  20   0  2592  768  656 S    0  0.1   0:08.68 init
                    2 A1714340  20   0     0    0    0 S    0  0.0   0:00.00 kthreadd
                    3 A1714340  RT   0     0    0    0 S    0  0.0   0:00.00 migration/0
                    4 A1714340  20   0     0    0    0 S    0  0.0   0:00.00 ksoftirqd/0
                    5 A1714340  RT   0     0    0    0 S    0  0.0   0:00.00 migration/1
                    6 A1714340  20   0     0    0    0 S    0  0.0   0:00.00 ksoftirqd/1
                    7 A1714340  20   0     0    0    0 S    0  0.0   0:00.87 events/0
                    8 A1714340  20   0     0    0    0 S    0  0.0   0:00.17 events/1
                    
                '''
                start_pattern = "^========== "
                end_pattern = "^====================================="
                cpu_start_line = 4
                mem_start_line = 5
                process_start_line = 9
                skip_line = 0
                current_state = "looking_for_marker"
                csvfile = filename.rsplit('.txt')[0]+".csv"
                cpu_mem_state = ""
                csv_row_header = ["Timestamp", "Software Interrupts", "Free Memory"]
                csv_row_values = []
                csv_write_header_state = "not_written"

                try:
                        top_file = open(filename)
                except:
                        print 'Could not open file:', top_file
                        sys.exit()

                for line in top_file:
                        line = line.rstrip('\n')
                        if re.findall(start_pattern, line):
                                timestamp = line.rsplit(' ')[1]+' '+line.rsplit(' ')[2]
                                #print "Timestamp:", timestamp
                                current_state = "looking_to_process"
                                if csv_write_header_state == "not_written":
                                        self.write_csv(csvfile,csv_row_header)
                                        csv_write_header_state = "written"

                                csv_row_values.append(timestamp)
                        elif re.findall(end_pattern,line):
                                skip_line = 0
                                current_state = "looking_for_marker"
                        else:
                                if current_state == "looking_to_process":
                                        skip_line += 1
                                        if skip_line == cpu_start_line:
                                                process_data = re.findall(r"[\w.()%:\-/]+", line)
                                                si = process_data[-2].rsplit('%')[0]
                                                hi = process_data[-3]
                                                cpu_mem_state = "cpu"
                                                print "Software Interrupt:", si
                                                csv_row_values.append(si)
                                        if skip_line == mem_start_line:
                                                process_data = re.findall(r"[\w:]+", line)
                                                free_mem = process_data[-4]
                                                cpu_mem_state += "mem"
                                                print "Free Memory:", free_mem
                                                csv_row_values.append(free_mem)

                                        if cpu_mem_state == "cpumem":
                                                self.write_csv(csvfile, csv_row_values)
                                                cpu_mem_state = ""
                                                csv_row_values = []
                return csvfile
        
        
        
        def parse_file_apcount(self,filename):
                '''
                Parse output of show stations counts
                ========== 2015:09:11 09:56:52 ==========
                show stations counts
                
                Associated Station Counts by Operating Mode
                
                2.4GHz Stations                    5GHz Stations                 
                ------------------------------     ------------------------------
                  802.11b            0      0%       802.11a            0      0%
                  802.11g            0      0%       802.11n            0      0%
                  802.11n            0      0%       802.11ac           0      0%
                                 =====   =====                      =====   =====
                                     0      0%                          0      0%
                
                2.4GHz Spatial Streams             5GHz Spatial Streams          
                ------------------------------     ------------------------------
                  1x1                0      0%       1x1                0      0%
                  2x2                0      0%       2x2                0      0%
                  3x3                0      0%       3x3                0      0%
                                 =====   =====                      =====   =====
                                     0      0%                          0      0%
                
                Band Totals                        802.11 Totals                 
                ------------------------------     ------------------------------
                  2.4GHz             0      0%       802.11a/b/g        0      0%
                    5GHz             0      0%       802.11n            0      0%
                
                        
                                 =====   =====       802.11ac           0      0%
                                     0      0%                      =====   =====
                                                                        0      0%
                
                A171434033AB9#                             
                =====================================
                '''
                ap_ip_line_pattern = "^\+\+ "
                start_pattern = "^========== "
                end_pattern = "^====================================="
                stations_start_line = 11
                skip_line = 0
                current_state = "looking_for_marker"
                csvfile = filename.rsplit('.txt')[0]+".csv"
                write_csv_state = ""
                csv_row_header = ["Timestamp", "AP_IP", "2.4GHz Stations", "5GHz Stations"]
                csv_row_values = []
                csv_write_header_state = "not_written"
                skip_first = "not_parsed_ap_ip"
                ap_ip = "0.0.0.0"

                try:
                        apcount_file = open(filename)
                except:
                        print 'Could not open file:', apcount_file
                        sys.exit()

                for line in apcount_file:
                        line = line.rstrip('\n')
                        
                        if skip_first == "not_parsed_ap_ip":
                                ap_ip = line.rsplit(" ")[5]
                                skip_first = "parsed_ap_ip"
                                print ap_ip
                        
                        
                        if re.findall(start_pattern, line):
                                timestamp = line.rsplit(' ')[1]+' '+line.rsplit(' ')[2]
                                print "Timestamp:", timestamp
                                current_state = "looking_to_process"
                                if csv_write_header_state == "not_written":
                                        self.write_csv(csvfile,csv_row_header)
                                        csv_write_header_state = "written"

                                csv_row_values.append(timestamp)
                                csv_row_values.append(ap_ip)
                                
                        elif re.findall(end_pattern,line):
                                skip_line = 0
                                current_state = "looking_for_marker"
                        else:
                                if current_state == "looking_to_process":
                                        skip_line += 1
                                        if skip_line == stations_start_line:
                                                process_data = re.findall(r"[\w%]+", line)
                                                twoghz = process_data[0]
                                                fiveghz = process_data[2]
                                                write_csv_state = "writecsv"
                                                csv_row_values.append(twoghz)
                                                csv_row_values.append(fiveghz)
                            
                                        if write_csv_state == "writecsv":
                                                self.write_csv(csvfile, csv_row_values)
                                                write_csv_state= ""
                                                csv_row_values = []
                return csvfile
        
        
        

        def generate_chart(self,csvinputfile, info, htmltemplate="google_annotation_template.html"):
                #row_template = '[new Date(%s), %.3f, %d, %s],' --> Use this if you want to plot Free Memory 
                htmloutfile = csvinputfile.rsplit('.csv')[0]+'-si.html'
                row_template = '[new Date(%s), %.3f, "%s"],'
                row_list = []
                with open(csvinputfile) as fc:
                        reader = csv.DictReader(fc, delimiter=',')
                        for row in reader:
                                timestamp = row['Timestamp']
                                si = row['Software Interrupts']
                                freemem = row['Free Memory']

                                timestamp_list = timestamp.split(' ')
                                
                                #','.join(timestamp_list[0].split("/")+timestamp_list[1].split(":")) 
                                # if the format of time is 2015/09/11 16:10:18
                                timestamp_str = ','.join(':'.join(timestamp_list).split(':'))

                                freemem_int = int(freemem.split('k')[0])

                                si_float = float(si)

                                # Use the below if you want to include Free Memory
                                #row_data = row_template % (timestamp_str, si_float, freemem_int, info)

                                row_data = row_template % (timestamp_str, si_float, info)

                                row_list.append(row_data)

                with open(htmltemplate) as fh:
                        chart_template = fh.read()

                with open(htmloutfile, 'w') as fho:
                        fho.write(chart_template % ('\n'.join(row_list)))















