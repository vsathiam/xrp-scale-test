from wap import *
import threading


def apiniticpu(ap_ip, commands):
    remote_conn = wap(username = "admin", password = "admin", ap_ip =ap_ip, timeout = 8)
    remote_conn.establish_connection()

    for command_string in commands:
        try:
            output = remote_conn.send_command(command_string)
        except:
                print "Unable to send command:", command_string
        

commands = ["configure", "boot-env", "edit bootargs console=ttyS0,115200n8 root=/dev/ram rw quiet  console=ttyS0,115200n8 root=/dev/ram rw quiet  CLIOPTS=b", "save", "show top -b -n 1"]
ap_ip = "192.168.1.10"

apiniticpu(ap_ip, commands)