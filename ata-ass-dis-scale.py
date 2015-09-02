#!/usr/bin/env python

from __future__ import print_function
import sys
import xml.etree.ElementTree as ET
import threading

try:
    import pexpect
except:
    sys.stderr.write("You do not have 'pexpect' installed.\n")
    exit(1)

class VeriWavePort(object):

    def __init__(self, chassis, slot_num, port_num, port_name, channel, port_type):
        # This mapping technically doesn't work in every case. Mostly the issue is silly Japan.
        # Japan has channel identifiers that overap between 2.4 and 5.
        chan_freq_map = {'1': 2400, '2': 2400,'3': 2400,'4': 2400,'5': 2400,'6': 2400,'7': 2400,'8': 2400,'9': 2400,'10': 2400,'11': 2400,'12': 2400,'13': 2400,
        '34': 5000,'36': 5000,'38': 5000,'40': 5000,'42': 5000,'44': 5000,'46': 5000,'48': 5000,'52': 5000,'56': 5000,'60': 5000,'64': 5000,
        '100': 5000,'104': 5000,'108': 5000,'112': 5000,'108': 5000,'116': 5000,'120': 5000,'124': 5000,'128': 5000,'132': 5000,'136': 5000,
        '140': 5000,'144': 5000,'149': 5000,'153': 5000,'157': 5000,'161': 5000,'165': 5000,}

        self.chassis = chassis
        self.slot_num = slot_num
        self.port_num = port_num
        self.port_name = port_name
        self.channel = channel
        self.type = port_type
        self.frequency = chan_freq_map[str(channel)]
        self.clients = []

    def __repr__(self):
        return "\nname: %s\nchassis: %s\nslot number: %s\nport number: %s\nchannel: %s\nfrequency: %s\ntype:%s\nclients: %s\n" % (self.port_name, self.chassis, self.slot_num, self.port_num, self.channel, self.frequency, self.type, self.clients)
    def __str__(self):
        return "\nname: %s\nchassis: %s\nslot number: %s\nport number: %s\nchannel: %s\nfrequency: %s\ntype:%s\nclients: %s\n" % (self.port_name, self.chassis, self.slot_num, self.port_num, self.channel, self.frequency, self.type, self.clients)

    def add_client(self, client_name):
        self.clients.append(client_name)

class VeriWaveClient(object):

    def __init__(self, name, ssid, allowed_ports):
        self.name = name
        self.ssid = ssid
        self.allowed_ports = allowed_ports

    def __repr__(self):
        return "\nname: %s\nssid: %s\nallowed ports: %s\n" % (self.name, self.ssid, self.allowed_ports)
    def __str__(self):
        return "\nname: %s\nssid: %s\nallowed ports: %s\n" % (self.name, self.ssid, self.allowed_ports)


def session_setup(ata_ip, ata_user):
    # This function logs into the ATA and sets some parameters we want to user for the session

    # Log into the ATA and send the username
    ata_telnet_handler = pexpect.spawn('telnet ' + ata_ip)
    #ata_telnet_handler.logfile = sys.stdout
    ata_telnet_handler.expect('Hit Enter to proceed:')
    ata_telnet_handler.sendline()
    ata_telnet_handler.expect('Enter username:')
    ata_telnet_handler.sendline(ata_user)
    ata_telnet_handler.expect('admin ready>')

    # Set term length to 0 and responses to be formatted in XML
    ata_telnet_handler.sendline('termlen 0')
    ata_telnet_handler.expect('admin ready>')
    ata_telnet_handler.sendline('xmlrsps')
    ata_telnet_handler.expect('admin ready>')

    return ata_telnet_handler

def clear_all_ports(handler, chassis_ip):
    # This function clears all port associations for a given chassis IP
    
    # Setup our varabiles
    clear_port_list = list()

    # Send the command to list all of the ports and grab the output
    handler.sendline('list ports')
    handler.expect('admin ready>')
    list_ports_output = handler.before

    # Parse the output into XML handler. Weirdness in string formatting is because the output includes the 'list ports' command we typed above.
    list_ports_xml = ET.fromstring('\n'.join(list_ports_output.split('\n')[1:]))

    # Useful for later when we need to figure out how XML is structured
    #for child1 in list_ports_xml:
    #    print (child1.tag, child1.attrib, child1.text)
    #    for child2 in child1:
    #        print ('  ', child2.tag, child2.attrib, child2.text)
    #        for child3 in child2:
    #            print ('    ', child3.tag, child3.attrib, child3.text)
    #            for child4 in child3:
    #                print ('      ', child4.tag, child4.attrib, child4.text)

    # Collects the ports we need to clear based off the XML output
    for port in list_ports_xml.findall('./portList/port'):
        # If the chassis element of this port is equal to the chassis we want to clean up then add the port name to the clear port list
        if port.find('location/chassis').text == chassis_ip:
            clear_port_list.append(port.find('name').text)

    # Iterate the clear port list and get rid of all the ports
    for clear_port in clear_port_list:
        handler.sendline('releasePort ' + clear_port)
        handler.expect('admin ready>')

def initialize_veriwave_port_list(handler, chassis, channel_list):
    # This function initializes a list of VeriWavePort objects by iterating through a list of channels

    # Send the 'getChassisInfo' command to extract information about the currently installed cards
    handler.sendline('getChassisInfo ' + chassis)
    handler.expect('admin ready>')

    # Grab the output of the command and parse the XML
    get_chassis_info_output = handler.before
    get_chassis_info_xml = ET.fromstring('\n'.join(get_chassis_info_output.split('\n')[1:]))

    # Initialize some variables
    channel_iterator = 0
    veriwave_wireless_port_list = []
    veriwave_wired_port_list = []

    # Iterate through the root XML
    for slot in get_chassis_info_xml:
        # Look for the slots
        if 'slot_' in slot.tag:
            # Extract the port type
            port_type = slot.find('cardClass').text
            # Iterate through the ports
            for port in slot.find('ports'):
                # Build the port name
                port_name = ''
                if port_type == 'WLAN':
                    port_name += 'w'
                else:
                    port_name += 'e'
                port_name += slot.tag.split('_')[1]
                port_name += port.tag.split('_')[1]
                slot_num = int(slot.tag.split('_')[1])
                port_num = int(port.tag.split('_')[1])
                # Set the channel
                channel = channel_list[channel_iterator]
                channel_iterator += 1
                if channel_iterator == len(channel_list):
                    channel_iterator = 0
                # Insert new VeriWave Port object into list
                if port_type == 'WLAN':
                    veriwave_wireless_port_list.append(VeriWavePort(chassis, slot_num, port_num, port_name, channel, port_type))
                else:
                    veriwave_wired_port_list.append(VeriWavePort(chassis, slot_num, port_num, port_name, channel, port_type))

    return veriwave_wireless_port_list, veriwave_wired_port_list

def modify_veriwave_client_list(client_list, port_list, ssid, target_count):
    max_client_count = len(port_list[0].clients)
    add_client_port_iterator = 0

    for i, port in enumerate(port_list):
        if len(port.clients) < max_client_count:
            add_client_port_iterator = i
            break

    while len(client_list) < target_count:
        client_name = 'c' + str(len(client_list)) + '_'
        client_name += port_list[add_client_port_iterator].port_name

        port_list[add_client_port_iterator].clients.append(client_name)
        client_list.append(VeriWaveClient(client_name, ssid, [port_list[add_client_port_iterator].port_name]))

        add_client_port_iterator += 1
        if add_client_port_iterator >= len(port_list):
            add_client_port_iterator = 0

    while len(client_list) > target_count:
        remove_client_name = client_list[-1].name
        for port in port_list:
            if remove_client_name in port.clients:
                port.clients.remove(remove_client_name)
        client_list.pop()


    return client_list, port_list

#def sync_veriwave_port_list():
#def sync_veriwave_client_list():


#def ass_dis_manager():


def main():
    # Setup some constants for the testbed. 
    ata_server_ip = '10.140.251.50'
    veriwave_chassis_ip = '10.140.251.53'
    admin_username = 'admin'
    client_ssid = '\'Test_SSID\''

    veriwave_wireless_port_list = []
    veriwave_wired_port_list = []
    veriwave_client_list = []

    # Setup the session and log into ATA
    handler = session_setup(ata_server_ip,admin_username)
    ass_dis_handler = session_setup(ata_server_ip,admin_username)


    veriwave_wireless_port_list, veriwave_wired_port_list = initialize_veriwave_port_list(handler, veriwave_chassis_ip, [144, 36, 10, 52, 165])

    while True:

        sys.stdout.write('1. Modify target client count.\t\t\t\t Current: %s\n' % len(veriwave_client_list))
        sys.stdout.write('2. Modify target associate/disassociate rate. \t\t Current: 0\n')
        sys.stdout.write('3. Clear config and exit.\n')
        sys.stdout.write('Please choose:')
        option = sys.stdin.readline()
        option = option.strip()

        if option == '1':
            sys.stdout.write('Please enter new client count: ')
            new_client_count = sys.stdin.readline()
            new_client_count = int(new_client_count.strip())
            veriwave_client_list, veriwave_wireless_port_list = modify_veriwave_client_list(veriwave_client_list, veriwave_wireless_port_list, client_ssid, new_client_count)
            print ('CLIENT LIST')
            print (veriwave_client_list)
            print ('PORT LIST')
            print (veriwave_wireless_port_list)
        elif option == '2':
            sys.stdout.write('Please enter new association/disassoication rate in a per client per 10 min value: ')
            new_ass_dis_rate = sys.stdin.readline()
        elif option == '3':
            sys.stdout.write('**** Exiting!\n')
            break
        else:
            sys.stdout.write('**** Invalid option. Please try again.\n')

    # Do some stuff to test things out.
    #ata_telnet_handler.sendline('list ports')
    #ata_telnet_handler.expect('admin ready>')

main()