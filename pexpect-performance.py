#!/usr/bin/env python

from __future__ import print_function
import threading
import pexpect
import ipaddress
import sys
import xml.etree.ElementTree as ET
import time

class VeriWavePort(object):
    # Class for storing information about VeriWave ports

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
    # Class for storing information about VeriWave clients

    def __init__(self, name, ssid, allowed_ports, ip_address=None, gateway=None):
        self.name = name
        self.ssid = ssid
        self.allowed_ports = allowed_ports
        self.ip_address = ip_address
        self.gateway = gateway

    def __repr__(self):
        return "\nname: %s\nssid: %s\nallowed ports: %s ip address: %s gateway: %s\n" % (self.name, self.ssid, self.allowed_ports, self.ip_address, self.gateway)
    def __str__(self):
        return "\nname: %s\nssid: %s\nallowed ports: %s ip address: %s gateway: %s\n" % (self.name, self.ssid, self.allowed_ports, self.ip_address, self.gateway)

def session_setup(ata_ip, ata_user,debug=False):
    # This function logs into the ATA and sets some parameters we want to user for the session

    # Log into the ATA and send the username
    ata_telnet_handler = pexpect.spawn('telnet ' + ata_ip)
    if debug:
        ata_telnet_handler.logfile = sys.stdout
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

def initialize_veriwave_port_list(handler, chassis, channel_list):
    # This function initializes a list of VeriWavePort objects by iterating through a list of channels

    # Send the 'getChassisInfo' command to extract information about the currently installed cards
    handler.sendline('getChassisInfo ' + chassis)
    handler.expect('admin ready>', timeout=160)

    # Grab the output of the command and parse the XML
    get_chassis_info_output = handler.before.decode('utf-8', 'ignore')
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
                # Build the first part of the port name, w or e depending on if it is wireless or ethernet.
                port_name = ''
                if port_type == 'WLAN':
                    port_name += 'w'
                else:
                    port_name += 'e'
                # Now add the slot and port number to the end.
                port_name += slot.tag.split('_')[1]
                port_name += port.tag.split('_')[1]
                # Also grab the slot number and port number so we have them in interger form.
                slot_num = int(slot.tag.split('_')[1])
                port_num = int(port.tag.split('_')[1])
                # Set the channel from the channel list passed to the function. Iterate through the list evenly. Roll back to the beginning when we hit the end.
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

def modify_veriwave_client_list(client_list, port_list, ssid, target_count, client_network=None):
    # This function adds or subtracts clients from the port and client lists and returns the new list. This function DOES NOT synchronize with the chassis.

    # Setup some variables
    ip_host_offset = 10

    # We have to check if the new client network setting matches the current client network setting in the list
    if len(client_list) > 0:
        # The client list currently has some items. We should cehck to see if what we are passing from a network perspective matches to old value.
        if client_network == None:
            # The passed client network value is equivelent to DHCP.
            if client_list[0].ip_address != None:
                # It looks like the client network value passed to this function doesn't align with what is currently set let's return the same value
                return client_list, port_list
        else:
            if client_list[0].gateway != list(client_network.hosts())[0]:
                # This would indicate that default gateway assigned to the first client in the client list doesn't match the first address in the client network passed
                # This is no good so we are going to return unchanged values and exit
                return client_list, port_list
            elif client_list[0].ip_address.ip != list(client_network.hosts())[0] + ip_host_offset:
                # This would seem to indicate that the first host in the client doesn't match the first IP address we were going to use from client network
                # This is no good so we are going to return unchanged values and exit
                return client_list, port_list
            elif target_count > len(list(client_network.hosts())) - 1 - ip_host_offset:
                # This would seem to indicate that the targetted number of hosts is greater than the number of hosts availible. Note that we subtract 1 for the gateway and ip host offset
                # This is no good so we are going to return unchanged values and exit
                return client_list, port_list 

    # Start by grabing the netmask and the default gateway
    if client_network != None:
        client_netmask = str(client_network).split('/')[1]
        client_gateway = list(client_network.hosts())[0]

    # Find the position where we last added a client to the port list. This is important so we maintain even distribution accross the ports.
    max_client_count = len(port_list[0].clients)
    add_client_port_iterator = 0

    for i, port in enumerate(port_list):
        if len(port.clients) < max_client_count:
            add_client_port_iterator = i
            break

    # If the target client count is greater than the current client count then add until they are equal
    while len(client_list) < target_count:
        # Build the client name. Client names will be a combination of a unique client ID and the port number it is locked to. Example c10_w23
        client_name = 'c' + str("%06d" % len(client_list)) + '_'
        client_name += port_list[add_client_port_iterator].port_name

        # Add the new client name into the port object it will be associated with
        port_list[add_client_port_iterator].clients.append(client_name)

        if client_network == None:
            # Append the new client object to the end of the client list without IP address information (DHCP)
            client_list.append(VeriWaveClient(client_name, ssid, [port_list[add_client_port_iterator].port_name]))
        else:
            # Append the new client object to the end of the client list with an iterated IP address (Static)
            client_interface = ipaddress.IPv4Interface(str(list(client_network.hosts())[len(client_list)+ip_host_offset]) + '/' + client_netmask)
            client_list.append(VeriWaveClient(client_name, ssid, [port_list[add_client_port_iterator].port_name], client_interface, client_gateway))

        # Deal with properly iterating the port list insertion point for the next client to be added
        add_client_port_iterator += 1
        if add_client_port_iterator >= len(port_list):
            add_client_port_iterator = 0

    # If the target client count is less than the current client count then subtract until they are equal
    while len(client_list) > target_count:
        # Grab the name of the last client in the client list
        remove_client_name = client_list[-1].name
        # Find that client in the port list objects and remove it
        for port in port_list:
            if remove_client_name in port.clients:
                port.clients.remove(remove_client_name)
        client_list.pop()

    # Return our new client list and port list
    return client_list, port_list

def ass_dis_manager(handler, client_list, da_per_10min, stop_event):
    # This function is intended to be run as a thread. It basically disassociates then associates every client in the client list in order with a delay.

    # Calculate the delay factor.
    if da_per_10min != 0:
        # Take the passed number and refactor it into disassociates/assoicates (da) per second.
        rate_in_da_per_sec = float(da_per_10min) / (10*60)
        # Inverse the rate to get seconds per disassociates/associates. Divide this by two so we spread out the assoication and disassociation
        delay_time = (1.0 / rate_in_da_per_sec) / 2.0

        handler_index = 0

        print ('Delay Time: %s' % (delay_time))

        while (not stop_event.is_set()):
            for client in client_list:
                # Disassociate the client.
                handler[handler_index].sendline('disassociateClient %s' % (client.name))
                #handler.expect('admin ready>')
                time.sleep(delay_time)
                # Assoicate the client
                handler[handler_index].sendline('associateClient %s' % (client.name))
                #handler.expect('admin ready>')
                time.sleep(delay_time)
                handler_index += 1
                if handler_index >= len(handler):
                    handler_index = 0
                # Adding this so we don't have to wait until we have gone thru the entire list. That might take a while depending on the length of the list
                if stop_event.is_set():
                    break

def main():
    # Setup some constants for the testbed. 
    ata_server_ip = '10.140.251.50'
    veriwave_chassis_ip = '10.140.251.53'
    admin_username = 'admin'
    client_ssid = '\'RnD5-Soak\''
    ip_addressing = ipaddress.IPv4Network('10.5.0.0/18')
    new_client_count = 2500

    stop_da_event = threading.Event()
    da_per_10min = 5000000
    veriwave_client_list = []
    ass_dis_handler = []

    handler = session_setup(ata_server_ip, admin_username)
    for x in range(0,29):
        ass_dis_handler.append(session_setup(ata_server_ip, admin_username))

    veriwave_wireless_port_list, veriwave_wired_port_list = initialize_veriwave_port_list(handler, veriwave_chassis_ip, [36, 44, 149, 157])
    veriwave_client_list, veriwave_wireless_port_list = modify_veriwave_client_list(veriwave_client_list, veriwave_wireless_port_list, client_ssid, new_client_count, client_network = ip_addressing)


    print (veriwave_wireless_port_list)
    print (veriwave_client_list)
    da_thread = threading.Thread(target = ass_dis_manager, args = (ass_dis_handler, veriwave_client_list, da_per_10min, stop_da_event))
    da_thread.start()

main()