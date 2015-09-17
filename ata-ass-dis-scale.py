#!/usr/bin/env python

from __future__ import print_function
import sys
import xml.etree.ElementTree as ET
import threading
import time
import ipaddress

try:
    import pexpect
except:
    sys.stderr.write("You do not have 'pexpect' installed.\n")
    exit(1)

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

def session_end(handler):
    # This function disconnects from ATA cleanly
    handler.sendline('exit')
    handler.expect('Goodbye')

def clear_all_ports(handler, chassis_ip):
    # This function clears all port associations for a given chassis IP
    
    # Setup our varabiles
    clear_port_list = list()

    # Send the command to list all of the ports and grab the output
    handler.sendline('list ports')
    handler.expect('admin ready>')
    list_ports_output = handler.before.decode('utf-8', 'ignore')

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

def sync_veriwave_port_list(handler, sync_port_list):
    # This function synchronizes the ATA port configuration to the sync_port_list that is passed to it.

    # Setup our varabiles
    clear_port_list = list()
    add_port_list = list()

    # Send the command to list all of the ports and grab the output
    handler.sendline('list ports')
    handler.expect('admin ready>')
    list_ports_output = handler.before.decode('utf-8', 'ignore')

    # Parse the output into XML handler. Weirdness in string formatting is because the output includes the 'list ports' command we typed above.
    list_ports_xml = ET.fromstring('\n'.join(list_ports_output.split('\n')[1:]))

    # Collects the ports we need to add based off the XML output
    for sync_port in sync_port_list:
        sync_port_found = False
        for port in list_ports_xml.findall('./portList/port'):
            if sync_port.port_name == port.find('name').text:
                sync_port_found = True
        if not sync_port_found:
            add_port_list.append(sync_port)

    # Collects the ports we need to remove based off the XML output
    for port in list_ports_xml.findall('./portList/port'):
        port_found = False
        for sync_port in sync_port_list:
            if sync_port.port_name == port.find('name').text:
                port_found = True
        if not port_found:
            clear_port_list.append(port.find('name').text)


    # Iterate the clear port list and get rid of all the ports
    for clear_port in clear_port_list:
        handler.sendline('releasePort ' + clear_port)
        handler.expect('admin ready>', timeout=90)

    # Iterate the add port list and insert the new ports
    for add_port in add_port_list:
        handler.sendline('bindPort %s %s %s %s' % (add_port.port_name, add_port.chassis, add_port.slot_num, add_port.port_num))
        handler.expect('admin ready>', timeout=90)

    # Set the channels
    for sync_port in sync_port_list:
        handler.sendline('setChannel %s %s %s' % (sync_port.port_name, sync_port.frequency, sync_port.channel))
        handler.expect('admin ready>')

def purge_clients_ports(handler):
    # Relase all ports and clear out all the clients in the system

    handler.sendline('purge clients')
    handler.expect('admin ready>', timeout=90)
    handler.sendline('purge ports')
    handler.expect('admin ready>', timeout=90)

def purge_clients(handler):
    # Clear out all the clients in the system

    handler.sendline('purge clients')
    handler.expect('admin ready>', timeout=90)


def sync_veriwave_client_list(handler, sync_client_list):
    # This function synchronizes the ATA client configuration to the sync_client_list that is passed to it.

    # Setup out variables
    clear_client_list = list()
    add_client_list = list()

    # Send to command to list all of the clients and grab the output.
    handler.sendline('list clients')
    handler.expect('admin ready>')
    list_clients_output = handler.before.decode('utf-8', 'ignore')

    # Parse the output into XML handler.  Weirdness in string formatting is because the output includes the 'list clients' command we typed above.
    list_clients_xml = ET.fromstring('\n'.join(list_clients_output.split('\n')[1:]))

    # Collects the clients we need to add based off the XML output
    for sync_client in sync_client_list:
        sync_client_found = False
        for client in list_clients_xml.findall('./singleList/client'):
            if sync_client.name == client.find('name').text:
                sync_client_found = True
        if not sync_client_found:
            add_client_list.append(sync_client)

    # Collects the clients we need to remove based off the XML output
    for client in list_clients_xml.findall('./singleList/client'):
        sync_client_found = False
        for sync_client in sync_client_list:
            if sync_client.name == client.find('name').text:
                sync_client_found = True
        if not sync_client_found:
            clear_client_list.append(sync_client)

    # Iterate the clear client list and get rid of all the clients
    for clear_client in clear_client_list:
        handler.sendline('destroyClient ' + clear_client.name)
        handler.expect('admin ready>', timeout=90)

    # Iterate the add client list and insert the new clients
    for add_client in add_client_list:
        if add_client.ip_address == None:
            handler.sendline('createClient %s %s allowedPorts=%s' % (add_client.name, add_client.ssid, add_client.allowed_ports))
            handler.expect('admin ready>')
        else:
            handler.sendline('createClient %s %s allowedPorts=%s IP=%s subnetMask=%s gateway=%s' % (add_client.name, add_client.ssid, add_client.allowed_ports, add_client.ip_address.ip, add_client.ip_address.netmask, add_client.gateway))
            handler.expect('admin ready>')


def associate_veriwave_client_list(handler, client_list):
    # This functions looks at the clients on the chassis and associates them if they are both on the client list and currently disassociated.
    # This might not be needed.

    # Setup out variables
    associate_client_list = list()

    # Send to command to list all of the clients and grab the output.
    handler.sendline('list clients')
    handler.expect('admin ready>')
    list_clients_output = handler.before.decode('utf-8', 'ignore')

    # Parse the output into XML handler.  Weirdness in string formatting is because the output includes the 'list clients' command we typed above.
    list_clients_xml = ET.fromstring('\n'.join(list_clients_output.split('\n')[1:]))

    # Iterate through the list of clients to be associated and associate them
    for client in associate_client_list:
        handler.sendline('associateClient %s' % (client))
        handler.expect('admin ready>')


def ass_dis_manager(handler, client_list, da_per_10min, stop_event):
    # This function is intended to be run as a thread. It basically disassociates then associates every client in the client list in order with a delay.

    # Calculate the delay factor.
    if da_per_10min != 0:
        # Take the passed number and refactor it into disassociates/assoicates (da) per second.
        rate_in_da_per_sec = float(da_per_10min) / (10*60)
        # Inverse the rate to get seconds per disassociates/associates. Divide this by two so we spread out the assoication and disassociation
        delay_time = (1.0 / rate_in_da_per_sec) / 2.0

        while (not stop_event.is_set()):
            for client in client_list:
                # Disassociate the client.
                handler.sendline('disassociateClient %s' % (client.name))
                handler.expect('admin ready>')
                time.sleep(delay_time)
                # Assoicate the client
                handler.sendline('associateClient %s' % (client.name))
                handler.expect('admin ready>')
                time.sleep(delay_time)
                # Adding this so we don't have to wait until we have gone thru the entire list. That might take a while depending on the length of the list
                if stop_event.is_set():
                    break

def get_client_info(handler):
    # This function takes the handler and gets current information about client states on the chassis

    # Send the 'list clients' command and grab the output
    handler.sendline('list clients')
    handler.expect('admin ready>')
    list_clients_output = handler.before.decode('utf-8', 'ignore')

    # Parse the output into XML handler. Weirdness in string formatting is because the output includes the 'list clients' command we typed above.
    list_clients_xml = ET.fromstring('\n'.join(list_clients_output.split('\n')[1:]))

    # Grab the ready, idle, and disabled data out of the XML
    ready = list_clients_xml.find('./clientCount/ready').text
    idle = list_clients_xml.find('./clientCount/idle').text
    disabled = list_clients_xml.find('./clientCount/disabled').text
    busy = list_clients_xml.find('./clientCount/busy').text

    return ready, idle, disabled, busy


def main():
    # Setup some constants for the testbed. 
    ata_server_ip = '10.140.251.50'
    veriwave_chassis_ip = '10.140.251.53'
    admin_username = 'admin'
    client_ssid = '\'RnD5-Soak\''

    # Setup some initial varaibles
    veriwave_wireless_port_list = []
    veriwave_wired_port_list = []
    veriwave_client_list = []
    stop_da_event = threading.Event()
    da_per_10min = 0
    ip_addressing = 'DHCP'

    # Setup the session and log into ATA
    sys.stdout.write('**** Connecting to the chassis. This takes about 5 seconds.\n')
    handler = session_setup(ata_server_ip, admin_username)
    ass_dis_handler = session_setup(ata_server_ip, admin_username)

    # Setup the initial port list. This is simple and stupid. Pull all the ports from a given chassis and drop them into a list.
    sys.stdout.write('**** Preparing the chassis. This can take up to 60 seconds.\n')
    # Clear all current settings from the chassis to make sure we have a clean environment.
    purge_clients_ports(handler)
    #clear_all_ports(handler, veriwave_chassis_ip)
    veriwave_wireless_port_list, veriwave_wired_port_list = initialize_veriwave_port_list(handler, veriwave_chassis_ip, [36, 44, 149, 157])
    # Calcualte the time this action might take to do and let the user know
    port_add_time = 5 * (len(veriwave_wireless_port_list) + len(veriwave_wired_port_list))
    sys.stdout.write('**** Syncing the ports. This will take about %s seconds.\n' % (port_add_time))
    # Sync the settings to the ATA chassis.
    sync_veriwave_port_list(handler, veriwave_wired_port_list + veriwave_wireless_port_list)

    while True:
        # Display some status info
        clients_ready, clients_idle, clients_disabled, clients_busy = get_client_info(handler)
        sys.stdout.write('Clients Ready: %s   Clients Idle: %s   Clients Disabled: %s   Client Busy: %s\n' % (clients_ready,clients_idle,clients_disabled,clients_busy))
        # Determine the right way to display the IP settings
        if ip_addressing == None:
            disp_ip_addressing = 'DHCP'
        else:
            disp_ip_addressing = str(ip_addressing)
        # Display the main menu    
        sys.stdout.write('1. Change settings\t\t\t\t\tCurrent: IP Addressing - %s\n' % (disp_ip_addressing))
        sys.stdout.write('2. Modify target client count.\t\t\t\tCurrent: %s\n' % len(veriwave_client_list))
        sys.stdout.write('3. Modify target associate/disassociate rate. \t\tCurrent: %s\n' % (da_per_10min))
        sys.stdout.write('4. Refresh display.\n')
        sys.stdout.write('5. Clear config and exit.\n')
        sys.stdout.write('Please choose: ')
        
        # Read the users input and clean it up
        sys.stdout.flush()
        option = sys.stdin.readline()
        option = option.strip()

        # Modify current global seetings
        if option == '1':
            settings_options_clean = False
            old_ip_addressing = ip_addressing
            while not settings_options_clean:
                # Read the input for the option and clean it up
                sys.stdout.write('1. Change client IP Addressing method.\n')
                sys.stdout.write('2. Back\n')
                sys.stdout.write('Please choose: ')
                sys.stdout.flush()
                option = sys.stdin.readline()
                option = option.strip()
                if option == '1':
                    settings_options_clean = True
                    ip_option_clean = False
                    while not ip_option_clean:
                        # Display the change client IP addresssing method menu
                        sys.stdout.write('1. DHCP\n')
                        sys.stdout.write('2. Static\n')
                        sys.stdout.write('3. Back\n')
                        # Read the input for the option and clean it up
                        sys.stdout.write('Please choose: ')
                        sys.stdout.flush()
                        option = sys.stdin.readline()
                        option = option.strip()
                        if option == '1':
                            ip_option_clean = True
                            # Set the IP Addressing method to DHCP
                            ip_addressing = None
                            if ip_addressing == old_ip_addressing:
                                sys.stdout.write('**** The IP addressing scheme has not been changed. No modifications will occur.\n')
                            else:
                                sys.stdout.write('**** The IP addressing scheme has been changed. The client list will be rebuilt if needed.\n')
                                if len(veriwave_client_list) > 0:
                                    # Stop the associate disassociate threading
                                    stop_da_event.set()
                                    # Grab the old list length so we can replicate it.
                                    new_client_count = len(veriwave_client_list)
                                    # Clear out the current client list and purge the chassis
                                    veriwave_client_list = []
                                    sys.stdout.write('**** Purging the clients. This will take about 60 seconds.\n')
                                    parge_clients(handler)
                                    # Calculate the time it might take to do this and let the user know
                                    client_mod_time = int(.5 * abs(new_client_count))
                                    sys.stdout.write('**** Syncing the clients. This will take about %s seconds.\n' % (client_mod_time))
                                    # Pass the new value over the the client list modifier
                                    veriwave_client_list, veriwave_wireless_port_list = modify_veriwave_client_list(veriwave_client_list, veriwave_wireless_port_list, client_ssid, new_client_count, client_network = ip_addressing)
                                    # Sync the new client list to the ATA chassis.
                                    sync_veriwave_client_list(handler, veriwave_client_list)
                                    # Kick off the disassociate associate threading manager with the new client list
                                    stop_da_event = threading.Event()
                                    da_thread = threading.Thread(target = ass_dis_manager, args = (ass_dis_handler, veriwave_client_list, da_per_10min, stop_da_event))
                                    da_thread.start()

                        elif option == '2':
                            ip_option_clean = True
                            # Set the IP Addressing method to static and get the needed details
                            ip_add_input_clean = False
                            while not ip_add_input_clean:
                                sys.stdout.write('Enter the client network using prefix length notation. (Example 10.5.0.0/18): ')
                                sys.stdout.flush()
                                ip_address_network = sys.stdin.readline()
                                ip_address_network = ip_address_network.strip()
                                print (ip_address_network)
                                try:
                                    client_network = ipaddress.ip_network(ip_address_network)
                                    if len(list(client_network.hosts())) > 10:
                                        ip_add_input_clean = True
                                        ip_addressing = client_network
                                        if ip_addressing == old_ip_addressing:
                                            sys.stdout.write('**** The IP addressing scheme has not been changed. No modifications will occur.\n')
                                        else:
                                            sys.stdout.write('**** The IP addressing scheme has been changed. The client list will be rebuilt if needed.\n')
                                            if len(veriwave_client_list) > 0:
                                                # Stop the associate disassociate threading
                                                stop_da_event.set()
                                                # Grab the old list length so we can replicate it.
                                                new_client_count = len(veriwave_client_list)
                                                # Clear out the current client list and purge the chassis
                                                veriwave_client_list = []
                                                sys.stdout.write('**** Purging the clients. This will take about 60 seconds.\n')
                                                parge_clients(handler)
                                                # Calculate the time it might take to do this and let the user know
                                                client_mod_time = int(.5 * abs(new_client_count))
                                                sys.stdout.write('**** Syncing the clients. This will take about %s seconds.\n' % (client_mod_time))
                                                # Pass the new value over the the client list modifier
                                                veriwave_client_list, veriwave_wireless_port_list = modify_veriwave_client_list(veriwave_client_list, veriwave_wireless_port_list, client_ssid, new_client_count, client_network = ip_addressing)
                                                # Sync the new client list to the ATA chassis.
                                                sync_veriwave_client_list(handler, veriwave_client_list)
                                                # Kick off the disassociate associate threading manager with the new client list
                                                stop_da_event = threading.Event()
                                                da_thread = threading.Thread(target = ass_dis_manager, args = (ass_dis_handler, veriwave_client_list, da_per_10min, stop_da_event))
                                                da_thread.start()

                                    else:
                                        sys.stdout.write('This is not enough hosts. Please enter a subnet with more hosts.')
                                except:
                                    sys.stdout.write('This address seems to be invalid. Please try again.\n')
                            sys.stdout.write('**** New client network is %s. The default gateway for these clients will be %s. This subnet can handle up to %s clients.\n' % (client_network, list(client_network.hosts())[0], len(list(client_network.hosts())) - 10))
                        elif option == '3':
                            ip_option_clean = True
                            settings_options_clean = False
                        else:
                            sys.stdout.write('Invalid option. Please try again.\n')
                elif option == '2':
                    settings_options_clean = True
                else:
                    sys.stdout.write('Invalid option. Please try again.\n')
            #print (client_n)

        # Modify target client count option.
        elif option == '2':
            # Read the input for the new value and clean it up
            sys.stdout.write('Please enter new client count: ')
            sys.stdout.flush()
            new_client_count = sys.stdin.readline()
            new_client_count = int(new_client_count.strip())
            # Stop the associate/disassociate threader if it is running. If not then this shouldn't affect anything
            stop_da_event.set()
            # Calculate the time it might take to do this and let the user know
            client_mod_time = int(.5 * abs((len(veriwave_client_list) - new_client_count)))
            sys.stdout.write('**** Syncing the clients. This will take about %s seconds.\n' % (client_mod_time))
            # Pass the new value over the the client list modifier
            veriwave_client_list, veriwave_wireless_port_list = modify_veriwave_client_list(veriwave_client_list, veriwave_wireless_port_list, client_ssid, new_client_count, client_network = ip_addressing)
            # Sync the new client list to the ATA chassis.
            sync_veriwave_client_list(handler, veriwave_client_list)
            # Kick off the disassociate associate threading manager with the new client list
            stop_da_event = threading.Event()
            da_thread = threading.Thread(target = ass_dis_manager, args = (ass_dis_handler, veriwave_client_list, da_per_10min, stop_da_event))
            da_thread.start()
            # Some debugging
            #print (veriwave_client_list)

        # Modify target associate disassociate rate option.
        elif option == '3':
            # Read the intput for the new value and clean it up
            sys.stdout.write('Please enter new association/disassoication rate in a per client per 10 min value. For example, if you enter 1, each client will disassociate and reassociate once every 10 minutes: ')
            sys.stdout.flush()
            new_ass_dis_rate = sys.stdin.readline()
            da_per_10min = int(new_ass_dis_rate.strip())
            # Stop the current thread if it is running. If not that isn't an issue.
            stop_da_event.set()
            # Kick off the disassociate associate threading manager with the new rate
            stop_da_event = threading.Event()
            da_thread = threading.Thread(target = ass_dis_manager, args = (ass_dis_handler, veriwave_client_list, da_per_10min, stop_da_event))
            da_thread.start()

        # Refresh display option.
        elif option == '4':
            pass

        # Clean up and exit option
        elif option == '5':
            # Purge everything
            sys.stdout.write('**** Cleaning up the chassis. This can take up to 90 seconds.\n')
            stop_da_event.set()
            purge_clients_ports(handler)
            session_end(handler)
            session_end(ass_dis_handler)
            sys.stdout.write('Exiting!\n')
            # Exit program
            break
        # User did something stupid. Kick him back to the beginning
        else:
            sys.stdout.write('Invalid option. Please try again.\n')

    # Do some stuff to test things out.
    #ata_telnet_handler.sendline('list ports')
    #ata_telnet_handler.expect('admin ready>')

main()