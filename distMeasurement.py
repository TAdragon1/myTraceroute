import socket
import struct
import select
import time


DESTINATION_PORT_NUM = 33434

if __name__ == "__main__":
    #  Open file and read in destinations
    targets_file = open('targets.txt', 'r')
    destinations = []
    destination = 'val'

    while destination != '':
        destination = targets_file.readline()
        if destination != '':
            destinations.append(destination[:-1])
    targets_file.close()

    for destination in destinations:
        destination_ip_address = 0
        
        try:
            destination_ip_address = socket.gethostbyname(destination)
        except socket.gaierror:
            print('Error getting by host name')

        #  Debugs TODO remove
        print(f'Destination: {destination}')
        print(f'Destination ip address: {destination_ip_address}')

        # Create datagram
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Change headers
        ttl = 1
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # Include disclaimer
        msg = "Measurement for class project. Questions to student twa16@case.edu or professor mxr136@case.edu"
        payload	= bytes(msg	+ 'a'*(1472	- len(msg)),'ascii')

        # Send socket
        send_sock.sendto(payload, (destination_ip_address, DESTINATION_PORT_NUM))

        # Create raw socket to receive ICMP messages
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Windows shenanigans
        recv_sock.bind(('', 0))

        time_left = ttl*3
        started_select = time.time()
        ready = select.select([recv_sock], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []:
            print("Timed out")
            continue
        # TODO If don't respond 3x in a row, print error msg and move on to next destination

        # Get ICMP packet
        icmp_packet = recv_sock.recv(4000)
        print(len(icmp_packet))
        print(icmp_packet)

        # First 20 bytes are receiving IP header + 8 bytes for ICMP header
        time_to_live_start_index = 8
        time_to_live_end_index = 9
        time_to_live = ord(icmp_packet[time_to_live_start_index:time_to_live_end_index])
        print(time_to_live)
        
        protocol_start_index = 9
        protocol_end_index = 10
        protocol = ord(icmp_packet[protocol_start_index:protocol_end_index])
        print(protocol)
        
        source_address_start_index = 12
        source_address_end_index = 16
        source_ip = struct.unpack("BBBB", icmp_packet[source_address_start_index:source_address_end_index])
        print(source_ip)
        
        dest_address_start_index = 16
        dest_address_end_index = 20
        dest_ip = struct.unpack("BBBB", icmp_packet[dest_address_start_index:dest_address_end_index])
        print(dest_ip)
        
        # Then 20 bytes for sent IP header + 8 bytes for UDP header
        time_to_live_start_index = 8 + 28
        time_to_live_end_index = 9 + 28
        time_to_live = ord(icmp_packet[time_to_live_start_index:time_to_live_end_index])
        print(time_to_live)
        
        protocol_start_index = 9 + 28
        protocol_end_index = 10 + 28
        protocol = ord(icmp_packet[protocol_start_index:protocol_end_index])
        print(protocol)
        
        source_address_start_index = 12 + 28
        source_address_end_index = 16 + 28
        source_ip = struct.unpack("BBBB", icmp_packet[source_address_start_index:source_address_end_index])
        print(source_ip)
        
        dest_address_start_index = 16 + 28
        dest_address_end_index = 20 + 28
        dest_ip = struct.unpack("BBBB", icmp_packet[dest_address_start_index:dest_address_end_index])
        print(dest_ip)

        



        # TODO
        # Do ips match
        # If so, print ip's match

        # If not, print ip's don't match

        # repeat for port nums

        # print total/2 matching

        # TODO print num hops, RTT