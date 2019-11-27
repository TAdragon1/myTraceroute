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
        #send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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

        # Assuming icmp_packet[x:x+1] represents the two-bytes port num in a packet
        time_to_live = ord(icmp_packet[8:9])
        print(time_to_live)

        dest_ip = struct.unpack("BBBB", icmp_packet[0:4])[0]
        print(dest_ip)

        dest_ip = struct.unpack("BBBB", icmp_packet[4:8])[0]
        print(dest_ip)
        
        dest_ip = struct.unpack("BBBB", icmp_packet[8:12])[0]
        print(dest_ip)
        
        dest_ip = struct.unpack("BBBB", icmp_packet[12:16])[0]
        print(dest_ip)
        
        dest_ip = struct.unpack("BBBB", icmp_packet[16:20])[0]
        print(dest_ip)
        
        dest_ip = struct.unpack("BBBB", icmp_packet[20:24])[0]
        print(dest_ip)

        print("\n")
        for x in range(25):
            dest_ip = ord(icmp_packet[x])
            print(dest_ip)

        # TODO
        # Do ips match
        # If so, print ip's match

        # If not, print ip's don't match

        # repeat for port nums

        # print total/2 matching

        # TODO print num hops, RTT