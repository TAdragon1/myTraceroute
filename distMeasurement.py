import socket
import struct


destination_port_num = 33434

if __name__ == "__main__":
    #  Open file and read in destinations
    targets_file = open('targets.txt', 'r')
    destinations = []
    destination = 'val'

    while destination != '':
        destination = targets_file.readline()
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
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Change headers
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)

        # Include disclaimer
        msg = "Measurement for class project. Questions to student twa16@case.edu or professor mxr136@case.edu"
        payload	= bytes(msg	+ 'a'*(1472	- len(msg)),'ascii')

        # Send socket
        send_sock.sendto(payload, (destination_ip_address, destination_port_num))

        # Create raw socket to receive ICMP messages
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Windows shenanigans
        recv_sock.bind(('', 0))

        # TODO use select or poll before reading so servers that don't respond won't error
        # If don't respond 3x in a row, print error msg and move on to next destination

        # Get ICMP packet
        icmp_packet = recv_sock.recv(4000)
        print(len(icmp_packet))
        print(icmp_packet)

        # Assuming icmp_packet[x:x+1] represents the two-bytes port num in a packet
        dest_ip = struct.unpack("!H", icmp_packet[16:20])[0]
        print(dest_ip)

        # x is what for port number
        port_from_packet = struct.unpack("!H", icmp_packet[x:x+2])[0]

        # If only needing a single byte
        port_from_packet = ord(icmp_packet[x])


        # TODO
        # Do ips match
        # If so, print ip's match

        # If not, print ip's don't match

        # repeat for port nums

        # print total/2 matching

        # TODO print num hops, RTT