# Imports
import socket
import struct

# Create datagram
my_socket = socket.SOCK_DGRAM

# Change headers
my_socket.setsockopt()                                              # TODO how?

# Include disclaimer
msg = "Measurement for class project. Questions to student twa16@case.edu or professor mxr136@case.edu"
payload = bytes(msg + 'a'*(1472 - len(msg), 'ascii'))

# TODO define dest_ip and dest_port
# Send socket
my_socket.sendto(payload, (dest_ip, dest_port))



# Create raw socket to receive ICMP messages
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Windows shenanigans
recv_sock.bind("", 0)

# Get ICMP packet
icmp_packet = recv_sock.recv(max_length_of_expected_packet)         # TODO define max_length_of_expected_packet

# Assuming icmp_packet[x:x+1] represents the two-bytes port num in a packet
port_from_packet = struct.unpack("!H", icmp_packet[x:x+2])[0]       # TODO define x

# If only needing a singly byte
port_from_packet = ord(x)

