import select
import socket
import struct
import time


DESTINATION_PORT_NUM = 33434


def do_ips_match(ip_string, ip_array):
    ip_num_array = ip_string.split('.')

    for i in range(4):
        if int(ip_num_array[i]) != ip_array[i]:
            return False

    return True


def do_ports_match(port_int, port):
    return port_int == port


def is_right_type(icmp_type):
    return icmp_type == 3


def is_right_code(icmp_code):
    return icmp_code == 3


def read_destinations():
    #  Open file and read in destinations
    targets_file = open('targets.txt', 'r')
    destinations = []
    at_end_of_file = False

    while not at_end_of_file:
        destination = targets_file.readline()
        
        if destination != '':
            destinations.append(destination[:-1])
        else:
            at_end_of_file = True
    
    targets_file.close()
    return destinations


if __name__ == "__main__":
    destinations = read_destinations()

    for destination in destinations:
        attempts = 0
        read_response = False

        while attempts < 3 and not read_response:
            destination_ip_address = 0

            try:
                destination_ip_address = socket.gethostbyname(destination)
            except socket.gaierror:
                print('Error getting by host name')

            # Create datagram
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            # send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Change headers
            ttl = 255
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            # Include disclaimer
            msg = "Measurement for class project. Questions to student twa16@case.edu or professor mxr136@case.edu"
            payload	= bytes(msg	+ 'a'*(1472	- len(msg)),'ascii')

            # Send socket
            send_sock.sendto(payload, (destination_ip_address, DESTINATION_PORT_NUM))
            time_sent = time.time()

            # Create raw socket to receive ICMP messages
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # Windows shenanigans
            recv_sock.bind(('', 0))

            timeout_sec = 10
            ready = select.select([recv_sock], [], [], timeout_sec)
            if ready[0] == []:
                attempts += 1
                if attempts == 3:
                    print(f'Destination: {destination}')
                    print("Timed out\n\n")

            else:
                rtt = time.time() - time_sent         
                print(f'Destination: {destination}')

                # Get ICMP packet
                icmp_packet = recv_sock.recv(2000)  # should be plenty
                read_response = True

                # Type
                icmp_type_start_index = 20
                icmp_type_end_index = 21
                icmp_type = ord(icmp_packet[icmp_type_start_index:icmp_type_end_index])
                print(f'Type: {icmp_type}')
                right_type = is_right_type(icmp_type)

                # Code
                code_start_index = 21
                code_end_index = 22
                code = ord(icmp_packet[code_start_index:code_end_index])
                print(f'Code: {code}')
                right_code = is_right_code(code)

                right_type_and_code = right_type and right_code

                # Time to Live
                time_to_live_start_index = 36
                time_to_live_end_index = 37
                time_to_live = ord(icmp_packet[time_to_live_start_index:time_to_live_end_index])
                # print(f'Time_to_live: {time_to_live}')
                num_hops = ttl - time_to_live

                # Check if match:
                dest_address_start_index = 16 + 28
                dest_address_end_index = 20 + 28
                dest_ip = struct.unpack("BBBB", icmp_packet[dest_address_start_index:dest_address_end_index])
                print(f'Sent ip address: {destination_ip_address}')
                print(f'Sent ip from payload: {dest_ip}')

                num_matched = 0
                matched_destination_ip = do_ips_match(destination_ip_address, dest_ip)
                if matched_destination_ip and right_type_and_code:
                    num_matched += 1
                print(f'Type, Code, and IPs match: {matched_destination_ip and right_type_and_code}')

                # Grab port from payload
                dest_port_start_index = 2 + 48
                dest_port_end_index = 4 + 48
                dest_port = struct.unpack("!H", icmp_packet[dest_port_start_index:dest_port_end_index])[0]
                print(f'Payload port: {dest_port}')

                matched_destination_port = do_ports_match(DESTINATION_PORT_NUM, dest_port)
                if matched_destination_port:
                    num_matched += 1
                print(f'Ports match: {matched_destination_port}')

                print(f'Num of matches: {num_matched}')

                print(f'Num hops: {num_hops}')
                print(f'RTT in ms: {rtt*1000}')

                bytes_included_from_original = len(icmp_packet) - 28
                print(f'Length of packet: {len(icmp_packet)}')
                print(f'Number of byes from send datagram: {bytes_included_from_original}\n\n')
