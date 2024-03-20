"""
Router 2 Server Script

This script serves as a server for Router 2 in a network simulation. It establishes a socket connection, 
reads routing information and packet data from CSV files, and processes incoming packets based on TTL and IP ranges.
The script contains functions for creating sockets, reading CSV files, generating forwarding tables,
and handling packet transmission and reception.

Helper Functions:
- create_socket(host, port, is_server=False): Creates and configures a socket for either server or client use.
- read_csv(path): Reads a CSV file and returns its contents as a list of lists.
- find_default_gateway(table): Finds the default gateway from a routing table.
- generate_forwarding_table_with_range(table): Generates a forwarding table with IP ranges.
- ip_to_bin(ip): Converts an IP address to binary format.
- find_ip_range(network_dst, netmask): Finds the IP range based on network destination and netmask.
- ip_in_range(ip, ip_range): Checks if an IP address is within a specified range.
- bit_not(n, numbits=32): Computes the bitwise NOT operation.
- receive_packet(connection, max_buffer_size): Receives and decodes a packet from a socket connection.
- write_to_file(path, packet_to_write, send_to_router=None): Writes a packet to an output file.

Processing Thread Function:
- processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, soc_to_router3, soc_to_router4, max_buffer_size=5120): 
  Handles packet processing in a separate thread.

Main Function:
- start_server(): Initializes the server, establishes connections, and starts processing threads.

Usage:
- Ensure the 'input' and 'output' directories exist in the script's directory.
- Place the router's table CSV file in the 'input' directory.
- Run the script to start Router 2 server.

Note: This script is part of a network simulation involving multiple routers.
"""


import socket
import sys
import time
import traceback
from threading import Thread

# Helper Functions
rnumber=2

def create_socket(host, port, is_server=False):
    """
    Creates and configures a socket for either server or client use.

    Parameters:
    - host (str): The host IP address.
    - port (int): The port number.
    - is_server (bool): Specifies whether the socket is for server use. Default is False for client use.

    Returns:
    - socket: The created and configured socket.
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if is_server:
        soc.bind((host, port))
        soc.listen(5)
        print("Socket now listening")
    else:
        try:
            print(f"Attempting to connect to {host}:{port}")
            soc.connect((host, port))
            print("Connected to", host, "on port", port)
        except Exception as e:
            print(f"Connection Error to {port}: {e}")
            sys.exit()

    return soc


def read_csv(path):
    """
    Reads a CSV file and returns its contents as a list of lists.

    Parameters:
    - path (str): The path to the CSV file.

    Returns:
    - list: A list of lists representing the CSV file contents.
    """
    table_file = open(path, "r")
    table = table_file.readlines()
    table_list = []
    for line in table:
        elements = [element.strip() for element in line.split(',')]
        table_list.append(elements)
    table_file.close()
    return table_list


def find_default_gateway(table):
    """
    Finds the default gateway from a routing table.

    Parameters:
    - table (list): The routing table.

    Returns:
    - str: The default gateway IP address.
    """
    for row in table:
        if row[0] == '0.0.0.0':
            return row[3]


def generate_forwarding_table_with_range(table):
    """
    Generates a forwarding table with IP ranges.

    Parameters:
    - table (list): The routing table.

    Returns:
    - list: A new forwarding table with IP ranges.
    """
    new_table = []
    for row in table:
        if row[0] != '0.0.0.0':
            network_dst_string = row[0]
            netmask_string = row[1]
            network_dst_bin = ip_to_bin(network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            ip_range = find_ip_range(int(network_dst_bin, 2), int(netmask_bin, 2))
            new_row = [network_dst_string, netmask_string, row[2], row[3], ip_range]
            new_table.append(new_row)
    return new_table


def ip_to_bin(ip):
    """
    Converts an IP address to binary format.

    Parameters:
    - ip (str): The IP address.

    Returns:
    - str: The binary representation of the IP address.
    """
    ip_octets = ip.split('.')
    ip_bin_string = ""
    for octet in ip_octets:
        int_octet = int(octet)
        bin_octet = bin(int_octet)[2:]
        bin_octet_string = bin_octet.zfill(8)
        ip_bin_string += bin_octet_string
    ip_int = int(ip_bin_string, 2)
    return bin(ip_int)


def find_ip_range(network_dst, netmask):
    """
    Finds the IP range based on network destination and netmask.

    Parameters:
    - network_dst (int): The network destination in decimal format.
    - netmask (int): The netmask in decimal format.

    Returns:
    - list: A list containing the minimum and maximum IP addresses in the range.
    """
    bitwise_and = network_dst & netmask
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    max_ip = min_ip + compliment
    return [min_ip, max_ip]


def ip_in_range(ip, ip_range):
    """
    Checks if an IP address is within a specified range.

    Parameters:
    - ip (str): The binary representation of the IP address.
    - ip_range (list): A list containing the minimum and maximum IP addresses in the range.

    Returns:
    - bool: True if the IP address is within the specified range, False otherwise.
    """
    return ip_range[0] <= int(ip, 2) <= ip_range[1]

def bit_not(n, numbits=32):
    """
    Computes the bitwise NOT operation.

    Parameters:
    - n (int): The number to perform bitwise NOT on.
    - numbits (int): The number of bits.

    Returns:
    - int: The result of the bitwise NOT operation.
    """
    return (1 << numbits) - 1 - n


def receive_packet(connection, max_buffer_size):
    """
    Receives and decodes a packet from a socket connection.

    Parameters:
    - connection: The socket connection.
    - max_buffer_size (int): The maximum buffer size for receiving the packet.

    Returns:
    - list: A list representing the decoded packet.
    """
    received_packet = connection.recv(max_buffer_size).decode().rstrip()
    if not received_packet:
        return None  # Return None for empty packets
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    decoded_packet = received_packet.strip()
    print("received packet", decoded_packet)
    write_to_file(f'received_by_router_{rnumber}.txt', decoded_packet)
    packet = decoded_packet.split(',')
    return packet


def write_to_file(path, packet_to_write, send_to_router=None):
    """
    Writes a packet to an output file.

    Parameters:
    - path (str): The path to the output file.
    - packet_to_write (str): The packet to write to the file.
    - send_to_router (str): The router number to append to the output.

    Returns:
    - None
    """
    out_file = open(f"output/{path}", "a")
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + f" to Router {send_to_router}\n")
    out_file.close()


def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, soc_to_router3, soc_to_router4, max_buffer_size=5120):
    """
    Handles packet processing in a separate thread.

    Parameters:
    - connection: The socket connection.
    - ip (str): The IP address of the connected client.
    - port (int): The port number of the connected client.
    - forwarding_table_with_range (list): The forwarding table with IP ranges.
    - default_gateway_port (str): The default gateway port.
    - soc_to_router3: The socket connection to Router 3.
    - soc_to_router4: The socket connection to Router 4.
    - max_buffer_size (int): The maximum buffer size for receiving packets.

    Returns:
    - None
    """
    while True:
        packet = receive_packet(connection, max_buffer_size)

        if not packet or not any(packet):
            break

        if len(packet) < 4:
            print(f"Invalid packet format: {packet}")
            continue

        sourceIP, destinationIP, payload, ttl = packet

        if int(ttl) > 0:
            new_ttl = int(ttl) - 1
            new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"

            destinationIP_bin = ip_to_bin(destinationIP)
            destinationIP_int = int(destinationIP_bin, 2)

            send_to_router = None
            for row in forwarding_table_with_range:
                if row[4][0] <= destinationIP_int <= row[4][1]:
                    send_to_router = row[3]

            if send_to_router is None:
                send_to_router = default_gateway_port


            if send_to_router == '127.0.0.1':
                print("OUT:", payload)
                write_to_file(f'out_router_{rnumber}.txt', payload)

            # Check whether the TTL is greater than 0
            if new_ttl > 0:
         
                if send_to_router == '8003':
                    print(f"sending packet {new_packet} to Router 3")
                    soc_to_router3.send(new_packet.encode())
                    write_to_file(f'sent_by_router_{rnumber}.txt', new_packet, send_to_router='2')
                elif send_to_router == '8004':
                    print(f"sending packet {new_packet} to Router 4")
                    soc_to_router4.send(new_packet.encode())
                    write_to_file(f'sent_by_router_{rnumber}.txt', new_packet, send_to_router='4')
                
             
            else:
                print("DISCARD (TTL=0):", new_packet)
                write_to_file(f'discarded_by_router_{rnumber}.txt', new_packet)

            time.sleep(1)


def start_server():
    """
    Initializes the server, establishes connections, and starts processing threads.

    Returns:
    - None
    """
    host = '127.0.0.1'
    port = 8002
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")
    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()
    soc.listen(5)
    print("Socket now listening")

    forwarding_table = read_csv('input/router_2_table.csv')
    default_gateway_port = find_default_gateway(forwarding_table)
    forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

    # Create socket for router 3
    soc_to_router5 = create_socket('127.0.0.1', 8003)
    # Create socket for router 4
    soc_to_router6 = create_socket('127.0.0.1', 8004)

    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)
        try:
            Thread(target=processing_thread, args=(connection, ip, port, forwarding_table_with_range, default_gateway_port, soc_to_router5, soc_to_router6)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

if __name__ == "__main__":
    start_server()