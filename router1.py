"""
Router 1 Script

This script simulates the behavior of Router 1 in a network. It reads routing information from a CSV file,
configures a socket connection with other routers, and processes packets with Time-to-Live (TTL) values.
The script contains functions for creating sockets, reading CSV files, generating forwarding tables,
and handling packet transmission and reception.

Helper Functions:
- create_socket(host, port): Creates and connects a socket to a specified host and port.
- read_csv(path): Reads a CSV file and returns its contents as a list of lists.
- find_default_gateway(table): Finds the default gateway from a routing table.
- generate_forwarding_table_with_range(table, router_number): Generates a forwarding table with IP ranges.
- ip_to_bin(ip): Converts an IP address to binary format.
- find_ip_range(network_dst, netmask): Finds the IP range based on network destination and netmask.
- bit_not(n, numbits=32): Computes the bitwise NOT operation.
- receive_packet(connection, max_buffer_size): Receives and decodes a packet from a socket connection.
- write_to_file(path, packet_to_write, send_to_router=None): Writes a packet to an output file.

Main Function:
- start_router1(): Configures sockets, reads routing tables and packets, and processes packets based on TTL and IP ranges.

Usage:
- Ensure the 'input' and 'output' directories exist in the script's directory.
- Place the router's table and packet CSV files in the 'input' directory.
- Run the script to simulate the behavior of Router 1.

Note: This script is part of a network simulation involving multiple routers.
"""


import glob
import socket
import sys
import time
import os
import traceback
from threading import Thread

# Helper Functions

def create_socket(host, port):
    """
    Creates and connects a socket to the specified host and port.

    Parameters:
    - host (str): The host IP address.
    - port (int): The port number.

    Returns:
    - socket: The created and connected socket.
    """
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect((host, port))
    except Exception as e:
        print(f"Connection Error to {host}:{port}. Error: {e}")
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


def generate_forwarding_table_with_range(table, router_number):
    """
    Generates a forwarding table with IP ranges.

    Parameters:
    - table (list): The routing table.
    - router_number (int): The router number.

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
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    decoded_packet = received_packet.strip()
    print("received packet", decoded_packet)
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


def start_router1():
    """
    Configures sockets, reads routing tables and packets, and processes packets based on TTL and IP ranges.

    Returns:
    - None
    """
    host = '127.0.0.1'
    port = 8001

    soc_to_router2 = create_socket('127.0.0.1', 8002)
    soc_to_router4 = create_socket('127.0.0.1', 8004)

    forwarding_table = read_csv('input/router_1_table.csv')
    default_gateway_port = find_default_gateway(forwarding_table) 
    forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table, 1)  # Changed the router_number to 1

    packets_path = 'input/packets.csv'
    packets = read_csv(packets_path)

    for packet in packets:
        # Unpack the packet
        sourceIP, destinationIP, payload, ttl = packet

        # Decrement the TTL
        new_ttl = int(ttl) - 1
        new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"    

        # Convert the destination IP into an integer for comparison
        destinationIP_bin = ip_to_bin(destinationIP)
        destinationIP_int = int(destinationIP_bin, 2)

        # Initialize send_to_router
        send_to_router = None

        # Check for a valid port based on IP range
        for row in forwarding_table_with_range:
            if row[4][0] <= destinationIP_int <= row[4][1]:
                send_to_router = row[3]
                print("sending to router: ",send_to_router)

        # If no valid port is found, set it to the default port
        if send_to_router == None:
            send_to_router = default_gateway_port
            print("send to router not found using default: ",default_gateway_port)


        if send_to_router == '127.0.0.1':
            print("OUT:", payload)
            write_to_file('out_router_1.txt', payload)

        # Check whether the TTL is greater than 0
        if new_ttl > 0:
            if send_to_router == '8002':
                print(f"sending packet {new_packet} to Router 2")
                soc_to_router2.send(new_packet.encode())
                write_to_file('sent_by_router_1.txt', new_packet, send_to_router='2')
            elif send_to_router == '8004':
                print(f"sending packet {new_packet} to Router 4")
                soc_to_router4.send(new_packet.encode())
                write_to_file('sent_by_router_1.txt', new_packet, send_to_router='4')
            
          
        else:
            print("DISCARD (TTL=0):", new_packet)
            write_to_file('discarded_by_router_1.txt', new_packet)

        time.sleep(1)

        


if __name__ == "__main__":
    files = glob.glob('output/*')
    #print(files)
    for f in files:
        os.remove(f)
    start_router1()