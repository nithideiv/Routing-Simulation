# Routing Simulation Project

This project simulates a network of routers using socket programming to understand how routers route traffic through the Internet. Each router in the network communicates with its neighboring routers based on a given topology and forwards packets according to its forwarding table.

## Overview

The project involves the following components:

1. **Network Topology**: The routers are interconnected based on a provided diagram, with each router represented as a separate program running on the same machine.

2. **Input Files**:
   - `packets.csv`: Contains packets that need to be routed. Each packet includes source IP, destination IP, payload, and TTL.
   - `router_#_table.csv` (for each router): Contains the router's forwarding table with network destination, netmask, gateway, and interface.

## Abstractions

- **Interfaces**: Simulated using ports, where each router's socket binds to represent its interface.
- **Forwarding Tables**: Each router parses its forwarding table to determine the next hop for received packets.
- **Routing Process**: Routers decrement TTL, forward packets, and handle cases of no match or TTL expiration.

## Instructions

1. **Understanding Input Files**: Study the purpose of each field in the input files, especially the forwarding tables.

2. **Setting Up Connections**: Determine which routers act as clients, servers, or both. Create sockets, bind them to ports, and establish connections following the topology diagram.

3. **Parsing Forwarding Tables**: Each router should parse its forwarding table to determine the next hop for incoming packets.

4. **Routing Process**:
   - Router 1 reads packets and initiates the routing process.
   - Routers receive, parse, and forward packets according to their forwarding tables.
   - Decrement TTL, handle forwarding, and manage cases of TTL expiration.

## Running the Network

1. Open separate terminal windows for each router (6 in total).
2. Run the router programs in reverse order based on the network topology (e.g., start with `router6.py`, then `router5.py`, and so on).

## Files

1. **Router Code** (`router#.py`): Total of 6 files, one for each router.
2. **Output Files** (`received_by_router_#.txt`, `discarded_by_router_#.txt`, `sent_by_router_#.txt`, and `out_router_#.txt`): There will be a total of 17 output files. 

