# PacketBuilder
We assume scapy and python untilitiy are installed in the system.

-This utility is used to generate python packets, valid inputs for this file is any number from 1 to 8 for different types of packet to be built and eth port from  which the packet should be sent

                  1 - L2_Ether packet
                  2 - ARP packet
                  3 - L3_IP packet
                  4 - L3_TCP packet
                  5 - L3_UDP packet
                  6 - L3_IPv6 packet
                  7 - L3_IPv6_TCP packet
                  8 - L3_IPv6_UDP packet
                  
- This utility asks for user input to build diffrent packets, if user does not pass the input we use default values to build the packet.
- COMMAND to run: sudo -E python packet_build_send.py 3 "en1"
- Output is just a interger of how many packets are sent from the eth port.

