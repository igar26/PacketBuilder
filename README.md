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



Send Packet Utility:
Write a program which can construct a packet based on the following inputs from the user:
	•	Port to send packets from
	•	Type of packet to be sent (IPV4, IPVv6, ARP, TCP (with v4), UDP (with v6)) etc. You can define the enum for valid packet types and restrict user here 
	•	Based on above input for packet type, Request the packet specific params (for eg: for UDP you will need to request src and dst port, over and above the params like src ds tip needed for ipv4/ipv6)

Script should:
	•	Start sending packets form the given port with the constructed packet
	•	On doing a ctrl+c (sigkill), the script should stop sending packets
	•	Final count of packets sent should be displayed.

As a pointer, please take a look at the following python module.
https://scapy.net
 
