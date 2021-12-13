
#!/usr/bin/python3
import logging
import os
import argparse
import enum
import re
import ipaddress
from scapy.all import Ether, Padding, sniff, sendp, Raw, ARP, hexdump
from scapy.layers.l2  import LLC, Dot1Q
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

class Packet_Builder():

    def ptype(self):
        logging.info("Will modify the packet type based on the headers")
        if self._packet.haslayer(Dot1Q):
            self._packet.type=0x8100
            if self._packet.haslayer(ARP):
                self._packet[Dot1Q].type = 0x806
            if self._packet.haslayer(IP):
                self._packet[Dot1Q].type = 0x800
            if self._packet.haslayer(IPv6):
                self._packet[Dot1Q].type = 0x86dd
        else:
            self._packet.type=0x8000
            if self._packet.haslayer(ARP):
                self._packet.type = 0x806
            if self._packet.haslayer(IP):
                self._packet.type = 0x800
            if self._packet.haslayer(IPv6):
                self._packet.type = 0x86dd


    def __init__(self, packet_type, iface):
        self._packet_type = str(packet_type)
        self._packet = None
        self._vlanid = None
        self._lowvid = None
        self._highvid = None
        self._interface = iface
        self._srcmac = "00:00:00:00:00:01"
        self._dstmac = "00:00:00:00:00:01"
        self._srcip = "10.10.10.10"
        self._dstip = "20.20.20.20"
        self._dscp = 10
        self._ttl = 255
        self._srcprt = 8000
        self._dstprt = 8080
        self._tcpflags = 1
        self._srcipv6 = "1000::1"
        self._dstipv6 = "2000::1"
        self._fl = 10000
        self._nh = 59

        if self._packet_type == "L2_Ether":
            self._packet = self.get_ether_layer()
            self.ptype()
            self.run(self._packet)
        
        elif self._packet_type == "ARP":
            self._packet = self.get_ether_layer(arp=True)
            self.ptype()
            self.run(self._packet)
        
        elif self._packet_type == "L3_IP":
            self._packet = self.get_ether_layer()
            self._packet = self.build_l3_layer(self._packet, 255)
            self.ptype()
            self.run(self._packet)

        elif self._packet_type == "L3_TCP":
            self._packet = self.get_ether_layer()
            self._packet = self.build_l3_layer(self._packet, 6)
            self._packet = self.build_l3_tcp_or_udp_layer(self._packet, tcp=True)
            self.ptype()
            self.run(self._packet)
        
        elif self._packet_type == "L3_UDP":
            self._packet = self.get_ether_layer()
            self._packet = self.build_l3_layer(self._packet, 17)
            self._packet = self.build_l3_tcp_or_udp_layer(self._packet, tcp=False)
            self.ptype()
            self.run(self._packet)
        
        elif self._packet_type == "L3_IPv6":
            self._packet = self.get_ether_layer()
            self._packet = self.build_ipv6_l3_layer(self._packet, 59)
            self.ptype()
            self.run(self._packet)

        elif self._packet_type == "L3_IPv6_TCP":
            self._packet = self.get_ether_layer()
            self._packet = self.build_ipv6_l3_layer(self._packet, 6)
            self._packet = self.build_l3_ipv6_tcp_or_udp_layer(self._packet, tcp=True)
            self.ptype()
            self.run(self._packet)
        
        elif self._packet_type == "L3_IPv6_UDP":
            self._packet = self.get_ether_layer()
            self._packet = self.build_ipv6_l3_layer(self._packet, 17)
            self._packet = self.build_l3_ipv6_tcp_or_udp_layer(self._packet, tcp=False)
            self.ptype()
            self.run(self._packet)


    def check_valid_mac(self, mac):
        """
        This function takes a mac address string and checks if the mac address is valid or not
        """
        regex = ("^([0-9A-Fa-f]{2}[:-])" +
             "{5}([0-9A-Fa-f]{2})|" +
             "([0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4})$")

        p = re.compile(regex)
 
        # If the string is empty
        # return false
        if (mac == None):
            return ValueError
 
        # Return if the string
        # matched the ReGex
        if(re.search(p, mac)):
            return True
        return False

    def check_valid_ip(self, ip):
        """
        This function checks wehther the user passed valid ipv4 address we are letting the user
        pass only starting form 1.0.0.0 to 223.255.255.255
        """
        
        low = ipaddress.IPv4Address('1.0.0.0')
        high = ipaddress.IPv4Address('223.255.255.255')

        test = ipaddress.IPv4Address(ip)
        if low <= test <= high:
            return True
        return False

    def check_vlan_prio(self, vlan_prio):

        if int(vlan_prio) not in range(0, 7):
            # Not ready to raise any error, lets use some valid vlan id
            # raise ValueError("Vlan priority passed not to be valid")
            return True
        return False

    def check_length_of_input_field(self, min_len, max_len, parameter):

        if min_len <= len(parameter) <= max_len:
            return True
        return False


    def check_valid_dscp(self, dscp):

        if int(dscp) in range(0, 256):
            return True
        return False
    
    def check_valid_transport_prt(self, prt):

        if int(prt) in range(1, 65535):
            return True
        return False
    
    def check_valid_ipv6_address(self, ipv6addr):

        try:
            ipaddress.IPv6Network(ipv6addr)
            return True
        except ValueError:
            return False

    def check_valid_flow_label(self, fl):

        if int(fl) in range(0, 1048575):
            return True
        return False


    def get_ether_layer(self, arp=False):
        """
        This function forms a l2 packet and returns it, there are all fields are populated
        by user input else we will form a packert with default values, user can build different type of packets
        Example:
        Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x8000)
        Ether(src"00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x8100)/ Dot1Q(vlan=10, prio=3)
        Ether(src"00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x8100)/ Dot1Q(vlan=(10, 15), prio=3)
        Ether(src"00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff", type=0x806)/ ARP(op=1, psrc="10.10.10.10",
                          pdst="20.20.20.20", hwdst="00:00:00:00:00:00", hwsrc="00:00:00:00:00:01")
        Ether(src"00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff", type=0x8100)/ Dot1Q(vlan=10, prio=3)/ ARP(op=1, psrc="10.10.10.10",
        pdst="20.20.20.20", hwdst="00:00:00:00:00:00", hwsrc="00:00:00:00:00:01")
        Ether(src"00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff", type=0x8100)/ Dot1Q(vlan=(10, 20), prio=3)/ ARP(op=1, psrc="10.10.10.10",
        pdst="20.20.20.20", hwdst="00:00:00:00:00:00", hwsrc="00:00:00:00:00:01")
        """
        self._srcmac = input("Please input L2 Src mac address for building Ether packet if no "
                             "input is given default value of 00:00:00:00:00:01 is used:")
        logging.info("Check whether user had passed valid source mac address else take default value of 00:00:00:00:00:01")
        self._srcmac = self._srcmac if self.check_length_of_input_field(min_len=17, max_len=17, parameter=self._srcmac) and \
            self.check_valid_mac(self._srcmac) else "00:00:00:00:00:01"
        if not arp:
            self._dstmac = input("Please input L2 Dst mac address for building Ether packet if no "
                                 "input is given default value of 00:00:00:00:00:02 is used: ")
            logging.info("Check whether user had passed valid destination mac address else take default value of 00:00:00:00:00:02")
            self._dstmac = self._dst_mac if self.check_length_of_input_field(min_len=17, max_len=17, parameter=self._dstmac) and \
                self.check_valid_mac(self._dstmac) else "00:00:00:00:00:02"
        else:
            self._dstmac = "ff:ff:ff:ff:ff:ff"
        
        vlan_id_needed = input("Please input \"yes\" if a vlan header to be added else \"no\": ").lower()
        packet = Ether(src=self._srcmac, dst=self._dstmac)
        logging.info("Enter Vlan details for the packet")
        # Though scapy accepts any vlan number lets be sure to check this is vlan id
        if vlan_id_needed == "yes":
            self._vlanid = input("Please specify Dot1Q tag value to be used for the packet specify "
                                 "a single tag or range seperated by \"-\" if no input is given "
                                 "default tag value os 0 is used: ")
            vlan_prio = input("Please specify Dot1Q priority value to be used for the packet: ")
            if "-" not in self._vlanid:
                if int(self._vlanid) in range(0, 4096):
                    # Not ready to raise any error, lets use some valid vlan id
                    # raise ValueError("Vlan ID passed not to be valid")
                    packet /= Dot1Q(vlan=int(self._vlanid), prio=int(vlan_prio) if self.check_vlan_prio(vlan_prio) else 3)
                else:
                    packet /= Dot1Q(vlan=0, prio=vlan_prio if self.check_vlan_prio(vlan_prio) else 3)
            else:
                self._lowvid = self._vlanid.split("-")[0]
                self._highvid = self._vlanid.split("-")[1]
                if int(self._lowvid) in range(0, 4096) and int(self._highvid) in range(0, 4096):
                    packet /= Dot1Q(vlan=(int(self._lowvid), int(self._highvid)), prio=int(vlan_prio) if self.check_vlan_prio(vlan_prio) else 3)
                else:
                    packet /= Dot1Q(vlan=0, prio=vlan_prio if self.check_vlan_prio(vlan_prio) else 3)
        if arp:
            self._srcip = input("Please input L3 - SrcIP mac address for building ARP packet if no " 
                                "input is given default value of 10.10.10.10 is used: ")
            logging.info("Check whether user had passed valid source ip address "
                         "else take default value of 10.10.10.10")
            self._srcip = self._srcip if self.check_length_of_input_field(min_len=7, max_len=15, parameter=self._srcip) else "10.10.10.10"
            self._dstip = input("Please input L3 - DstIP address for building ARP packet if no "
                                "input is given default value of 20.20.20.20 is used: ")
            logging.info("Check whether user had passed valid destination ip address else take default value of 20.20.20.20")
            self._dstip = self._dstip if self.check_length_of_input_field(min_len=7, max_len=15, parameter=self._dstip) else "20.20.20.20"
            packet /= ARP(op=1, psrc=self._srcip if self.check_valid_ip(self._srcip) else "10.10.10.10",
                          pdst=self._dstip if self.check_valid_ip(self._dstip) else "20.20.20.20",
                          hwdst="00:00:00:00:00:00", hwsrc=self._srcmac if self.check_valid_mac(self._srcmac) else "00:00:00:00:00:01")
        return packet

    def build_l3_layer(self, packet, protocol):
        """
        L3 layer is built after Ether layer is filled
        """
        self._srcip = input("Please input L3 - SrcIP mac address for building IP packet if no "
                            "input is given default value of 10.10.10.10 is used:  ")
        logging.info("Check whether user had passed valid source ip address else take default value of 10.10.10.10")
        self._srcip = self._srcip if self.check_length_of_input_field(min_len=7, max_len=15, parameter=self._srcip) else "10.10.10.10"
        self._dstip = input("Please input L3 - DstIP address for building IP packet if no "
                            "input is given default value of 20.20.20.20 is used:  ")
        logging.info("Check whether user had passed valid destination ip address else take default value of 20.20.20.20")
        self._dstip = self._dstip if self.check_length_of_input_field(min_len=7, max_len=15, parameter=self._dstip) else "20.20.20.20"
        self._dscp = input("Please input L3 - TOS/DSCP value: ")
        logging.info("Check whether user had passed a valid value for DSCP else take default value as 10")
        self._dscp = self._dscp if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._dscp) else 10
        self._ttl = input("Please input L3 - TTL value for the packet: ")
        logging.info("Check whether user had passed a valid value for TTL else take default value as 255")
        self._ttl = self._ttl if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._ttl) else 255
        packet /= IP(src=self._srcip if self.check_valid_ip(self._srcip) else "10.10.10.10", \
                     dst=self._dstip if self.check_valid_ip(self._dstip) else "20.20.20.20", \
                     tos=int(self._dscp) if self.check_valid_dscp(self._dscp) else 10, 
                     ttl=int(self._ttl) if self.check_valid_dscp(self._ttl) else 255, proto=protocol)
        return packet

    def build_l3_tcp_or_udp_layer(self, packet, tcp):
        """
        TCP/UDP layer is built after Ether layer and L3 layer is filled
        """
        self._srcprt = input("Please input L3 - TCP/UDP srcport used to build packet if no "
                             "input is given defult value of 8000 is used: ")
        logging.info("Check whether user had passed valid TCP/UDP source port else take default value of 8000")
        self._srcprt = self._srcprt if self.check_length_of_input_field(min_len=1, max_len=5, parameter=self._srcprt) else 8000
        self._dstprt = input("Please input L3 - TCP/UDP srcport used to build packet if no "
                             "input is given defult value of 8080 is used: ")
        logging.info("Check whether user had passed valid TCP/UDP source port else take default value of 8080")
        self._dstprt = self._dstprt if self.check_length_of_input_field(min_len=1, max_len=5, parameter=self._dstprt) else 8080
        if tcp:
            self._tcpflags = input("Please input L3 - TCP Flag value to be used to build packet if no "
                                   "input is given default value of 2 is used: ")
            logging.info("Check whether user had passed valid TCP flag value else take default value of 2")
            self._tcpflags = self._tcpflags if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._tcpflags) else 2
            packet /= TCP(sport=int(self._srcprt) if self.check_valid_transport_prt(self._srcprt) else 8000, \
                          dport=int(self._dstprt) if self.check_valid_transport_prt(self._dstprt) else 8080, \
                          flags=int(self._tcpflags) if self.check_valid_dscp(self._dscp) else 2)
        else:
            packet /= UDP(sport=int(self._srcprt) if self.check_valid_transport_prt(self._srcprt) else 8000, \
                          dport=int(self._dstprt) if self.check_valid_transport_prt(self._dstprt) else 8080)
        return packet

    def build_ipv6_l3_layer(self, packet, protocol):
        """
        IPv6 layer is built after Ether Layer 
        """
        self._srcipv6 = input("Please input source ipv6 address used to build packet if no "
                             "input is given defult value of 1000::1 is used: ")
        logging.info("Check whether user had passed valid IPv6 source address else take default value of 1000::1")
        self._srcipv6 = self._srcipv6 if self.check_length_of_input_field(min_len=3, max_len=39, parameter=self._srcipv6) else "1000::1"
        self._dstipv6 = input("Please input destination ipv6 address used to build packet if no "
                             "input is given defult value of 2000::1 is used: ")
        logging.info("Check whether user had passed valid IPv6 destination address else take default value of 2000::1")
        self._dstipv6 = self._dstipv6 if self.check_length_of_input_field(min_len=3, max_len=39, parameter=self._dstipv6) else "2000::1"
        self._dscp = input("Please input IPv6 - TOS/DSCP value: ")
        logging.info("Check whether user had passed a valid value for DSCP else take default value as 10")
        self._dscp = self._dscp if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._dscp) else 10
        self._fl = input("Please input IPv6 flow label value: ")
        logging.info("Check whether user had passed a valid value for flow label else take default value as 10000")
        self._fl = self._fl if self.check_length_of_input_field(min_len=1, max_len=7, parameter=self._fl) else 10000
        self._ttl = input("Please input L3IPv6 - HLIM value for the packet: ")
        logging.info("Check whether user had passed a valid value for HLIM else take default value as 255")
        self._ttl = self._ttl if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._ttl) else 255
        packet /= IPv6(src=self._srcipv6 if self.check_valid_ipv6_address(self._srcipv6) else "1000::1", \
                       dst=self._dstipv6 if self.check_valid_ipv6_address(self._dstipv6) else "2000::1",
                       tc=int(self._dscp) if self.check_valid_dscp(self._dscp) else 10, 
                       fl=int(self._fl) if self.check_valid_flow_label(self._fl) else 10000,
                       hlim=int(self._ttl) if self.check_valid_dscp(self._ttl) else 255, nh=protocol)
        return packet
    
    def build_l3_ipv6_tcp_or_udp_layer(self, packet, tcp):
        """
        TCP/UDP layer is built after Ether layer and L3 layer is filled
        """
        self._srcprt = input("Please input L3 - TCP/UDP srcport used to build packet if no "
                             "input is given defult value of 8000 is used: ")
        logging.info("Check whether user had passed valid TCP/UDP source port else take default value of 8000")
        self._srcprt = self._srcprt if self.check_length_of_input_field(min_len=1, max_len=5, parameter=self._srcprt) else 8000
        self._dstprt = input("Please input L3 - TCP/UDP srcport used to build packet if no "
                             "input is given defult value of 8080 is used: ")
        logging.info("Check whether user had passed valid TCP/UDP source port else take default value of 8080")
        self._dstprt = self._dstprt if self.check_length_of_input_field(min_len=1, max_len=5, parameter=self._dstprt) else 8080
        if tcp:
            self._tcpflags = input("Please input L3 - TCP Flag value to be used to build packet if no "
                                   "input is given default value of 2 is used: ")
            logging.info("Check whether user had passed valid TCP flag value else take default value of 2")
            self._tcpflags = self._tcpflags if self.check_length_of_input_field(min_len=1, max_len=3, parameter=self._tcpflags) else 2
            packet /= TCP(sport=int(self._srcprt) if self.check_valid_transport_prt(self._srcprt) else 8000, \
                          dport=int(self._dstprt) if self.check_valid_transport_prt(self._dstprt) else 8080, \
                          flags=int(self._tcpflags) if self.check_valid_dscp(self._dscp) else 2)
        else:
            packet /= UDP(sport=int(self._srcprt) if self.check_valid_transport_prt(self._srcprt) else 8000, \
                          dport=int(self._dstprt) if self.check_valid_transport_prt(self._dstprt) else 8080)
        return packet
        
    def run(self, p):

        count = 0
        try:
            while KeyboardInterrupt:
                p.show()
                input("PE")
                sendp(p, iface=self._interface, count=1)
                count += 1
        except KeyboardInterrupt:
            if not p.haslayer(Dot1Q):
                print("Number of {} packets sent: {}".format(self._packet_type, count))
            else:
                if p.haslayer(Dot1Q):
                    if isinstance(p.vlan, tuple):
                        print("Number of {} packets sent: {}".format(self._packet_type, count*((p.vlan[1] - p.vlan[0])+1)))
                    elif isinstance(p.vlan, int):
                        print("Number of {} packets sent: {}".format(self._packet_type, count))


class Packet(enum.Enum):
    
    L2_Ether = 1
    ARP = 2
    L3_IP = 3
    L3_TCP = 4
    L3_UDP = 5
    L3_IPv6 = 6
    L3_IPv6_UDP = 7
    L3_IPv6_TCP = 8

ap = argparse.ArgumentParser()
ap.add_argument("packet_type", help="Do any valid sellection from the below availble options \n\
                  1 - L2_Ether packet, \n\
                  2 - ARP packet, \n\
                  3 - L3_IP packet, \n\
                  4 - L3_TCP packet, \n\
                  5 - L3_UDP packet, \n\
                  6 - L3_IPv6 packet, \n\
                  7 - L3_IPv6_TCP packet, \n\
                  8 - L3_IPv6_UDP packet", type=int)
ap.add_argument("eth_interface", help="pass which eth interface should be used to send packets", type=str)
args = ap.parse_args()

y = Packet(args.packet_type)
Packet_Builder(y.name, args.eth_interface)