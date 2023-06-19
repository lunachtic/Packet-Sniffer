#Packet sniffer in Python
#Linux based implementation

'''
import socket

#create an INET raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

#receive a packet
while True:
	print s.recvfrom(65565)

'''
import socket, sys, textwrap
from struct import *

#create an INET, STREAMing socket
def main():
	try:
		#s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
		s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		#AF_INET is the family of sockets created - TCP or UDP
		#Socket type is SOCK_RAW instead of SOCK_STREAM or SOCK_DGRAM
		#Socket protocol specified is IP-PROTO_<TCP/UDP/ICMP>
	except socket.error as msg:
		print ('Socket could not be created. Error Code : '+str(msg[0])+'Message '+msg[1] )
		sys.exit
		count = 0
		print ('Getting a packet\n\n')
	filter = int(input('Select a filter.\nIPv4, type 1;\nIPv6, type 2;\n\nNúmero escolhido: '))
	#get a packet 
	while True:
		packet = s.recvfrom(65565) #keep in mind that this port binding won't work in Windows
				   #Windows uses a Winsock API hook or Winpcap driver for sockets
		#socket.recvfrom(buffersize,[flags]) gets the data from the socket. O/P - (string,address)

		print ('Packet Received:'+str(packet)+'\n\n')
		count= count+1
		#packet string from tuple
		
		#-------------------L2 Information-------------------------------------
		eth = Ethernet(packet)
		if(filter==1):
			if eth.proto != 8:
				continue
		elif filter == 2:
			if eth.proto != 56710:
				continue

		print ('\nEthernet Frame:')
		print ('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

	
  	    #-------------------IP HEADER EXTRACTION--------------------------------
		# IPv4
		if eth.proto == 8:
			ipv4 = IPv4(eth.data)
			print('IPv4 Packet:')
			print('Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
			print('Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

        	# ICMP
			if ipv4.proto == 1:
				icmp = ICMP(ipv4.data)
				print('ICMP Packet:')
				print('Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
				print('ICMP Data:')
				print(format_multi_line(icmp.data))

			# TCP
			elif ipv4.proto == 6:
				tcp = TCP(ipv4.data)
				printTCP(tcp)

			# UDP
			elif ipv4.proto == 17:
				udp = UDP(ipv4.data)
				printUDP(udp)

			# Other IPv4
			else:
				print('Other IPv4 Data:')
				print(format_multi_line(ipv4.data))

		elif eth.proto == 56710:
			ipv6 = IPv6(eth.data)
			print('IPv6 Packet:')
			print('Version: {}, Traffic Class: {}, Flow Label: {},'.format(ipv6.version, ipv6.traffic_class,
                                                                                   ipv6.flow_label))
			print('Payload Length: {}, Next Header: {}, Hop Limit: {}'.format(ipv6.payload_length,
                                                                                      ipv6.next_header, ipv6.hop_limit))
			print('Source Address: {}, Destination Address: {}'.format(ipv6.source_address,
                                                                               ipv6.destination_address))
			next_header = ipv6.next_header
			extension_header = ipv6.extension_header
			identifyHeaderNPrint(next_header, extension_header)
		else:
			print('Ethernet Data:')
			print(format_multi_line(eth.data))
                        
def Ethernet(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]

def AuthenticationHeader(self, raw_data):
        self.next_header = raw_data[0:1]
        self.length = raw_data[1:2]
        self.reserved = raw_data[2:4]
        self.spi = raw_data[4:8]
        self.sequence = raw_data[8:12]
        self.auth_data = raw_data[12:16]

def HopByHop(self, raw_data):
        self.next_header, self.heLength = struct.unpack('! B B', raw_data[:2])
        self.data = raw_data[2:]

def DestinationOptions(self, raw_data):
        self.next_header, self.heLength = struct.unpack('! B B', raw_data[:2])
        self.data = raw_data[2:]

def FragmentHeader(self, raw_data):
        self.next_header = raw_data[0:1] #8 bits
        self.reserved = raw_data[1:2] #8 bits
        self.fragment_offset = raw_data[2:4] << 13 #13 bits
        self.reserved2 = (raw_data[2:4] >> 3) << 1 #2 bits
        self.m = raw_data[2:4] >> 1 #1 bit
        self.id_number = raw_data[4:] #32 bits

def EncapsulationSecurityPayload(self, raw_data):
        self.spi = raw_data[0:4]
        self.sequence = raw_data[4:8]
        self.payload_data = raw_data[8:13]
        self.padding = raw_data[13:18]
        self.pad_size = raw_data[18:19]
        self.next_header = raw_data[19:20]
        self.auth_data = raw_data[20:24]

def DestinationOptions(self, raw_data):
        self.next_header, self.heLength = struct.unpack('! B B', raw_data[:2])
        self.data = raw_data[2:]

def RoutingHeader(self, raw_data):
        self.next_header, self.heLength, self.routing_type, self.segments_left = struct.unpack('! B B B B', raw_data[:4]) #8 bits cada
        self.data = None #variável
        self.reserved = None #32 bits
        self.addresses = None #128 bits cada

        if self.routing_type == 0:
            self.reserved = raw_data[4:8]
            self.addresses = raw_data[8:]
        else:
            self.data = raw_data[4:]

def get_mac_addr(mac_raw):
    # need python 3
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Return an IPv6 address
def get_ipv6_address(raw_data):
    address = ":".join(
        map('{:04x}'.format, struct.unpack('! H H H H H H H H', raw_data)))
    return address.replace(":0000:","::" ).replace(":::", "::").replace(":::", "::")

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def byteDataToString(raw_data):
    return " ".join(map('{:02x}'.format, raw_data))


try:
    main()
except Exception as e:
    print('Error Code:\n' + str(e))