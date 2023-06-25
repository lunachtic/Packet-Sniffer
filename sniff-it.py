import socket
import struct
import sys
import textwrap

# Get string of 6 characters as ethernet address into dash-separated hex string


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return b


# Create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error as msg:
    print('Socket could not be created. Error Code: ' +
          str(msg[0]) + ' Message: ' + msg[1])
    sys.exit()

count = 0
print('Getting a packet\n')

# Get a packet
while True:
    packet, addr = s.recvfrom(65565)

    print('Packet Received:')
    wrapped_packet = textwrap.wrap(str(packet))

    # Print a maximum of 5 lines
    for line in wrapped_packet[:5]:
        print(line)
    if len(wrapped_packet) > 5:
        print('...')  # Print ellipsis if there are more lines

    # ------------------- L2 Information -------------------------------------
    eth_length = 14
    eth_header = packet[:eth_length]
    eth_unpack = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth_unpack[2])
    print('############### Layer 2 Information ############')
    print('Destination MAC: ' + eth_addr(packet[0:6]))
    print('Source MAC: ' + eth_addr(packet[6:12]))
    print('Protocol: ' + str(eth_protocol))
    print('-----------------------------------------------\n')

    # ------------------- IP HEADER EXTRACTION --------------------------------
    if eth_protocol == 8:  # IPv4
        ip_header = packet[eth_length:eth_length + 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        source_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        print('########## IPv4 Header Info ##############')
        print('Version: ' + str(version))
        print('IP Header Length: ' + str(ihl))
        print('TTL: ' + str(ttl))
        print('Protocol: ' + str(protocol))
        print('Source Address: ' + str(source_addr))
        print('Destination Address: ' + str(dest_addr))
        print('------------------------------------------\n')

        # ---------------- TCP HEADER EXTRACTION --------------------------------
        if protocol == 6:  # TCP
            tcp_header = packet[eth_length +
                                iph_length:eth_length + iph_length + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            ack = tcph[3]
            resrve = tcph[4]
            tcph_length = resrve >> 4

            print('########### TCP Header Info ##############')
            print('Source Port: ' + str(source_port))
            print('Destination Port: ' + str(dest_port))
            print('Sequence Number: ' + str(sequence))
            print('Acknowledgement: ' + str(ack))
            print('TCP Header Length: ' + str(tcph_length))
            print('------------------------------------------\n')
        # Add support for other protocols as needed

    elif eth_protocol == 56710:  # IPv6
        ip_header = packet[eth_length:eth_length + 40]
        iph = struct.unpack('!IHBB16s16s', ip_header)

        version = (iph[0] >> 28) & 0x0F
        traffic_class = (iph[0] >> 20) & 0xFF
        flow_label = iph[0] & 0xFFFFF

        payload_length = iph[1]
        next_header = iph[2]
        hop_limit = iph[3]
        source_addr = socket.inet_ntop(socket.AF_INET6, iph[4])
        dest_addr = socket.inet_ntop(socket.AF_INET6, iph[5])

        print('########## IPv6 Header Info ##############')
        print('Version: ' + str(version))
        print('Traffic Class: ' + str(traffic_class))
        print('Flow Label: ' + str(flow_label))
        print('Payload Length: ' + str(payload_length))
        print('Next Header: ' + str(next_header))
        print('Hop Limit: ' + str(hop_limit))
        print('Source Address: ' + str(source_addr))
        print('Destination Address: ' + str(dest_addr))
        print('------------------------------------------\n')

        # Check the Next Header field and handle specific headers accordingly
        if next_header == 0:
            # Hop-by-Hop Options Header
            hbh_header = packet[eth_length + 40:eth_length + 48]
            hbh_next_header, hbh_header_length = struct.unpack(
                '!BB', hbh_header)

            print('######## Hop-by-Hop Options Header Info ########')
            print('Next Header: ' + str(hbh_next_header))
            print('Header Length: ' + str((hbh_header_length + 1) * 8))
            print('----------------------------------------------\n')

        elif next_header == 43:
            # Routing Header
            routing_header = packet[eth_length + 40:eth_length + 48]
            routing_next_header, routing_header_length, routing_type, routing_segments = \
                struct.unpack('!BBB', routing_header)

            print('############## Routing Header Info #############')
            print('Next Header: ' + str(routing_next_header))
            print('Header Length: ' + str((routing_header_length + 1) * 8))
            print('Routing Type: ' + str(routing_type))
            print('Segments Left: ' + str(routing_segments))
            print('----------------------------------------------\n')

        elif next_header == 44:
            # Fragmentation Header
            fragmentation_header = packet[eth_length + 40:eth_length + 48]
            fragmentation_next_header, fragmentation_reserved, fragmentation_fragment_offset, fragmentation_m_flag, \
                fragmentation_identification = struct.unpack(
                    '!B3sHBH', fragmentation_header)

            print('############ Fragmentation Header Info ##########')
            print('Next Header: ' + str(fragmentation_next_header))
            print('Reserved: ' + str(fragmentation_reserved))
            print('Fragment Offset: ' + str(fragmentation_fragment_offset))
            print('M Flag: ' + str(fragmentation_m_flag))
            print('Identification: ' + str(fragmentation_identification))
            print('----------------------------------------------\n')

        elif next_header == 50:
            # Encapsulating Security Payload Header
            esp_header = packet[eth_length + 40:eth_length + 48]
            esp_next_header, esp_payload_length, esp_spi = struct.unpack(
                '!BBH', esp_header)

            print('####### Encapsulating Security Payload Info ######')
            print('Next Header: ' + str(esp_next_header))
            print('Payload Length: ' + str(esp_payload_length))
            print('SPI: ' + str(esp_spi))
            print('----------------------------------------------\n')

        elif next_header == 51:
            # Authentication Header
            ah_header = packet[eth_length + 40:eth_length + 48]
            ah_next_header, ah_header_length, ah_reserved, ah_spi, ah_sequence, ah_auth_data = \
                struct.unpack('!BBHLL', ah_header)

            print('######## Authentication Header Info ###########')
            print('Next Header: ' + str(ah_next_header))
            print('Header Length: ' + str((ah_header_length + 2) * 4))
            print('Reserved: ' + str(ah_reserved))
            print('SPI: ' + str(ah_spi))
            print('Sequence Number: ' + str(ah_sequence))
            print('Auth Data: ' + str(ah_auth_data))
            print('----------------------------------------------\n')

    # ------------------------ Get the DATA -----------------------------------
    h_size = eth_length + tcph_length * 4
    data_size = len(packet) - h_size

    # Get the data
    data = packet[h_size:]
    if data_size > 0:
        print('##############DATA##################')
        print('Data:')
        # Wrap the data into lines
        wrapped_data = textwrap.wrap(str(data))
        # Print a maximum of 5 lines
        for line in wrapped_data[:5]:
            print(line)
        if len(wrapped_data) > 5:
            print('...')  # Print ellipsis if there are more lines
        print('------------------------------------\n\n')

    print('Packet {} is done!\n'.format(count))
    count += 1
    # if count >= 10: break
