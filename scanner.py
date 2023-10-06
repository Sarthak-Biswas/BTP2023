import pyshark

def calculate(interface, packet_count):
    # Open a live capture on the specified interface
    capture = pyshark.LiveCapture(interface=interface)

    # Initialize variables to calculate mean and count of TCP window sizes
    total_window_size = 0
    received_packets = 0

    # Capture the specified number of packets
    for packet in capture.sniff_continuously():
        if 'TCP' in packet:
            try:
                window_size = int(packet['TCP'].window_size)
                total_window_size += window_size
                received_packets += 1
                """ Average tcp window size """
                print(f"Current Average Window Size: {total_window_size / received_packets} bytes")
            except ValueError:
                pass
            
            """ IP header length """    
            header_length = int(packet['IP'].hdr_len)
            print(f"Header length: {header_length} bytes")
            
            """ TCP payload size """
            tcp_payload = int(packet.tcp.len)
            print(f"TCP payload : {tcp_payload}")
            
            print("")
    

if __name__ == "__main__":
    interface = 'Wi-Fi' # or wlan0 for linux
    packet_count = 10000  # Specify the number of packets to capture

    calculate(interface, packet_count)