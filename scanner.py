import pyshark
import socket
import time
import joblib
import os
import subprocess
from sklearn.ensemble import RandomForestClassifier

def set_firewall(ip, port, inbound):
    
    cmd = ""
    
    if inbound:
        cmd = f"sudo iptables -A INPUT -s {ip} --dport {port} -j DROP"
    else:
        cmd = f"sudo iptables -A OUTPUT -s {ip} --dport {port} -j DROP"
        
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"Traffic from {ip}:{port} blocked")
    except Exception as e:
        print(f"ERROR: {e}")
        
    

def calculate(interface, packet_count):
    # Open a live capture on the specified interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    sys_ip = s.getsockname()[0]
    s.close()
    
    capture = pyshark.LiveCapture(interface=interface)

    # Initialize variables to calculate mean and count of TCP window sizes
    total_window_size = 0
    received_packets = 0
    
    s_packet_count = {}
    d_packet_count = {}
    s_bytes_count = {}
    d_bytes_count = {}
    s_time = {}
    d_time = {}
    
    rf_model = joblib.load('./model/random_forest.joblib')

    # Capture the specified number of packets
    for packet in capture.sniff_continuously():
        if 'TCP' in packet:
            # try:
            #     window_size = int(packet['TCP'].window_size)
            #     total_window_size += window_size
            #     received_packets += 1
            #     """ Average tcp window size """
            #     print(f"Current Average Window Size: {total_window_size / received_packets} bytes")
            # except ValueError:
            #     pass
            
            protocol = packet.transport_layer
            src_ip = packet.ip.src
            src_port = packet[protocol].srcport
            
            dst_ip = packet.ip.dst
            dst_port = packet[protocol].dstport
            
            # src_map = str(src_ip) + ',' + str(src_port)
            # dst_map = str(dst_ip) + ',' + str(dst_port)
            
            src_map = (src_ip, src_port)
            dst_map = (dst_ip, dst_port)
            
            # spkts
            if not src_ip == sys_ip:
                if src_map not in s_packet_count:
                    s_packet_count[src_map] = 1
                else:
                    s_packet_count[src_map] += 1
                
            # dpkts
            if not dst_ip == sys_ip:
                if dst_map not in d_packet_count:
                    d_packet_count[dst_map] = 1
                else:
                    d_packet_count[dst_map] += 1
                    
            # sbytes
            if not src_ip == sys_ip:
                if src_map not in s_bytes_count:
                    s_bytes_count[src_map] = int(packet.tcp.len)
                else:
                    s_bytes_count[src_map] += int(packet.tcp.len)
                    
            # dbytes
            if not dst_ip == sys_ip:
                if dst_map not in d_bytes_count:
                    d_bytes_count[dst_map] = int(packet.tcp.len)
                else:
                    d_bytes_count[dst_map] += int(packet.tcp.len)
                
            print(s_bytes_count)
            print(d_bytes_count)
            
            """ IP header length """    
            header_length = int(packet['IP'].hdr_len)
            print(f"Header length: {header_length} bytes")
            
            """ TCP payload size """
            tcp_payload = int(packet.tcp.len)
            print(f"TCP payload : {tcp_payload}")
            
            """ ttl """
            if src_ip == sys_ip:
                dttl = packet.ip.ttl
                print(f"dttl : {dttl}")
            elif dst_ip == sys_ip:
                sttl = packet.ip.ttl
                print(f"sttl : {sttl}")
            
            # stime
            if not src_ip == sys_ip:
                if src_map not in s_time:
                    s_time[src_map] = {}
                    s_time[src_map][0] =  time.time()
                    s_time[src_map][1] = 0.0
                    print(f"Sload: 0")
                else:
                    s_time[src_map][1] = time.time() - s_time[src_map][0]
                    print(f"Sload: {s_bytes_count[src_map] * 8.0 / s_time[src_map][1]}")
                    # print sload = sbytes * 8 / stime
                    
            # dtime
            if not dst_ip == sys_ip:
                if dst_map not in s_time:
                    d_time[dst_map] = {}
                    d_time[dst_map][0] =  time.time()
                    d_time[dst_map][1] = 0.0
                    # print dload = 0
                else:
                    d_time[dst_map][1] = time.time() - d_time[dst_map][0]
                    # print dload = dbytes * 8 / dtime
            
            print("")
    

if __name__ == "__main__":
    interface = 'wlo1' # or wlan0 for linux
    packet_count = 10000  # Specify the number of packets to capture

    calculate(interface, packet_count)