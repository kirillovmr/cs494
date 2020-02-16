from scapy.all import IP,TCP

# Creates a spoofed UDP packet with the payload
# and send it over to the destination IP and port specified
def send_packet(src_ip, dst_ip, dst_port, payload):
    packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port)/payload
    send(packet)
