import base64
from scapy.all import Ether, IP, TCP, wrpcap, rdpcap

class TCPOptionsStego:
    """Methods for custom TCP option steganography."""
    
    def embed(self, data_chunks: list, output_pcap: str, kind: int = 253):
        packets = []
        src_ip, dst_ip = "192.168.1.101", "192.168.1.2"
        src_port, dst_port = 10000, 80
        
        # Handshake
        syn = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
        packets.append(syn)
        
        for i, chunk in enumerate(data_chunks):
            encoded_chunk = base64.b64encode(chunk).decode('ascii')
            custom_option = (kind, encoded_chunk)
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", seq=1001 + i, ack=1, options=[custom_option])
            packets.append(pkt)
            
        wrpcap(output_pcap, packets)
        return kind

    def extract(self, pcap_path: str, kind: int):
        packets = rdpcap(pcap_path)
        recovered_chunks = []
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.options:
                for opt in pkt.options:
                    if isinstance(opt, tuple) and len(opt) == 2 and opt[0] == kind:
                        try:
                            encoded_data = opt[1]
                            if isinstance(encoded_data, bytes):
                                encoded_data = encoded_data.decode('ascii')
                            recovered_chunks.append(base64.b64decode(encoded_data))
                        except Exception:
                            pass
        return b"".join(recovered_chunks)
