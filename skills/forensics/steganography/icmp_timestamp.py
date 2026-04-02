import struct
from scapy.all import Ether, IP, ICMP, wrpcap, rdpcap

class ICMPTimestampStego:
    """Methods for ICMP Timestamp steganography (originate_timestamp)."""
    
    def embed(self, data_chunks: list, output_pcap: str):
        packets = []
        src_ip, dst_ip = "192.168.1.102", "192.168.1.3"
        for i, chunk in enumerate(data_chunks):
            padded_chunk = chunk.ljust(4, b'\x00')
            ts = struct.unpack('>I', padded_chunk)[0]
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP(type=13, id=0x1337, seq=i, time=ts)
            packets.append(pkt)
        wrpcap(output_pcap, packets)
        return "ICMPType13"

    def extract(self, pcap_path: str):
        packets = rdpcap(pcap_path)
        recovered_chunks = []
        for pkt in packets:
            if pkt.haslayer(ICMP) and pkt.type == 13:
                recovered_chunks.append(struct.pack('>I', pkt.time))
        return b"".join(recovered_chunks)
