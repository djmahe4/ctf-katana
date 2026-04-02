import random
from scapy.all import Ether, IP, UDP, Raw, wrpcap, rdpcap
from ..models import Severity, ForensicsFinding

class IPFragmentationStego:
    """Methods for IPv4 fragmentation steganography."""
    
    def embed(self, data_chunks: list, output_pcap: str):
        packets = []
        hidden_id = random.randint(10000, 60000)
        for i, chunk in enumerate(data_chunks):
            mf_flag = 1 if i < len(data_chunks) - 1 else 0
            pkt = Ether() / IP(id=hidden_id, flags=mf_flag, frag=i, dst="192.168.1.1", src="192.168.1.100") / UDP(dport=12345, sport=54321) / Raw(load=chunk)
            packets.append(pkt)
        wrpcap(output_pcap, packets)
        return hidden_id

    def extract(self, pcap_path: str, hidden_id: int):
        packets = rdpcap(pcap_path)
        recovered_chunks = {}
        for pkt in packets:
            if pkt.haslayer(IP) and pkt.id == hidden_id:
                if pkt.haslayer(Raw):
                    recovered_chunks[pkt.frag] = pkt[Raw].load
        
        sorted_indices = sorted(recovered_chunks.keys())
        return b"".join([recovered_chunks[idx] for idx in sorted_indices])
