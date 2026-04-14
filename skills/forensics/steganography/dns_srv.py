import struct
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRRSRV, wrpcap, rdpcap

class DNSSRVStego:
    """Methods for DNS SRV record Priority/Weight steganography."""
    
    def embed(self, data_chunks: list, output_pcap: str, domain: bytes = b"_hiddenservice._tcp.example.com"):
        packets = []
        src_ip, dst_ip = "192.168.1.103", "192.168.1.4"
        for i, chunk in enumerate(data_chunks):
            padded_chunk = chunk.ljust(4, b'\x00')
            priority_val = struct.unpack('>H', padded_chunk[:2])[0]
            weight_val = struct.unpack('>H', padded_chunk[2:4])[0]
            
            query = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=50000+i, dport=53)/DNS(id=i+1, qr=0, qd=DNSQR(qname=domain, qtype="SRV"))
            packets.append(query)
            
            response = Ether()/IP(src=dst_ip, dst=src_ip)/UDP(sport=53, dport=50000+i)/DNS(
                id=i+1, qr=1, aa=1, rd=1, ra=1, 
                qd=DNSQR(qname=domain, qtype="SRV"),
                an=DNSRRSRV(rrname=domain, type="SRV", rclass="IN", ttl=60, 
                            priority=priority_val, weight=weight_val, port=12345, target="hidden.example.com")
            )
            packets.append(response)
        wrpcap(output_pcap, packets)
        return domain.decode()

    def extract(self, pcap_path: str, domain_to_find: str):
        packets = rdpcap(pcap_path)
        recovered_chunks = []
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.qr == 1 and pkt.an:
                for ans in pkt.an:
                    if ans.type == 33 and ans.rrname.decode().lower().rstrip('.') == domain_to_find.lower().rstrip('.'):
                        recovered_chunks.append(struct.pack('>H', ans.priority) + struct.pack('>H', ans.weight))
        return b"".join(recovered_chunks)
