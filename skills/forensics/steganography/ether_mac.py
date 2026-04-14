from scapy.all import Ether, IP, Raw, wrpcap, rdpcap

class EtherMACStego:
    """Methods for Ethernet Source MAC steganography."""
    
    def embed(self, data_chunks: list, output_pcap: str, base_mac_oui: str = "02:00:00"):
        packets = []
        for i, chunk in enumerate(data_chunks):
            padded_chunk = chunk.ljust(3, b'\x00')
            mac_suffix = ":".join(f"{b:02x}" for b in padded_chunk)
            src_mac = f"{base_mac_oui}:{mac_suffix}"
            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.104", dst="192.168.1.5")/Raw(load=f"Hidden chunk {i}".encode())
            packets.append(pkt)
        wrpcap(output_pcap, packets)
        return base_mac_oui

    def extract(self, pcap_path: str, base_mac_oui: str):
        packets = rdpcap(pcap_path)
        recovered_chunks = []
        for pkt in packets:
            if pkt.haslayer(Ether):
                mac_octets = pkt.src.split(':')
                if ":".join(mac_octets[:3]) == base_mac_oui:
                    recovered_chunks.append(bytes([int(octet, 16) for octet in mac_octets[3:]]))
        return b"".join(recovered_chunks)
