import os
from pathlib import Path
from skills.forensics.base import ForensicsHandlerBase
from skills.forensics.models import ForensicsResult, ForensicsCategory, Severity
from skills.forensics.steganography.ip_fragmentation import IPFragmentationStego
from skills.forensics.steganography.tcp_options import TCPOptionsStego
from skills.forensics.steganography.icmp_timestamp import ICMPTimestampStego
from skills.forensics.steganography.dns_srv import DNSSRVStego
from skills.forensics.steganography.ether_mac import EtherMACStego

class PcapHandler(ForensicsHandlerBase):
    """Handler for PCAP/PCAPNG network forensic analysis."""
    
    def __init__(self):
        super().__init__(ForensicsCategory.PCAP)
        self.stego_methods = {
            "ip_frag": IPFragmentationStego(),
            "tcp_opt": TCPOptionsStego(),
            "icmp_ts": ICMPTimestampStego(),
            "dns_srv": DNSSRVStego(),
            "ether_mac": EtherMACStego()
        }

    def analyze(self, target_path: Path, **kwargs) -> ForensicsResult:
        result = ForensicsResult(target=str(target_path), category=self.category)
        
        # Action-based logic (Triggered by flags)
        action = kwargs.get("pcap_action")
        
        if action == "extract":
            method = kwargs.get("method")
            if method in self.stego_methods:
                extracted_data = self._extract_data(str(target_path), method, kwargs)
                if extracted_data:
                    out_file = target_path.parent / f"extracted_{method}_{target_path.name}.bin"
                    out_file.write_bytes(extracted_data)
                    result.extracted_files.append(str(out_file))
                    result.summary = f"Successfully extracted data using {method}."
                    self.add_finding(result, f"stego-{method}", Severity.HIGH, 
                                     f"Hidden data extracted via {method}.", 
                                     f"Output saved to {out_file.name}", str(target_path))
            else:
                result.summary = f"Unknown extraction method: {method}"
                
        elif action == "embed":
            # This is handled by the designer/embedder logic
            pass
            
        return result

    def _extract_data(self, pcap_path: str, method: str, kwargs: dict) -> bytes:
        stego = self.stego_methods[method]
        try:
            if method == "ip_frag":
                return stego.extract(pcap_path, int(kwargs.get("id", 0)))
            elif method == "tcp_opt":
                return stego.extract(pcap_path, int(kwargs.get("kind", 253)))
            elif method == "icmp_ts":
                return stego.extract(pcap_path)
            elif method == "dns_srv":
                return stego.extract(pcap_path, kwargs.get("domain", ""))
            elif method == "ether_mac":
                return stego.extract(pcap_path, kwargs.get("oui", "02:00:00"))
        except Exception as e:
            print(f"Extraction error: {e}")
        return b""
def get_handler():
    return PcapHandler()
