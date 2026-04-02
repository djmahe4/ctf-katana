import sys
import os
import argparse
from pathlib import Path

# Add project skills directory to sys.path for standalone execution
sys.path.append(str(Path(__file__).resolve().parent.parent))

from forensics.models import ForensicsCategory, Severity
from forensics.handlers.pcap_handler import PcapHandler
from forensics.handlers.file_handler import FileHandler
from forensics.engines.pcap_designer import PcapDesigner

def main():
    parser = argparse.ArgumentParser(description="Advanced Forensics & PCAP Steganography Tool")
    parser.add_argument("target", nargs="?", help="Target file/directory for analysis.")
    parser.add_argument("--action", "-a", choices=["file_magic", "foremost", "pngcheck", "pdf_text", "extract", "embed", "think"], default="file_magic")
    parser.add_argument("--mode", "-m", choices=["file", "pcap", "network", "auto"], default="auto")
    
    # PCAP Extraction/Embedding flags
    parser.add_argument("--method", help="Steganography method (ip_frag, tcp_opt, icmp_ts, dns_srv, ether_mac)")
    parser.add_argument("--id", type=int, help="IP ID for ip_frag extraction.")
    parser.add_argument("--kind", type=int, default=253, help="TCP option kind for tcp_opt extraction.")
    parser.add_argument("--domain", help="DNS domain for dns_srv extraction.")
    parser.add_argument("--oui", default="02:00:00", help="MAC OUI for ether_mac extraction.")
    
    # Designer flags
    parser.add_argument("--prompt", help="Designer prompt for brainstorming a new challenge.")
    parser.add_argument("--model", default="groq/llama-3.3-70b-versatile", help="LLM model for the designer.")

    args = parser.parse_args()

    if args.action == "think":
        if not args.prompt:
            print("Error: --prompt required for 'think' action.")
            sys.exit(1)
        designer = PcapDesigner(model=args.model)
        print(f"[*] Triggering Llama-based brainstorming for: '{args.prompt}'")
        # In actual usage, the user would invoke the free-llm-apis MCP via the agent.
        # This CLI provides the entry point for that 'thinking' session.
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target_path = Path(args.target)
    
    # Auto-detect mode if needed
    mode = args.mode
    if mode == "auto":
        if target_path.suffix.lower() in [".pcap", ".pcapng"]:
            mode = "pcap"
        else:
            mode = "file"

    # Select handler
    if mode == "pcap":
        handler = PcapHandler()
    else:
        handler = FileHandler()

    # Orchestrate analysis
    kwargs = vars(args)
    kwargs["pcap_action"] = args.action
    result = handler.analyze(target_path, **kwargs)
    
    # Display results
    print(f"[*] Forensics Results for: {target_path.name}")
    print(f"[*] Category: {result.category.value}")
    print(f"[*] Summary: {result.summary}")
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.vulnerability_id}: {finding.description}")
        print(f"    Evidence: {finding.evidence}")
    
    if result.extracted_files:
        print("[*] Extracted Files:")
        for f in result.extracted_files:
            print(f"    - {f}")

if __name__ == "__main__":
    main()
