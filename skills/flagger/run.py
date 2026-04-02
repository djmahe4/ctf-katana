import argparse
import sys
import json
from skills.flagger.core.intensity import IntensityArchitect
from skills.flagger.handlers.reverse_handler import ReverseHandler
from skills.flagger.handlers.web_handler import WebHandler

def main():
    parser = argparse.ArgumentParser(description="CTF-Katana Flagger: Anti-AI Flag Hardening & Poisoning")
    parser.add_argument("flag", help="Original flag string to harden.")
    parser.add_argument("--level", "-n", choices=["moderate", "difficult", "expert"], default="moderate",
                        help="Harden intensity level (Moderate, Difficult, or Expert).")
    parser.add_argument("--handler", "-hnd", choices=["reverse", "web"], default="reverse",
                        help="Target challenge type.")
    parser.add_argument("--template", "-t", default="python",
                        help="Language template (e.g., python, html).")
    parser.add_argument("--output", "-o", help="File to write the hardened payload to.")
    
    args = parser.parse_args()
    
    # 1. Harden Flag
    architect = IntensityArchitect()
    try:
        payload = architect.harden_flag(args.flag, args.level)
    except Exception as e:
        print(f"Error during hardening: {e}")
        sys.exit(1)
        
    # 2. Embed into Challenge
    if args.handler == "reverse":
        handler = ReverseHandler()
    elif args.handler == "web":
        handler = WebHandler()
    else:
        print(f"Unknown handler: {args.handler}")
        sys.exit(1)
    
    final_output = handler.embed(payload, args.template)
    
    # 3. Handle Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(final_output)
        print(f"Hardened payload written to: {args.output}")
    else:
        print(final_output)

if __name__ == "__main__":
    main()
