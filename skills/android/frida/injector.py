import os
import logging
import frida
import sys
from typing import Optional

logger = logging.getLogger(__name__)

class FridaInjector:
    """Helper to inject Frida scripts into a running Android process."""
    
    def __init__(self, device_id: Optional[str] = None):
        try:
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                self.device = frida.get_usb_device()
            logger.info(f"[*] Attached to device: {self.device.name}")
        except Exception as e:
            logger.error(f"Failed to connect to device: {e}")
            self.device = None

    def inject_script(self, package_name: str, script_content: str):
        """Injects a script into the target package."""
        if not self.device:
            logger.error("No device connected. Cannot inject.")
            return False
            
        try:
            logger.info(f"[*] Attaching to {package_name}...")
            session = self.device.attach(package_name)
            script = session.create_script(script_content)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    print(f"[*] {message['payload']}")
                else:
                    print(message)
                    
            script.on('message', on_message)
            script.load()
            logger.info("[*] Script loaded successfully.")
            
            # Keep alive
            # sys.stdin.read()
            return True
        except frida.ProcessNotFoundError:
            logger.error(f"Process {package_name} not found. Try spawning it.")
            return False
        except Exception as e:
            logger.error(f"Injection failed: {e}")
            return False
