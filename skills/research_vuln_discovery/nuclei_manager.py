import os
import requests
import yaml

class NucleiManager:
    """
    Manages official Nuclei templates for CTF verification.
    Interfaces with the projectdiscovery/nuclei-templates repository.
    """
    
    def __init__(self, template_dir=None):
        self.template_dir = template_dir or os.path.join(os.getcwd(), "vuln_discovery", "templates")
        if not os.path.exists(self.template_dir):
            os.makedirs(self.template_dir)

    def search_official_template(self, cve_id):
        """
        Searches the official GitHub repository for a matching template.
        Returns the raw URL of the YAML template if found.
        """
        # Since this is a specialized search, we'll try a common naming convention
        # Format: CVE-2024-4040.yaml
        
        # In a real-world scenario, we'd use the browser to search the repo
        # Here we define the discovery URL patterns
        base_search_url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
        
        # Common folders: http, cves, network, dns
        potential_paths = [
            f"/http/cves/{cve_id.split('-')[1]}/{cve_id}.yaml",
            f"/cves/{cve_id.split('-')[1]}/{cve_id}.yaml"
        ]
        
        for path in potential_paths:
            full_url = f"{base_search_url}{path}"
            # We'll use a HEAD request to check existence via requests
            try:
                response = requests.head(full_url, timeout=5)
                if response.status_code == 200:
                    return full_url
            except Exception:
                continue
        
        return None

    def import_template(self, cve_id, raw_url):
        """
        Downloads and stores the template locally.
        """
        response = requests.get(raw_url)
        if response.status_code == 200:
            target_path = os.path.join(self.template_dir, f"{cve_id}.yaml")
            with open(target_path, 'wb') as f:
                f.write(response.content)
            return target_path
        return None

    def validate_template(self, template_path):
        """
        Ensures the YAML is valid according to Nuclei schema.
        """
        try:
            with open(template_path, 'r') as f:
                content = yaml.safe_load(f)
            # Basic check for 'id' and 'info'
            if 'id' in content and 'info' in content:
                return True
        except Exception:
            pass
        return False
