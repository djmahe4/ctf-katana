import os
import sys
import json
import csv
import logging
import re
import time
from DrissionPage import ChromiumOptions, ChromiumPage
from bs4 import BeautifulSoup
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add project root to path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from scripts.research_ingest.advanced_yt_scraper import AdvancedYTScraper
except ImportError:
    logger.warning("AdvancedYTScraper not found in scripts. Falling back to basic logic.")
    AdvancedYTScraper = None

try:
    from skills.script_writer.scrapers.freedium import FreediumScraper
except ImportError:
    logger.warning("FreediumScraper not found in skills. Falling back to basic logic.")
    FreediumScraper = None

def format_cyber_data(examples):
    """Formats the data into the official Gemma 4 Instruct template."""
    instructions = examples.get("instruction", [])
    outputs = examples.get("output", [])
    
    # Handle if they are strings instead of lists
    if isinstance(instructions, str): instructions = [instructions]
    if isinstance(outputs, str): outputs = [outputs]
    
    texts = []
    for instr, out in zip(instructions, outputs):
        # Using Gemma 4's official Instruct Template
        text = f"<|turn|>user\nAnalyze this vulnerability or CTF challenge:\n{instr}\n<|turn|>model\n{out}"
        texts.append(text)
    return { "text" : texts }

class TryHackMeScraper:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.co = ChromiumOptions()
        # Stealth and stability settings to bypass detection
        self.co.set_argument('--disable-blink-features=AutomationControlled')
        self.co.set_pref('excludeSwitches', ['enable-automation'])
        self.co.set_pref('useAutomationExtension', False)
        self.co.set_argument('--no-sandbox')
        self.co.set_argument('--disable-gpu')
        self.co.set_argument('--window-size=1920,1080')
        
        # Maintain login state - use absolute path
        session_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'thm_session'))
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
        logger.info(f"Using session directory: {session_dir}")
        self.co.set_user_data_path(session_dir)
        self.co.set_user('Default') # Force a persistent profile
        self.co.auto_port()
        
        # Use a realistic User-Agent
        self.co.set_user_agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36')
        self.page = ChromiumPage(self.co)
        self._load_cookies()

    def _load_cookies(self):
        """Loads cookies from a local JSON file if it exists."""
        cookie_file = os.path.join(os.path.dirname(__file__), 'thm_cookies.json')
        if os.path.exists(cookie_file):
            try:
                with open(cookie_file, 'r', encoding='utf-8') as f:
                    cookies = json.load(f)
                self.page.set.cookies(cookies)
                logger.info(f"Loaded {len(cookies)} cookies from thm_cookies.json")
            except Exception as e:
                logger.error(f"Failed to load cookies: {e}")

    def _save_cookies(self):
        """Saves current session cookies to a local JSON file."""
        cookie_file = os.path.join(os.path.dirname(__file__), 'thm_cookies.json')
        try:
            cookies = self.page.cookies(all_domains=True, all_info=True)
            with open(cookie_file, 'w', encoding='utf-8') as f:
                json.dump(cookies, f, indent=2)
            logger.info(f"Saved {len(cookies)} cookies to thm_cookies.json")
        except Exception as e:
            logger.error(f"Failed to save cookies: {e}")

    def is_logged_in(self):
        """Checks if the current session is logged in."""
        try:
            url = self.page.url
            # logger.debug(f"Checking login status at: {url}")
            
            # Check for indicators of being logged in first (high confidence)
            if '/dashboard' in url:
                # Look for profile-related elements
                if self.page.ele('xpath://a[contains(@href, "/logout")]', timeout=1) or \
                   self.page.ele('xpath://a[contains(@href, "/profile/")]', timeout=1) or \
                   self.page.ele('.profile-dropdown', timeout=1) or \
                   self.page.ele('xpath://img[contains(@src, "profile")]', timeout=1):
                    return True
            
            # Check for indicators of being logged out (low confidence if they are hidden)
            login_btn = self.page.ele('text:Log In', timeout=1)
            if login_btn and login_btn.states.is_displayed:
                return False
                
            # Final fallback: if we are on dashboard or challenges and don't see a visible login button
            if '/dashboard' in url or '/challenges' in url:
                if not login_btn or not login_btn.states.is_displayed:
                    return True
            
            return False
        except Exception as e:
            # logger.error(f"Error in is_logged_in: {e}")
            return False

    def login(self):
        """Logs into TryHackMe using credentials from .env."""
        logger.info(f"Checking login status at https://tryhackme.com/login...")
        self.page.get('https://tryhackme.com/login')
        time.sleep(5)
        
        if self.is_logged_in():
            logger.info("Session found! Already logged in.")
            return True
            
        logger.info("No active session or logged out. Starting login process...")
        
        # Initial check for CAPTCHA
        self.handle_captcha()
        
        email_input = self.page.ele('input[name="email"]') or \
                     self.page.ele('input[type="email"]') or \
                     self.page.ele('#username-or-email-field')
        
        pass_input = self.page.ele('input[name="password"]') or \
                    self.page.ele('input[type="password"]') or \
                    self.page.ele('#password-field')
        
        if email_input and pass_input:
            logger.info(f"Filling credentials for {self.email}...")
            email_input.input(self.email)
            pass_input.input(self.password)
            
            # Handle captcha again before clicking
            self.handle_captcha()
            
            # Click login button
            login_btn = self.page.ele('button[type="submit"]') or \
                       self.page.ele('text:Log in')
            
            if login_btn:
                login_btn.click()
                logger.info("Login button clicked. Waiting for 60s for manual intervention if needed...")
                time.sleep(60) # Increased time for manual intervention/captcha
                
                # Verify success
                if self.is_logged_in():
                    logger.info("Login successful!")
                    self.page.get_screenshot(path="login_success.png")
                    self._save_cookies()
                    return True
        
        # Final attempt check after waiting
        if self.is_logged_in():
            logger.info("Login detected after wait period!")
            self._save_cookies()
            return True
            
        logger.error("Login failed. Still see login screen.")
        self.page.get_screenshot(path="login_failed.png")
        return False

    def handle_captcha(self):
        """Attempts to solve Turnstile/reCAPTCHA locally by interacting with elements."""
        try:
            # Check for Turnstile
            turnstile_iframe = self.page.ele('iframe[src*="cloudflare"]', timeout=2) or self.page.ele('iframe[src*="turnstile"]', timeout=2)
            if turnstile_iframe:
                logger.warning("Cloudflare Turnstile detected. Attempting solve...")
                try:
                    time.sleep(2)
                    # Try different potential selectors for the checkbox
                    checkbox = turnstile_iframe.ele('.ctp-checkbox-label', timeout=2) or turnstile_iframe.ele('#challenge-stage', timeout=2)
                    if checkbox:
                        checkbox.click()
                        time.sleep(5)
                except Exception as e:
                    logger.debug(f"Turnstile interaction failed: {e}")
            
            # Check for reCAPTCHA
            recaptcha_iframe = self.page.ele('iframe[src*="recaptcha"]', timeout=2)
            if recaptcha_iframe:
                logger.warning("reCAPTCHA detected. Attempting solve...")
                try:
                    anchor_iframe = self.page.ele('iframe[src*="recaptcha/api2/anchor"]', timeout=2)
                    if anchor_iframe:
                        # Use the specific selector provided by the user
                        checkbox = anchor_iframe.ele('.recaptcha-checkbox-border', timeout=2)
                        if checkbox:
                            logger.info("Clicking reCAPTCHA checkbox...")
                            checkbox.click()
                            time.sleep(5)
                except Exception as e:
                    logger.debug(f"reCAPTCHA interaction failed: {e}")
        except Exception as e:
            logger.warning(f"Error during CAPTCHA handling: {e}")
            
        time.sleep(3)

    def _select_dropdown_option(self, dropdown_name, option_text):
        """Robustly selects an option from a React-select dropdown."""
        # Map dropdown names to their expected indices on the challenges page
        # 1: Type, 2: Sort by, 3: Difficulty, 4: Status
        dropdown_indices = {
            "Type": 1,
            "Sort by": 2,
            "Difficulty": 3,
            "Status": 4
        }
        idx = dropdown_indices.get(dropdown_name)
        
        try:
            # Try finding by index first (more stable when text changes to selected value)
            btn = None
            if idx:
                btn = self.page.ele(f'xpath:(//button[@aria-label="click here to choose an option"])[{idx}]')
            
            # Fallback to text if index fails or not provided
            if not btn:
                btn = self.page.ele(f'xpath://button[contains(., "{dropdown_name}")]')
            
            if not btn:
                logger.error(f"Dropdown button '{dropdown_name}' (idx={idx}) not found")
                return False

            # Try to open the dropdown
            btn.click()
            time.sleep(1)
            
            # Check if any option is visible. React-select options usually have 'option' in ID or class.
            if not self.page.ele('xpath://div[contains(@id, "-option-")]'):
                logger.info(f"Options not visible for {dropdown_name}, clicking again (double-click logic)...")
                btn.click()
                time.sleep(1.5)

            # Look for the specific option text
            option = self.page.ele(f'xpath://div[contains(@id, "-option-") and contains(., "{option_text}")]') or \
                     self.page.ele(f'text:{option_text}')
            
            if option:
                option.click()
                logger.info(f"Selected option '{option_text}' in '{dropdown_name}'")
                time.sleep(2)
                return True
            else:
                logger.warning(f"Option '{option_text}' not found in '{dropdown_name}'")
                self.page.get_screenshot(path=f"dropdown_{dropdown_name.replace(' ', '_')}_error.png")
                # Close dropdown by clicking body to reset state
                self.page.ele('xpath://body').click()
                return False
        except Exception as e:
            logger.error(f"Error in _select_dropdown_option for {dropdown_name}: {e}")
            return False

    def scrape_rooms(self):
        logger.info("Scraping rooms from https://tryhackme.com/challenges...")
        rooms = []
        
        self.page.get('https://tryhackme.com/challenges')
        logger.info(f"Page loaded: {self.page.url}")
        time.sleep(5)
        
        # 1. Sort by Newest (Mandatory per user request)
        logger.info("Setting sort order to Newest...")
        if self._select_dropdown_option("Sort by", "Newest"):
            logger.info("Successfully sorted by Newest.")
        else:
            logger.warning("Failed to sort by Newest, but continuing...")
        time.sleep(2)

        # 2. Iterate through difficulties
        difficulty_names = ['Medium', 'Hard', 'Insane']
        
        for diff_name in difficulty_names:
            try:
                logger.info(f"Filtering by difficulty: {diff_name}...")
                if self._select_dropdown_option("Difficulty", diff_name):
                    logger.info(f"Filter applied for {diff_name}. Waiting for results...")
                    time.sleep(3) # Wait for results to load
                    
                    # Scroll to load more
                    for i in range(3):
                        self.page.scroll.to_bottom()
                        time.sleep(1.5)
                    
                    # Find room cards
                    room_links = self.page.eles('xpath://a[contains(@href, "/room/")]')
                    added_count = 0
                    for link in room_links:
                        try:
                            url = link.link
                            if url and '/room/' in url and 'why-subscribe' not in url and not any(r['url'] == url for r in rooms):
                                # Try to find name
                                name_ele = link.ele('tag:h2') or link.ele('tag:h5') or link.ele('xpath:.//div[contains(@class, "title")]')
                                room_name = name_ele.text.strip() if name_ele else url.split('/')[-1]
                                
                                rooms.append({
                                    'name': room_name,
                                    'url': url,
                                    'difficulty': diff_name
                                })
                                added_count += 1
                        except:
                            continue
                    
                    logger.info(f"Added {added_count} {diff_name} rooms.")
                else:
                    logger.warning(f"Skipping {diff_name} due to filter error.")
            except Exception as e:
                logger.error(f"Error during {diff_name} scraping: {e}")

        return rooms

    def save_rooms_to_csv(self, rooms, filename='thm_rooms.csv'):
        if not rooms: return
        # Ensure all rooms have the same keys, including the new writeup_links
        for room in rooms:
            if 'writeup_links' not in room:
                room['writeup_links'] = ""
                
        keys = ['name', 'url', 'difficulty', 'writeup_links']
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            dict_writer.writeheader()
            dict_writer.writerows(rooms)
        logger.info(f"Saved {len(rooms)} rooms to {filename}")

    def find_writeup_urls(self, room_name, room_url):
        logger.info(f"Analyzing room for writeups: {room_name} ({room_url})")
        self.page.get(room_url)
        time.sleep(2)
        
        is_premium = 'why-subscribe' in self.page.url
        if is_premium:
            logger.info(f"Room {room_name} is premium on THM. Searching external sources...")
        
        writeup_urls = []
        yt_links = []
        
        if not is_premium:
            # Check for a 'Writeups' tab or section
            writeups_ele = self.page.ele('text:Writeups') or self.page.ele('t:a@text()=Writeups')
            if writeups_ele:
                logger.info("Found 'Writeups' section on room page.")
                writeups_ele.click()
                time.sleep(2)
                
            # Extract links from the room page
            links = self.page.eles('tag:a')
            for link in links:
                href = link.link
                if not href: continue
                
                if any(domain in href.lower() for domain in ['0xdf.net', 'ippsec.rocks', 'writeup', 'gitbook.io', 'medium.com']):
                    if 'medium.com' in href:
                        href = f"https://freedium.cfd/{href}"
                    if href not in writeup_urls:
                        writeup_urls.append(href)
                elif 'youtube.com' in href or 'youtu.be' in href:
                    if href not in yt_links:
                        yt_links.append(href)
        
        # Always search DuckDuckGo for comprehensive coverage
        logger.info(f"Searching DuckDuckGo for {room_name} writeups...")
        search_query = f"TryHackMe {room_name} writeup"
        search_url = f"https://duckduckgo.com/?q={search_query.replace(' ', '+')}"
        self.page.get(search_url)
        time.sleep(2)
        
        links = self.page.eles('tag:a')
        for link in links:
            href = link.link
            if not href or 'duckduckgo' in href: continue
            
            if any(domain in href.lower() for domain in ['medium.com', '0xdf.net', 'ippsec', 'writeup', 'gitbook.io']):
                if 'medium.com' in href:
                    href = f"https://freedium.cfd/{href}"
                if href not in writeup_urls:
                    writeup_urls.append(href)
            elif 'youtube.com' in href or 'youtu.be' in href:
                if href not in yt_links:
                    yt_links.append(href)
        
        # Merge and prioritize text
        final_urls = [u for u in writeup_urls if u not in yt_links] + yt_links
        return final_urls[:5], is_premium

    def extract_writeup_text(self, url):
        logger.info(f"Extracting content from {url}...")
        
        # Handle GitHub URLs by converting to raw content for cleaner extraction
        if 'github.com' in url.lower() and '/blob/' in url.lower():
            # Convert https://github.com/user/repo/blob/main/file.md
            # to https://raw.githubusercontent.com/user/repo/main/file.md
            raw_url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            logger.info(f"Detected GitHub blob. Fetching raw content: {raw_url}")
            try:
                response = requests.get(raw_url, timeout=10)
                response.raise_for_status()
                return response.text[:100000]
            except Exception as e:
                logger.warning(f"Failed to fetch raw GitHub content: {e}. Falling back to browser extraction.")

        self.page.get(url)
        time.sleep(3)
        html = self.page.html
        soup = BeautifulSoup(html, 'lxml')
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.get_text(separator='\n')
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        return text[:100000]

    def parse_writeup_with_llm(self, text):
        logger.info("Parsing writeup with LLM...")
        prompt = f"""
        Analyze this TryHackMe room writeup and extract the core steps as instruction-output pairs.
        Each 'instruction' should describe a task or phase (e.g., 'Enumerate open ports', 'Exploit the web application').
        The 'output' should provide the detailed explanation or commands used in that step.

        CRITICAL: Your response must be a SINGLE valid JSON object. 
        Escape all double quotes within the strings. Do not include any text before or after the JSON.

        WRITEUP CONTENT:
        {text}

        Output format (JSON):
        {{
            "instruction": ["step 1 description", "step 2 description"],
            "output": ["step 1 details/commands", "step 2 details/commands"]
        }}
        """
        try:
            response = requests.post(
                'http://localhost:11434/api/chat',
                json={
                    "model": "mistral-nemo",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                },
                timeout=300
            )
            response.raise_for_status()
            content = response.json().get('message', {}).get('content', '')
            
            # More robust JSON extraction
            json_match = re.search(r'(\{.*\})', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                # Basic cleaning of common LLM JSON errors
                json_str = json_str.replace('\n', ' ').replace('\r', '')
                return json.loads(json_str)
        except Exception as e:
            logger.error(f"LLM parsing failed: {e}")
        return None

    def close(self):
        if self.page:
            self.page.quit()

def run(params):
    email = params.get('email') or os.getenv('THM_EMAIL')
    password = params.get('password') or os.getenv('THM_PASSWORD')
    
    if not email or not password:
        return {'status': False, 'summary': "Missing credentials. Set THM_EMAIL and THM_PASSWORD in .env"}
    
    scraper = TryHackMeScraper(email, password)
    try:
        # Check if already logged in (look for Dashboard link or Profile icon)
        scraper.page.get('https://tryhackme.com/dashboard')
        time.sleep(5) 
        
        # Robust login check
        is_logged_in = True
        # Verify session
        if not scraper.is_logged_in():
            logger.info("No active session detected. Starting login process...")
            if not scraper.login():
                return {'status': False, 'summary': "Login failed."}
        else:
            logger.info("Active session detected. Proceeding to challenges...")
            
        # Always scrape for fresh data as requested by user
        logger.info("Starting automated room scraping (Newest + Medium/Hard/Insane)...")
        rooms = scraper.scrape_rooms()
        if rooms:
            scraper.save_rooms_to_csv(rooms)
            logger.info(f"Scraping complete. Total rooms found: {len(rooms)}")
        else:
            if os.path.exists('thm_rooms.csv'):
                logger.warning("Scraping returned no results, using existing thm_rooms.csv")
            else:
                return {'status': False, 'summary': "No rooms found and no existing cache."}
        
        rooms = []
        with open('thm_rooms.csv', 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rooms = list(reader)
            
        logger.info(f"Loaded {len(rooms)} rooms for processing.")
        
        output_file = "thm_dataset.jsonl"
        processed_count = 0
        max_rooms = params.get('max_rooms', 3)
        
        room_idx = 0
        while processed_count < max_rooms and room_idx < len(rooms):
            selected_room = rooms[room_idx]
            logger.info(f"[{processed_count + 1}/{max_rooms}] Analyzing room: {selected_room['name']}")
            
            try:
                writeup_urls, is_premium = scraper.find_writeup_urls(selected_room['name'], selected_room['url'])
                
                if not writeup_urls:
                    if is_premium:
                        logger.info(f"Premium room {selected_room['name']} has no external writeups. Removing.")
                        rooms.pop(room_idx)
                        scraper.save_rooms_to_csv(rooms)
                        continue
                    else:
                        logger.warning(f"No writeups found for public room {selected_room['name']}. Skipping.")
                        room_idx += 1
                        continue
                
                # Store found links in CSV room data
                selected_room['writeup_links'] = ";".join(writeup_urls)
                scraper.save_rooms_to_csv(rooms)
                
                best_data = None
                for url in writeup_urls:
                    text = ""
                    try:
                        if ("youtube.com" in url or "youtu.be" in url) and AdvancedYTScraper:
                            logger.info(f"Using AdvancedYTScraper for YouTube: {url}")
                            room_slug = selected_room['name'].lower().replace(" ", "_")
                            yt_output = os.path.abspath(os.path.join(os.getcwd(), "recordings", f"yt_{room_slug}"))
                            os.makedirs(yt_output, exist_ok=True)
                            
                            yt_scraper = AdvancedYTScraper(output_dir=yt_output)
                            yt_results = yt_scraper.run(url, max_duration=None)
                            
                            if yt_results:
                                text = "\n---\n".join([f"Timestamp: {r['timestamp']}s\n{r['ocr_text']}" for r in yt_results])
                                logger.info(f"Captured {len(yt_results)} frames from YouTube.")
                            else:
                                logger.warning("YouTube scraper returned no results.")
                                
                        elif "freedium.cfd" in url and FreediumScraper:
                            logger.info(f"Using FreediumScraper for: {url}")
                            f_scraper = FreediumScraper()
                            medium_url = url.replace("https://freedium.cfd/", "")
                            text = f_scraper.scrape(medium_url)
                        else:
                            text = scraper.extract_writeup_text(url)
                    except Exception as scrape_err:
                        logger.error(f"Failed to extract text from {url}: {scrape_err}")
                        continue

                    if not text or len(text) < 200:
                        continue
                        
                    parsed = scraper.parse_writeup_with_llm(text)
                    if parsed and len(parsed.get('instruction', [])) >= 2:
                        best_data = parsed
                        break
                
                if best_data:
                    formatted = format_cyber_data(best_data)
                    with open(output_file, 'a', encoding='utf-8') as f:
                        for text in formatted['text']:
                            f.write(json.dumps({'text': text, 'room': selected_room['name']}) + '\n')
                    processed_count += 1
                    logger.info(f"Successfully added {selected_room['name']} to dataset. ({processed_count}/{max_rooms})")
                else:
                    logger.warning(f"Could not extract valid training data for {selected_room['name']}")
                
                room_idx += 1
            except Exception as e:
                logger.error(f"Error processing {selected_room['name']}: {e}")
                room_idx += 1
                
        return {
            'status': True,
            'summary': f"Successfully processed {processed_count} rooms into {output_file}",
            'file': output_file
        }
    finally:
        scraper.close()

if __name__ == "__main__":
    print(run({}))
