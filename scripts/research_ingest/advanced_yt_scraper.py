import os
import time
import json
import logging
from datetime import datetime
import cv2
import numpy as np
from PIL import Image
try:
    import easyocr
except ImportError:
    easyocr = None
from DrissionPage import ChromiumPage, ChromiumOptions

class AdvancedYTScraper:
    def __init__(self, output_dir="recordings"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger("YTScraper")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # DrissionPage Setup
        co = ChromiumOptions()
        co.set_argument('--mute-audio')
        co.set_argument('--window-size=1280,720')
        self.page = ChromiumPage(co)
        
        self.last_histogram = None
        self.last_text_len = 0
        self.last_capture_time = 0
        self.is_terminal_mode = False
        self.video_metadata = {}
        
        # EasyOCR Setup
        if easyocr:
            self.reader = easyocr.Reader(['en'], gpu=False) # Use CPU for now as requested or detected
        else:
            self.reader = None
            self.logger.warning("EasyOCR not found. OCR extraction will be disabled.")

    def _get_histogram(self, image_path):
        """Calculates a normalized color histogram for an image."""
        try:
            img = cv2.imread(image_path)
            if img is None: return None
            # Convert to HSV for better color-based comparison
            hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
            hist = cv2.calcHist([hsv], [0, 1], None, [180, 256], [0, 180, 0, 256])
            cv2.normalize(hist, hist, 0, 1, cv2.NORM_MINMAX)
            return hist
        except Exception as e:
            self.logger.error(f"Histogram calculation failed: {e}")
            return None

    def _get_active_video(self):
        """
        Detects the current active video and ad state with Shadow DOM resilience.
        Returns: (video_element, is_ad, is_visible)
        """
        try:
            video = self.page.ele('.html5-main-video', timeout=2)
            if not video:
                video = self.page.ele('t:video', timeout=1)

            if not video:
                return None, False, False

            # Aggressive but Accurate Ad Detection
            # We look for visible ad-specific labels or UI elements
            js_ad_check = """
            try {
                const player = document.querySelector('ytd-player') || document.querySelector('#movie_player');
                if (!player) return false;
                
                // 1. Skip Buttons (Indisputable)
                const hasSkipBtn = !!player.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-ad-skip-button-container');
                
                // 2. Ad Module Overlays (Visible children)
                const adModule = player.querySelector('.ytp-ad-module');
                const hasVisibleAdOverlay = adModule && adModule.offsetHeight > 0 && adModule.children.length > 0;
                
                // 3. Ad Badges / Labels
                const adBadge = player.querySelector('.ytp-ad-simple-ad-badge, .ytp-ad-text, .ytp-ad-preview-text');
                const hasAdLabel = adBadge && adBadge.innerText.length > 0 && adBadge.offsetHeight > 0;
                
                // 4. Class check as fallback, but only if an ad label is also present
                const isAdClass = player.classList.contains('ad-showing') || player.classList.contains('ad-interrupting');

                return hasSkipBtn || hasVisibleAdOverlay || (isAdClass && hasAdLabel);
            } catch(e) { return false; }
            """
            is_ad = self.page.run_js(js_ad_check)

            is_visible = False
            try:
                is_visible = video.states.is_displayed and video.rect.size[0] > 0
            except:
                pass

            return video, is_ad, is_visible

        except Exception as e:
            self.logger.error(f"[-] Video detection failed: {e}")
            return None, False, False

    def force_high_quality(self):
        """Forces the YouTube player to 1080p or highest available."""
        js_force = """
        try {
            const player = document.getElementById('movie_player') || document.querySelector('.html5-video-player');
            if (player) {
                // Target 1080p but accept 720p as fallback
                player.setPlaybackQualityRange('hd1080', 'hd720');
                player.setPlaybackQuality('hd1080');
                return true;
            }
        } catch(e) {}
        return false;
        """
        if self.page.run_js(js_force):
            self.logger.info("[*] Forced High Quality (1080p/720p)")

    def toggle_chrome(self, visible=True):
        """Hides or shows YouTube player controls and overlays."""
        display_val = 'block' if visible else 'none'
        pointer_val = 'auto' if visible else 'none'
        
        js_chrome = f"""
        try {{
            const player = document.getElementById('movie_player');
            const selectors = [
                '.ytp-chrome-top', '.ytp-chrome-bottom', 
                '.ytp-gradient-top', '.ytp-gradient-bottom',
                '.ytp-pause-overlay', '.ytp-iv-container',
                '.ytp-watermark'
            ];
            selectors.forEach(s => {{
                const el = document.querySelector(s);
                if (el) el.style.display = '{display_val}';
            }});
            if (player) player.style.pointerEvents = '{pointer_val}';
            return true;
        }} catch(e) {{}}
        return false;
        """
        self.page.run_js(js_chrome)

    def get_video_duration(self):
        """Returns the total duration of the video in seconds, ensuring we get the main content duration."""
        for _ in range(15): # Wait up to 7.5 seconds
            duration = self.page.run_js("""
                try {
                    const player = document.getElementById('movie_player') || document.querySelector('ytd-player');
                    if (player && typeof player.getDuration === 'function') {
                        // The YouTube Player API's getDuration() consistently returns the main video's length 
                        // even if an ad is currently playing on top.
                        return player.getDuration();
                    }
                    const v = document.querySelector('video.html5-main-video');
                    return v ? v.duration : 0;
                } catch(e) { return 0; }
            """)
            if duration and duration > 3.0: # Ignore tiny durations (placeholders)
                return float(duration)
            
            # Check for error pages or availability
            if self.page.ele('text:Video unavailable'):
                self.logger.error("[!] Video is unavailable (Private/Deleted/Geo-blocked)")
                return 0.0

            time.sleep(0.5)
        return 0.0

    def cleanup(self, keep_txt=True):
        """Removes all files in the output directory."""
        self.logger.info(f"[*] Cleaning up output directory: {self.output_dir}")
        for f in os.listdir(self.output_dir):
            if keep_txt and f.endswith(".txt"):
                continue
            os.remove(os.path.join(self.output_dir, f))

    def _preprocess_for_ocr(self, image_path):
        """Optimizes images for EasyOCR: Resize + Grayscale."""
        try:
            img = cv2.imread(image_path)
            if img is None: return None
            
            # 1. Grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # 2. Resize (2x) to fix small text
            resized = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            
            # Save processed version
            proc_path = image_path.replace(".png", "_ocr.png")
            cv2.imwrite(proc_path, resized)
            return proc_path
        except Exception as e:
            self.logger.error(f"Preprocessing failed: {e}")
            return None

    def skip_ads(self):
        """
        Forcefully skips ads by accelerating playback and clicking skip buttons.
        """
        try:
            # 1. Acceleration & Muting (Must be JS for speed and reliability)
            # This also handles 'Force Play' if the ad is paused at the start
            js_accelerate = """
            try {
                const video = document.querySelector('video.html5-main-video') || document.querySelector('video');
                if (video) {
                    video.playbackRate = 16.0;
                    video.muted = true;
                    if (video.paused) video.play();
                }
                
                // Close overlay banners if present
                const closeBtn = document.querySelector('.ytp-ad-overlay-close-button');
                if (closeBtn) closeBtn.click();
                
                return true;
            } catch(e) {}
            return false;
            """
            self.page.run_js(js_accelerate)

            # 2. Modern Skip Button Search (Classes + Shadow DOM)
            skip_selectors = [
                '.ytp-ad-skip-button-modern', 
                '.ytp-ad-skip-button', 
                '.ytp-ad-skip-button-container',
                '.ytp-ad-skip-button-slot',
                'button.ytp-ad-skip-button',
                '.video-ads .ytp-ad-skip-button-slot'
            ]
            
            # Deep Search: Global -> Player Shadow Root -> Ad Module Shadow Root
            def try_click(root, sel):
                target = root.ele(sel, timeout=0.1)
                if target and target.states.is_displayed:
                    target.click()
                    return True
                return False

            for selector in skip_selectors:
                # 1. Global
                if try_click(self.page, selector): return True
                
                # 2. Player Shadow Root
                player = self.page.ele('#movie_player', timeout=0.1) or self.page.ele('ytd-player', timeout=0.1)
                if player and player.sr:
                    if try_click(player.sr, selector): return True
                    
                # 3. Ad module/Video Ads
                ad_container = self.page.ele('.video-ads', timeout=0.1) or self.page.ele('.ytp-ad-module', timeout=0.1)
                if ad_container:
                    if try_click(ad_container, selector): return True

            # 3. Fuzzy Text & Interactive Fallback (Narrowed to player)
            js_fuzzy_click = """
            try {
                const player = document.querySelector('ytd-player') || document.querySelector('#movie_player');
                if (!player) return false;
                const terms = ['Skip', 'Advertising', 'Continue', 'Next', 'Dismiss'];
                const buttons = player.querySelectorAll('button, a, .ytp-ad-skip-button-text');
                for (const btn of buttons) {
                    if (terms.some(t => btn.innerText && btn.innerText.includes(t))) {
                        btn.click();
                        return true;
                    }
                }
            } catch(e) {}
            return false;
            """
            if self.page.run_js(js_fuzzy_click):
                self.logger.info("[*] Ad Skipped via Fuzzy Text Match")
                return "Skipped Fuzzy"

            return "Accelerating"

        except Exception as e:
            self.logger.error(f"[-] Skip ads failed: {e}")
            return "Error"

    def _get_text(self, ocr_image_path):
        """Extract full text from preprocessed image using EasyOCR."""
        try:
            if not self.reader:
                return ""
            # EasyOCR returns a list of results (bbox, text, confidence)
            results = self.reader.readtext(ocr_image_path)
            text = " ".join([res[1] for res in results])
            return text.strip()
        except Exception as e:
            self.logger.warning(f"[!] OCR Error: {e}")
            return ""

    def is_terminal_window(self, frame_path):
        """Heuristic to detect if frame is likely a terminal."""
        try:
            img = cv2.imread(frame_path)
            if img is None: return False
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            # Terminals are usually dark. Check ratio of dark pixels (< 50 brightness)
            dark_pixels = np.sum(gray < 50)
            total_pixels = gray.size
            return (dark_pixels / total_pixels) > 0.70
        except:
            return False

    def is_ad_content(self, frame, text: str) -> bool:
        """Heuristic to detect YouTube ads based on keywords and frame characteristics."""
        text_lower = text.lower()
        ad_keywords = ["skip ad", "advertisement", "sponsored", "visit site", "video will play after ad"]
        
        # Keyword match
        if any(kw in text_lower for kw in ad_keywords):
            return True
            
        # Common ad layout: Very short text in a GUI window often indicates a transition or ad overlay
        if not self.is_terminal_window(frame) and len(text.strip()) < 15:
            # This is a bit aggressive, but helps skip banners
            # Avoid skipping if it's a very clear UI change
            pass
            
        return False

    def chunk_results(self, results, interval=120):
        """
        Splits the results into timestamped chunks for LLM ingestion.
        interval: Chunk size in seconds (default 2 minutes).
        """
        if not results:
            return []
            
        chunks = []
        current_chunk = {
            "start_time": results[0]["timestamp"],
            "end_time": results[0]["timestamp"],
            "combined_text": ""
        }
        
        last_text = ""
        for res in results:
            if res["timestamp"] - current_chunk["start_time"] > interval:
                # Close current chunk
                chunks.append(current_chunk)
                # Start new chunk
                current_chunk = {
                    "start_time": res["timestamp"],
                    "end_time": res["timestamp"],
                    "combined_text": ""
                }
            
            # Deduplicate text within chunk if very similar to previous frame
            if res["ocr_text"] != last_text:
                current_chunk["combined_text"] += f"\n[{res['timestamp']:.1f}s] {res['ocr_text']}"
                last_text = res["ocr_text"]
            
            current_chunk["end_time"] = res["timestamp"]
            
        chunks.append(current_chunk)
        return chunks

    def run(self, url, max_duration=None, chunk_interval=120):
        """Main scraping loop. Returns chunked OCR results."""
        self.logger.info(f"[*] Starting scrape: {url}")
        self.page.get(url)
        
        # Wait for video to be ready and metadata to load
        self.page.wait.ele_displayed('.html5-main-video', timeout=15)
        time.sleep(3) # Extra buffer for JS to update duration
        
        # Initial Quality Set
        self.force_high_quality()
        
        # Determine actual duration to scrape
        video_duration = self.get_video_duration()
        if max_duration is None or max_duration > video_duration:
            max_duration = video_duration
        
        self.logger.info(f"[*] Scraping for {max_duration:.1f}s (Video Total: {video_duration:.1f}s)")
        
        start_time = time.time()
        frames_saved = 0
        is_ui_hidden = False
        raw_results = []
        
        curr_video_time = 0
        while curr_video_time < max_duration:
            try:
                # 1. Detection
                video_node, is_ad, is_visible = self._get_active_video()
                
                if not video_node:
                    self.logger.info("[?] Waiting for video element...")
                    time.sleep(1)
                    continue

                # 2. Ad Management
                if is_ad:
                    if is_ui_hidden:
                        self.toggle_chrome(True)
                        is_ui_hidden = False
                    self.skip_ads()
                    self.logger.info("[!] Ad detected - managing...")
                    time.sleep(0.5)
                    continue
                else:
                    # Not an ad: ensure playback and normal speed
                    js_resume = """
                    try {
                        const v = document.querySelector('video');
                        if (v) {
                            if (v.playbackRate > 1.0) v.playbackRate = 1.0;
                            if (v.muted) v.muted = false;
                            if (v.paused) v.play();
                        }
                    } catch(e) {}
                    """
                    self.page.run_js(js_resume)
                    if frames_saved % 20 == 0:
                        self.force_high_quality()

                # 3. Capture Frame
                if is_visible:
                    if not is_ui_hidden:
                        self.toggle_chrome(False)
                        is_ui_hidden = True
                        
                    # Get current video timestamp
                    curr_video_time = self.page.run_js("return document.querySelector('video').currentTime;")
                    
                    frame_name = f"frame_{frames_saved:04d}.png"
                    frame_path = os.path.join(self.output_dir, frame_name)
                    video_node.get_screenshot(path=frame_path)
                    
                    # 4. Change Detection (Hybrid)
                    curr_hist = self._get_histogram(frame_path)
                    ocr_path = self._preprocess_for_ocr(frame_path)
                    curr_text = self._get_text(ocr_path)
                    curr_text_len = len(curr_text)
                    curr_time = time.time()
                    
                    self.is_terminal_mode = self.is_terminal_window(frame_path)
                    
                    should_save = False
                    reason = ""
                    
                    if self.last_histogram is None:
                        should_save = True
                        reason = "Initial frame"
                    else:
                        dist = cv2.compareHist(self.last_histogram, curr_hist, cv2.HISTCMP_BHATTACHARYYA)
                        if dist > 0.005: # More sensitive threshold
                            should_save = True
                            reason = f"Visual change ({dist:.3f})"
                        
                        len_diff = abs(curr_text_len - self.last_text_len)
                        if len_diff > 5: # More sensitive
                            should_save = True
                            reason = f"Text change ({len_diff})"
                        
                        if self.is_terminal_mode and (curr_time - self.last_capture_time > 1.5):
                            if len_diff > 2:
                                should_save = True
                                reason = "Terminal update"

                    if should_save and not self.is_ad_content(frame_path, curr_text):
                        self.logger.info(f"[+] Captured frame {frames_saved} - T:{curr_video_time:.1f}s - Reason: {reason}")
                        
                        # Keep OCR text only if it has content
                        if curr_text_len > 10:
                            raw_results.append({
                                "timestamp": curr_video_time,
                                "ocr_text": curr_text,
                                "is_terminal": self.is_terminal_mode
                            })
                            frames_saved += 1
                        
                        self.last_histogram = curr_hist
                        self.last_text_len = curr_text_len
                        self.last_capture_time = curr_time
                    
                    # Clean up images immediately to save space
                    if os.path.exists(frame_path): os.remove(frame_path)
                    if os.path.exists(ocr_path): os.remove(ocr_path)
                
                time.sleep(1/3) # Moderate sampling rate
                
            except Exception as e:
                self.logger.error(f"[-] Loop iteration error: {e}")
                time.sleep(1)

        self.logger.info(f"[*] Raw capture complete. Chunking {len(raw_results)} data points...")
        chunked_results = self.chunk_results(raw_results, interval=chunk_interval)
        
        self.page.quit()
        return chunked_results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://www.youtube.com/watch?v=SrBYVkTVZyw")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    
    scraper = AdvancedYTScraper()
    scraper.run(args.url, args.duration)
