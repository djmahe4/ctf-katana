import os
import time
import json
import logging
from datetime import datetime
import cv2
import numpy as np
from PIL import Image
import pytesseract
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
        
        # Optional: Set tesseract path if found in common Windows locations
        tess_paths = [
            r'C:\Program Files\Tesseract-OCR\tesseract.exe',
            r'C:\Users\mahes\AppData\Local\Tesseract-OCR\tesseract.exe'
        ]
        for p in tess_paths:
            if os.path.exists(p):
                pytesseract.pytesseract.tesseract_cmd = p
                break

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
            # 1. Locate the player and video using DrissionPage's built-in Shadow DOM handling
            # ytd-player is the main container; the video is deep inside it.
            # DrissionPage's .ele() with 'video.html5-main-video' often works but might need sr()
            video = self.page.ele('.html5-main-video', timeout=2)
            
            if not video:
                # Fallback: search within ytd-player's shadow root
                player_container = self.page.ele('ytd-player', timeout=1)
                if player_container:
                    video = player_container.sr('t:video') or player_container.sr('.html5-main-video')

            if not video:
                # Final fallback for unusual layouts (e.g., shorts or embedded)
                video = self.page.ele('t:video', timeout=1)

            if not video:
                return None, False, False

            # 2. Aggressive Ad Detection (JS for maximum reach)
            js_ad_check = """
            try {
                const player = document.querySelector('ytd-player') || document.querySelector('#movie_player');
                if (!player) return false;
                
                // 1. Official State Indicators (High Confidence)
                const isAdClass = player.classList.contains('ad-showing') || player.classList.contains('ad-interrupting');
                
                // 2. Clear Ad Components (High Confidence)
                const adModule = player.querySelector('.ytp-ad-module');
                const hasAdModule = adModule && adModule.children.length > 0;
                
                // 3. Skip Buttons (Indisputable)
                const hasSkipBtn = !!player.querySelector('.ytp-ad-skip-button') || 
                                 !!player.querySelector('.ytp-ad-skip-button-modern') ||
                                 !!player.querySelector('.ytp-ad-skip-button-container');
                
                return isAdClass || hasAdModule || hasSkipBtn;
            } catch(e) { return false; }
            """
            is_ad = self.page.run_js(js_ad_check)

            # 3. Visibility Check
            # Use DrissionPage's native rect and states properties
            is_visible = False
            try:
                rect = video.rect.size
                is_visible = rect[0] > 0 and rect[1] > 0 and video.states.is_displayed
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

    def _preprocess_for_ocr(self, image_path):
        """Optimizes images for Tesseract OCR: Resize + Grayscale + Adaptive Threshold."""
        try:
            img = cv2.imread(image_path)
            if img is None: return None
            
            # 1. Grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # 2. Resize (2x) to fix aliasing/small text
            resized = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            
            # 3. Adaptive Thresholding (handle shadows/gradients)
            processed = cv2.adaptiveThreshold(
                resized, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                cv2.THRESH_BINARY, 11, 2
            )
            
            # Save processed version
            proc_path = image_path.replace(".png", "_ocr.png")
            cv2.imwrite(proc_path, processed)
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
        """Extract full text from preprocessed image."""
        try:
            # Use PSM 6 (Assume a uniform block of text) for faster terminal OCR
            text = pytesseract.image_to_string(Image.open(ocr_image_path), config='--psm 6')
            return text.strip()
        except Exception as e:
            self.logger.warning(f"[!] OCR Error: {e}")
            return ""

    def _is_terminal(self, frame_path):
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

    def run(self, url, max_duration=60):
        """Main scraping loop."""
        self.logger.info(f"[*] Starting scrape: {url}")
        self.page.get(url)
        
        # Initial Quality Set
        self.force_high_quality()
        
        start_time = time.time()
        frames_saved = 0
        is_ui_hidden = False
        
        while time.time() - start_time < max_duration:
            try:
                # 1. Detection
                video_node, is_ad, is_visible = self._get_active_video()
                
                if not video_node:
                    self.logger.info("[?] Waiting for video element...")
                    time.sleep(1)
                    continue

                # 2. Ad Management
                if is_ad:
                    # Restore UI to see what we're skipping
                    if is_ui_hidden:
                        self.toggle_chrome(True)
                        is_ui_hidden = False
                    self.skip_ads()
                    self.logger.info("[!] Ad detected - managing...")
                    time.sleep(0.5)
                    continue
                else:
                    # Recovery: Ensure video is playing at normal speed
                    js_reset = """
                    const v = document.querySelector('video');
                    if (v && v.playbackRate > 1.0) {
                        v.playbackRate = 1.0;
                        v.muted = false;
                    }
                    """
                    self.page.run_js(js_reset)
                    # Periodic quality check
                    if frames_saved % 20 == 0:
                        self.force_high_quality()

                # 3. Capture Frame
                if is_visible:
                    # Persistently hide UI while in "Real Content" mode
                    if not is_ui_hidden:
                        self.toggle_chrome(False)
                        is_ui_hidden = True
                        
                    frame_path = os.path.join(self.output_dir, f"frame_{frames_saved:04d}.png")
                    video_node.get_screenshot(path=frame_path)
                    
                    # 4. Change Detection (Hybrid)
                    curr_hist = self._get_histogram(frame_path)
                    
                    # Preprocess for OCR first to get text
                    ocr_path = self._preprocess_for_ocr(frame_path)
                    curr_text = self._get_text(ocr_path)
                    curr_text_len = len(curr_text)
                    curr_time = time.time()
                    
                    # Detect Terminal Mode
                    self.is_terminal_mode = self._is_terminal(frame_path)
                    
                    # Decision Logic
                    should_save = False
                    reason = ""
                    
                    if self.last_histogram is None:
                        should_save = True
                        reason = "Initial frame"
                    else:
                        # 1. Histogram Check
                        dist = cv2.compareHist(self.last_histogram, curr_hist, cv2.HISTCMP_BHATTACHARYYA)
                        if dist > 0.01:
                            should_save = True
                            reason = f"Visual change (dist: {dist:.3f})"
                        
                        # 2. Text Length Check (High priority for terminals)
                        len_diff = abs(curr_text_len - self.last_text_len)
                        if len_diff > 10:
                            should_save = True
                            reason = f"Text change (diff: {len_diff})"
                        
                        # 3. Terminal Timing Guard (1s gap)
                        if self.is_terminal_mode and (curr_time - self.last_capture_time > 1.0):
                            if len_diff > 2: # Even a tiny text change in terminal is notable
                                should_save = True
                                reason = "Terminal update (1s interval)"

                    if should_save:
                        self.logger.info(f"[+] Saved frame {frames_saved} - Reason: {reason}")
                        
                        # Save extracted text to .txt file
                        txt_path = frame_path.replace(".png", ".txt")
                        with open(txt_path, "w", encoding="utf-8") as f:
                            f.write(curr_text)
                            
                        frames_saved += 1
                        self.last_histogram = curr_hist
                        self.last_text_len = curr_text_len
                        self.last_capture_time = curr_time
                    else:
                        os.remove(frame_path)
                        if os.path.exists(ocr_path): os.remove(ocr_path)
                
                time.sleep(1/5)
                
            except Exception as e:
                self.logger.error(f"[-] Loop iteration error: {e}")
                time.sleep(1)

        self.logger.info(f"[*] Scrape complete. Saved {frames_saved} unique frames.")
        self.page.quit()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://www.youtube.com/watch?v=3ku98xRQ9Ls")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    
    scraper = AdvancedYTScraper()
    scraper.run(args.url, args.duration)
