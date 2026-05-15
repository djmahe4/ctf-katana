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
    def __init__(self, output_dir="frames"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger("YTScraper")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            
        # Optimized browser setup
        co = ChromiumOptions()
        co.incognito(True)
        co.set_argument('--mute-audio')
        co.set_argument('--window-size=1280,720')
        co.headless(True) # Optional
        self.page = ChromiumPage(co)
        self.page.listen.start() # Start listening to all packets
        
        self.last_histogram = None
        self.last_text_len = 0
        self.last_capture_time = 0
        self.is_terminal_mode = False
        self.video_metadata = {}
        self._main_video_duration = 0
        self.screenshot_interval = 2.0 # Default interval between frame captures
        
        # EasyOCR Setup
        if easyocr:
            try:
                # Attempt to use GPU if available
                self.reader = easyocr.Reader(['en'], gpu=True)
                self.logger.info("[*] EasyOCR initialized with GPU acceleration.")
            except Exception as e:
                self.logger.warning(f"[*] EasyOCR GPU failed, falling back to CPU: {e}")
                self.reader = easyocr.Reader(['en'], gpu=False)
        else:
            self.reader = None
            self.logger.warning("EasyOCR not found. OCR extraction will be disabled.")

        # Network Listener for Transcripts (timedtext)
        self.page.listen.start('timedtext')
        self.transcript_segments = []

    def _process_timedtext(self):
        """Checks for captured timedtext packets and parses them into segments (Non-blocking)."""
        for packet in self.page.listen.steps(timeout=0):
            if 'timedtext' not in packet.url:
                continue
            try:
                data = packet.response.body
                if not data: continue
                
                # Handle bytes vs dict
                if isinstance(data, (bytes, bytearray)):
                    try:
                        data = json.loads(data.decode('utf-8'))
                    except: continue
                elif isinstance(data, str):
                    try:
                        data = json.loads(data)
                    except: continue
                
                if isinstance(data, dict) and 'events' in data:
                    new_events = 0
                    for event in data['events']:
                        if 'segs' in event:
                            text = "".join([s['utf8'] for s in event['segs'] if 'utf8' in s]).strip()
                            if text:
                                start_ms = event.get('tStartMs', 0)
                                duration_ms = event.get('dDurationMs', 0)
                                self.transcript_segments.append({
                                    "start": start_ms / 1000.0,
                                    "end": (start_ms + duration_ms) / 1000.0,
                                    "text": text
                                })
                                new_events += 1
                    if new_events > 0:
                        self.logger.info(f"[+] Captured {new_events} transcript segments from network.")
            except Exception as e:
                self.logger.debug(f"Failed to parse timedtext packet: {e}")
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
        Detects the current active video and ad state.
        Returns: (video_element, is_ad, is_visible)
        """
        try:
            video = self.page.ele('tag:video', timeout=2)
            if not video:
                return None, False, False

            # Accurate Ad Detection Heuristic
            js_ad_check = """
            (() => {
                const player = document.getElementById('movie_player') || document.querySelector('.html5-video-player');
                const video = document.querySelector('video');
                if (!player || !video) return {is_ad: false};
                
                const isVisible = (el) => el && (el.offsetWidth > 0 || el.offsetHeight > 0);

                // 1. Visit Advertiser Links / Component Markers (User Signal)
                const advertiserSelectors = [
                    '.ytp-visit-advertiser-link', '.ytp-ad-component--clickable', 
                    '.ytp-ad-visit-advertiser-button', '.ytp-ad-player-overlay'
                ];
                for (const s of advertiserSelectors) {
                    if (isVisible(document.querySelector(s))) return {is_ad: true, trigger: s};
                }

                // 2. Explicit classes and containers
                if (player.classList.contains('ad-showing') || player.classList.contains('ad-interrupting')) {
                    return {is_ad: true, trigger: 'player-class'};
                }
                if (isVisible(document.querySelector('.ad-showing')) || 
                    isVisible(document.querySelector('.ad-interrupting')) ||
                    isVisible(document.querySelector('.ytp-ad-module'))) {
                    return {is_ad: true, trigger: 'ad-container'};
                }
                
                // 3. Skip Button (Modern and Legacy)
                const skipSelectors = [
                    '.ytp-ad-skip-button', '.ytp-ad-skip-button-modern', 
                    '.ytp-ad-skip-button-container', '.ytp-ad-skip-button-slot'
                ];
                for (const s of skipSelectors) {
                    if (isVisible(document.querySelector(s))) return {is_ad: true, trigger: s};
                }

                // 4. Text-based labels and Badges
                const adLabels = document.querySelectorAll('.ytp-ad-text, .ytp-ad-badge-label-text, .ytp-ad-simple-ad-badge, .ytp-ad-badge, .ytp-ad-preview-text, .ytp-visit-advertiser-link__text');
                for (const label of adLabels) {
                    if (isVisible(label)) {
                        const txt = label.innerText.trim().toLowerCase();
                        if (txt.includes('ad') || txt.includes('sponsored') || txt.includes('youtube.com')) {
                            return {is_ad: true, trigger: 'badge-' + txt.substring(0, 10)};
                        }
                    }
                }

                // 5. API Check
                if (player.getVideoData) {
                    const data = player.getVideoData();
                    if (data && (data.isAd || data.ad_id)) return {is_ad: true, trigger: 'api-data'};
                }
                
                return {is_ad: false};
            })()
            """
            ad_res = self.page.run_js(js_ad_check)
            if not ad_res:
                ad_res = {'is_ad': False}
            
            is_ad = ad_res.get('is_ad', False)
            if is_ad:
                self.logger.info(f"[!] Ad detected - Trigger: {ad_res.get('trigger')}")
            
            # If ad is detected, try to FAST FORWARD it and CLICK SKIP
            if is_ad:
                self.page.run_js("""
                    const v = document.querySelector('video');
                    if (v && v.duration > 0 && v.currentTime < v.duration - 0.1) {
                        v.currentTime = v.duration - 0.1;
                        v.playbackRate = 16.0; 
                    }
                    
                    // Deep Skip Search
                    const findAndClickSkip = () => {
                        // 1. Primary selectors
                        const selectors = [
                            '.ytp-ad-skip-button', '.ytp-ad-skip-button-modern', 
                            '.ytp-ad-skip-button-container', '.ytp-ad-skip-button-slot',
                            '.ytp-ad-skip-button-text', '.ytp-ad-preview-container'
                        ];
                        for (const s of selectors) {
                            const btn = document.querySelector(s);
                            if (btn) {
                                btn.click();
                                const inner = btn.querySelector('button');
                                if (inner) inner.click();
                            }
                        }
                        
                        // 2. Text-based search (Highly robust for variations)
                        const allBtns = document.querySelectorAll('button, div[role="button"], .ytp-ad-component');
                        for (const b of allBtns) {
                            if (b.innerText && b.innerText.toLowerCase().includes('skip')) {
                                b.click();
                            }
                        }
                    };
                    findAndClickSkip();
                """)
            
            is_visible = False
            try:
                is_visible = video.states.is_displayed and video.rect.size[0] > 0
            except: pass
            
            return video, bool(is_ad), is_visible

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

    def _get_video_duration(self):
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
    
    def immediate_skip_ads(self):
        """Proactive ad skipping during initial page load."""
        self.logger.info("[*] Polling for initial ads (15s)...")
        # Try to set expected duration early if possible
        try:
            dur = self.get_video_duration()
            if dur > 0:
                self._main_video_duration = dur
                self.page.run_js(f"window._expected_duration = {dur};")
        except: pass

        for i in range(15):
            video_node, is_ad, _ = self._get_active_video()
            if is_ad:
                self.logger.info(f"[*] Initial ad detected (poll {i+1}), skipping...")
                try:
                    self.page.run_js("""
                        const video = document.querySelector('video');
                        if (video) video.currentTime = video.duration || 999;
                        const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern');
                        if (skipBtn) skipBtn.click();
                    """)
                except: pass
            else:
                # Check if we are on the main video
                v_dur_res = self.page.run_js("return document.querySelector('video') ? document.querySelector('video').duration : 0")
                v_dur = float(v_dur_res) if v_dur_res else 0
                if self._main_video_duration > 0 and abs(v_dur - self._main_video_duration) < 2:
                    self.logger.info("[*] Main video confirmed, stopping proactive poll.")
                    break
            time.sleep(1)

    def skip_ads(self, video_ele=None):
        """Accelerate and skip ads using targeted video element."""
        js_skip = """
        (v) => {
            const video = v || document.querySelector('video');
            if (!video) return "no_video";
            
            const getPlayer = (el) => {
                const mp = document.getElementById('movie_player');
                if (mp) return mp;
                const container = document.querySelector('.html5-video-player');
                if (container) return container;
                let root = el;
                while (root) {
                    if (root.classList && root.classList.contains('html5-video-player')) return root;
                    root = root.parentNode || root.host;
                }
                return null;
            };
            const player = getPlayer(video);
            
            // 1. Mute and Max Speed
            video.muted = true;
            video.playbackRate = 16.0;
            if (player && typeof player.setPlaybackRate === 'function') {
                player.setPlaybackRate(16);
            }
            if (video.paused) video.play();
            
            // 2. Identify skip button
            const skipSelectors = [
                '.ytp-ad-skip-button', '.ytp-ad-skip-button-modern', 
                '.ytp-skip-ad-button', '.videoAdUiSkipButton',
                '.ytp-ad-skip-button-container', '.ytp-ad-skip-button-slot'
            ];
            
            let skipBtn = null;
            if (player) {
                for (let s of skipSelectors) {
                    const btn = player.querySelector(s);
                    if (btn && (btn.offsetHeight > 0 || btn.offsetWidth > 0)) {
                        skipBtn = btn;
                        break;
                    }
                }
            }

            // 3. Action: Click Skip or Fast Forward
            if (skipBtn) {
                skipBtn.click();
                ['mousedown', 'mouseup', 'click'].forEach(type => {
                    skipBtn.dispatchEvent(new MouseEvent(type, {bubbles: true}));
                });
                return "skipped_via_button";
            }
            
            // 4. Fast Forward / Jump to end if not skippable
            // KEY FIX: Compare video.duration (element) with expected duration.
            // DO NOT trust player.getDuration() here as it returns main video length during ads.
            const expectedDur = window._expected_duration || 0;
            const isMainVideo = !!(expectedDur > 0 && video.duration > 0 && Math.abs(video.duration - expectedDur) < 2);
            
            // If it's NOT the main video and it's short (typical for ads), jump!
            if (!isMainVideo && video.duration > 0 && video.duration < 600) {
                video.currentTime = video.duration - 0.3;
                return "jumped_to_end";
            }

            return "fast_forwarding";
        }
        """
        try:
            result = self.page.run_js(js_skip, video_ele)
            return result
        except Exception as e:
            return f"error: {str(e)}"

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
        Combines Transcript (Spoken) and OCR (Visual).
        """
        if not results and not self.transcript_segments:
            return []
            
        chunks = []
        # Find start and end
        all_times = [r["timestamp"] for r in results] + [s["start"] for s in self.transcript_segments]
        if not all_times: return []
        
        min_t = min(all_times)
        max_t = max(all_times)
        
        for chunk_start in np.arange(min_t, max_t, interval):
            chunk_end = chunk_start + interval
            
            # 1. Get Transcript for this range
            spoken = " ".join([s["text"] for s in self.transcript_segments if chunk_start <= s["start"] < chunk_end])
            
            # 2. Get OCR for this range
            visual_events = [r for r in results if chunk_start <= r["timestamp"] < chunk_end]
            
            visual_text = ""
            last_ocr = ""
            for ev in visual_events:
                if ev["ocr_text"] != last_ocr and len(ev["ocr_text"]) > 10:
                    visual_text += f"\n[{ev['timestamp']:.1f}s] {ev['ocr_text']}"
                    last_ocr = ev["ocr_text"]
            
            combined = f"--- SEGMENT [{chunk_start:.1f}s - {chunk_end:.1f}s] ---\n"
            if spoken:
                combined += f"SPEAKER_CONTENT: {spoken}\n"
            if visual_text:
                combined += f"VISUAL_CONTEXT (OCR): {visual_text}\n"
                
            chunks.append({
                "start_time": chunk_start,
                "end_time": chunk_end,
                "combined_text": combined
            })
            
        return chunks

    def _init_player(self):
        """Initializes the YouTube player, handles quality, and enables captions."""
        try:
            # Wait for video to be ready
            self.page.wait.ele_displayed('.html5-main-video', timeout=15)
            time.sleep(3) # Extra buffer for JS
            
            # Force high quality
            self.force_high_quality()
            
            # Proactively enable CC to trigger timedtext packets
            self.page.run_js("""
                try {
                    const player = document.getElementById('movie_player') || document.querySelector('.html5-video-player');
                    if (player && player.loadModule) player.loadModule('captions');
                    const ccBtn = document.querySelector('.ytp-subtitles-button');
                    if (ccBtn && ccBtn.getAttribute('aria-pressed') === 'false') {
                        ccBtn.click();
                    }
                } catch(e) {}
            """)
            
            # Initial Skip Ads and Get Duration
            self.immediate_skip_ads()
            dur = self._get_video_duration()
            self._main_video_duration = dur
            self.page.run_js(f"window._expected_duration = {dur};")
            self.logger.info(f"[*] Player initialized. Video duration: {dur}s")
        except Exception as e:
            self.logger.warning(f"[!] Player initialization issues: {e}")

    def run(self, video_url, max_duration=3600, chunk_interval=180):
        """
        Main scraping loop.
        Refactored as a generator to yield chunked results in real-time.
        """
        self.video_url = video_url
        self.page.get(video_url)
        self._init_player()
        
        video_duration = self._get_video_duration()
        if max_duration is None or max_duration > video_duration:
            max_duration = video_duration
            
        self.logger.info(f"[*] Starting scraper on {video_url} (Max: {max_duration}s)")
        
        frames_saved = 0
        raw_results = []
        is_ui_hidden = False
        last_chunk_video_time = 0
        
        # Initial wait for player
        time.sleep(5)
        self.force_high_quality()

        curr_video_time = 0
        while curr_video_time < max_duration:
            try:
                # 1. Detection
                video_node, is_ad, is_visible = self._get_active_video()
                
                if not video_node:
                    time.sleep(1)
                    continue

                # Process transcripts
                if not is_ad:
                    self._process_timedtext()

                # 2. Ad Management
                if is_ad:
                    if is_ui_hidden:
                        self.toggle_chrome(True)
                        is_ui_hidden = False
                    self.logger.info(f"[!] Ad detected - forcing skip...")
                    self.page.run_js("""
                        const video = document.querySelector('video');
                        if (video) video.currentTime = video.duration || 999;
                        const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern');
                        if (skipBtn) skipBtn.click();
                    """)
                    time.sleep(1)
                    continue
                else:
                    # Not an ad: ensure playback and normal speed
                    self.page.run_js("""
                        try {
                            const v = document.querySelector('video');
                            if (v && v.playbackRate > 1.0) v.playbackRate = 1.0;
                        } catch(e) {}
                    """)
                    if frames_saved % 20 == 0:
                        self.force_high_quality()

                # EMERGENCY AD CHECK
                is_ad_emergency = self.page.run_js("""
                    const isVisible = (el) => el && (el.offsetWidth > 0 || el.offsetHeight > 0);
                    const selectors = ['.ytp-ad-skip-button', '.ytp-ad-badge', '.ad-showing', '.ad-interrupting'];
                    return selectors.some(s => isVisible(document.querySelector(s)));
                """)
                if is_ad_emergency:
                    self.page.run_js("const v = document.querySelector('video'); if (v) v.currentTime = v.duration || 999;")
                    continue

                # 3. Capture Frame
                if is_visible:
                    if not is_ui_hidden:
                        self.toggle_chrome(False)
                        is_ui_hidden = True
                    
                    curr_video_time = self.page.run_js("return document.querySelector('video').currentTime;")
                    
                    frame_name = f"frame_{frames_saved:04d}.png"
                    frame_path = os.path.join(self.output_dir, frame_name)
                    
                    try:
                        self.page.ele('tag:video').get_screenshot(path=frame_path)
                    except:
                        video_node.get_screenshot(path=frame_path)

                    ocr_path = self._preprocess_for_ocr(frame_path)
                    curr_text = self._get_text(ocr_path)
                    curr_hist = self._get_histogram(frame_path)
                    
                    should_save = False
                    if self.last_histogram is None:
                        should_save = True
                    else:
                        dist = cv2.compareHist(self.last_histogram, curr_hist, cv2.HISTCMP_BHATTACHARYYA)
                        if dist > 0.005 or abs(len(curr_text) - self.last_text_len) > 5:
                            should_save = True

                    if should_save and not self.is_ad_content(frame_path, curr_text):
                        raw_results.append({
                            "timestamp": curr_video_time,
                            "ocr_text": curr_text,
                            "is_terminal": self.is_terminal_window(frame_path)
                        })
                        frames_saved += 1
                        self.last_histogram = curr_hist
                        self.last_text_len = len(curr_text)
                    
                    if os.path.exists(frame_path): os.remove(frame_path)
                    if os.path.exists(ocr_path): os.remove(ocr_path)

                # 4. Generator Chunking Logic
                if curr_video_time >= last_chunk_video_time + chunk_interval:
                    chunk_data = self._process_current_chunk(raw_results, last_chunk_video_time, curr_video_time)
                    if chunk_data:
                        self.logger.info(f"[*] Yielding chunk at {int(curr_video_time)}s")
                        yield chunk_data
                    last_chunk_video_time = curr_video_time

                time.sleep(self.screenshot_interval)

            except Exception as e:
                self.logger.error(f"[!] Scraper loop error: {e}")
                time.sleep(1)

        # Final yield
        if curr_video_time > last_chunk_video_time:
            chunk_data = self._process_current_chunk(raw_results, last_chunk_video_time, curr_video_time)
            if chunk_data:
                yield chunk_data
        
        self.page.quit()

    def _process_current_chunk(self, results, start_t, end_t):
        """Helper to slice results and transcripts for a specific time range."""
        chunk_results = [r for r in results if start_t <= r["timestamp"] < end_t]
        chunk_transcripts = [s for s in self.transcript_segments if start_t <= s["start"] < end_t]
        
        if not chunk_results and not chunk_transcripts:
            return None
            
        return {
            "start": start_t,
            "end": end_t,
            "visuals": chunk_results,
            "transcripts": chunk_transcripts
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="https://www.youtube.com/watch?v=SrBYVkTVZyw")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    
    scraper = AdvancedYTScraper()
    scraper.run(args.url, args.duration)
