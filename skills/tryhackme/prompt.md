# TryHackMe Research Skill

You are an expert at extracting CTF training data from TryHackMe rooms and writeups.

## Strategy

1. **Room Discovery**: Use the scraper to find relevant rooms based on the query or difficulty filters (Medium, Hard, Insane).
2. **Writeup Retrieval**: Search for high-quality writeups across multiple platforms:
   - **GitHub**: Prefer raw markdown files for high-fidelity extraction.
   - **Medium/Freedium**: Use mirror services to bypass paywalls.
   - **YouTube**: Use OCR and transcript extraction for video-only content.
3. **Data Synthesis**: Use an LLM to parse extracted text into structured instruction-output pairs suitable for training a security model.
4. **Validation**: Ensure instructions describe clear security tasks and outputs contain specific commands or technical explanations.

## Tips

- Prioritize markdown writeups for better structural accuracy.
- For YouTube videos, focus on terminal outputs captured via OCR.
- If a room is premium, focus heavily on external search results.
- Ensure the final dataset adheres to the official Gemma 4 Instruct template format.
