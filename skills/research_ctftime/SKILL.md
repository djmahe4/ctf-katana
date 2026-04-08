---
name: "research_ctftime"
description: "Pulls upcoming CTFs and past technical writeups using the official CTFTime API. Very useful for locating real-world exploits or challenges matching our search criteria."
---

# `research_ctftime` Skill

This skill allows agents in the Purple Loop (specifically during the Research and Search KB phase) to interface dynamically with [CTFTime.org](https://ctftime.org/api/).

## Purpose
It provides a safe, API-driven method to:
1. Auto-discover upcoming CTF events to potentially pull challenge datasets from.
2. Locate past writeups corresponding to explicit vulnerabilities (useful when local KBs lack examples).

## Usage Integration
The core orchestrator should invoke `get_upcoming_ctfs()` to scan for active/pending events.
When analyzing a vulnerability or scenario without enough internal data, invoke `search_past_writeups("EventName")` to pull public intel.

## Note
Do not use this to scrape HTML. It strictly relies on the sanctioned `v1/events/` REST API endpoints.
