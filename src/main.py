# src/main.py
import requests
import time
import os

# Config
ADGUARD_HOST = os.getenv("ADGUARD_HOST", "http://dns-server:3000")
TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "xsts.auth.xboxlive.com")
BLOCK_INTERVAL = 3  # Seconds block
ALLOW_INTERVAL = 1  # Seconds allow

def set_filter(action):
    print(f"Setze Filter auf: {action}")

while True:
    set_filter("BLOCK")
    time.sleep(BLOCK_INTERVAL)
    set_filter("ALLOW")
    time.sleep(ALLOW_INTERVAL)