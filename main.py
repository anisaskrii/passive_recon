#!/usr/bin/env python3
import argparse
from dotenv import load_dotenv

load_dotenv()

from recon.pipeline import run


def main():
    parser = argparse.ArgumentParser(description="Passive recon pipeline with optional low-noise active checks")
    parser.add_argument("domain", help="Target domain, example: example.com")
    parser.add_argument("--active", action="store_true", help="Run httpx, WhatWeb, and security-header checks")
    args = parser.parse_args()
    run(args.domain, active=args.active)


if __name__ == "__main__":
    main()
