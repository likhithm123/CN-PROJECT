#!/usr/bin/env python3
"""
Real-Time Hybrid Network Intrusion Detection & Adaptive QoS Mitigation System
BCSE308P Computer Networks Capstone Project
Unified Launcher
"""
import sys
import argparse
import uvicorn
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_INTERFACE, ISOLATION_FOREST_PATH
from training.train_models import train_and_save_models

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Launch Real-Time Hybrid NIDS & Adaptive QoS Mitigation Engine"
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host interface (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port number (default: {DEFAULT_PORT})")
    parser.add_argument("--iface", default=DEFAULT_INTERFACE, help=f"Sniff interface e.g. eth0, en0, auto, none (default: {DEFAULT_INTERFACE})")
    parser.add_argument("--retrain", action="store_true", help="Retrain ML models prior to starting")
    parser.add_argument("--train-only", action="store_true", help="Only train models and exit")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print("\n" + "=" * 75)
    print(" 🛡️  HYBRID NETWORK INTRUSION DETECTION & ADAPTIVE QOS MITIGATION SYSTEM")
    print("    Course: BCSE308P - Computer Networks Project")
    print("=" * 75)

    # Check if models exist, or retrain requested
    if args.retrain or args.train_only or not ISOLATION_FOREST_PATH.exists():
        print(">> Initializing ML Model Pipeline (Isolation Forest + Random Forest)...")
        train_and_save_models()
        if args.train_only:
            print(">> Training complete. Exiting (--train-only).")
            return

    print(f"\n>> System Configuration:")
    print(f"   - Binding Host:     {args.host}")
    print(f"   - Web Port:         {args.port}")
    print(f"   - Sniff Interface:  {args.iface}")
    print(f"   - Dashboard URL:    http://localhost:{args.port}")
    print(f"   - API Documentation:http://localhost:{args.port}/docs")
    print(f"   - WebSocket Feed:   ws://localhost:{args.port}/ws")
    print("=" * 75)
    print(">> Starting real-time detection pipeline and dashboard server...\n")

    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        log_level="info",
        reload=False
    )

if __name__ == "__main__":
    main()
