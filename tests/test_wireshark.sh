#!/bin/bash
# Wireshark packet capture for testing

echo "Starting Wireshark capture on loopback interface..."
echo "Capturing traffic on port 5555"
echo "Press Ctrl+C to stop capture"
echo ""

# Start capture
sudo tcpdump -i lo port 5555 -w captures/securechat_capture.pcap

echo ""
echo "Capture saved to: captures/securechat_capture.pcap"
echo "To analyze with Wireshark: wireshark captures/securechat_capture.pcap"
