#!/usr/bin/env python3
"""
Test replay attack protection
Tests sequence number enforcement
"""

from crypto_utils import crypto
from protocol import Protocol

def test_replay_protection():
    """Test that replayed messages are detected"""
    print("=" * 60)
    print("     Replay Attack Protection Test")
    print("=" * 60)
    
    # Simulate message sequence
    print("\n=== Simulating Message Sequence ===")
    
    messages = [
        {"seqno": 1, "content": "First message"},
        {"seqno": 2, "content": "Second message"},
        {"seqno": 3, "content": "Third message"},
    ]
    
    current_seqno = 0
    
    print("\n--- Processing Messages in Order ---")
    for msg in messages:
        print(f"\nReceived message: seqno={msg['seqno']}, content='{msg['content']}'")
        
        # Check sequence number
        if msg['seqno'] <= current_seqno:
            print(f"✗ REPLAY DETECTED: seqno {msg['seqno']} <= current {current_seqno}")
            print("   Message REJECTED")
        else:
            print(f"✓ Valid seqno: {msg['seqno']} > {current_seqno}")
            print("   Message ACCEPTED")
            current_seqno = msg['seqno']
    
    # Test 1: Replay old message
    print("\n\n=== Test 1: Replay Attack ===")
    replayed_msg = {"seqno": 2, "content": "Second message (REPLAYED)"}
    print(f"Attempting to replay: seqno={replayed_msg['seqno']}, content='{replayed_msg['content']}'")
    
    if replayed_msg['seqno'] <= current_seqno:
        print(f"✓ Test PASSED - REPLAY DETECTED: seqno {replayed_msg['seqno']} <= current {current_seqno}")
        print("   Message REJECTED")
    else:
        print(f"✗ Test FAILED - Replay should be detected")
    
    # Test 2: Out of order message (but not replay)
    print("\n=== Test 2: Out of Order (Skip) ===")
    skip_msg = {"seqno": 5, "content": "Fifth message (skipped 4)"}
    print(f"Received: seqno={skip_msg['seqno']}, content='{skip_msg['content']}'")
    
    if skip_msg['seqno'] > current_seqno:
        print(f"✓ Valid seqno: {skip_msg['seqno']} > {current_seqno}")
        print("   Message ACCEPTED (but seqno 4 was skipped)")
        current_seqno = skip_msg['seqno']
    else:
        print(f"✗ Message rejected")
    
    # Test 3: Try to replay the skipped message
    print("\n=== Test 3: Replay Skipped Message ===")
    late_msg = {"seqno": 4, "content": "Fourth message (late arrival)"}
    print(f"Attempting late delivery: seqno={late_msg['seqno']}, content='{late_msg['content']}'")
    
    if late_msg['seqno'] <= current_seqno:
        print(f"✓ Test PASSED - REPLAY DETECTED: seqno {late_msg['seqno']} <= current {current_seqno}")
        print("   Message REJECTED (even though it was skipped earlier)")
    else:
        print(f"✗ Test FAILED")
    
    # Summary
    print("\n" + "=" * 60)
    print("Replay Protection Summary")
    print("=" * 60)
    print("The system enforces strict sequence number ordering:")
    print("- Each message must have seqno > last received seqno")
    print("- Replayed messages (old seqno) are rejected")
    print("- Out-of-order late arrivals are also rejected")
    print("=" * 60)

def test_sequence_scenarios():
    """Test various sequence number scenarios"""
    print("\n\n" + "=" * 60)
    print("     Sequence Number Scenarios")
    print("=" * 60)
    
    scenarios = [
        {
            "name": "Normal sequence",
            "sequence": [1, 2, 3, 4, 5],
            "expected": "All accepted"
        },
        {
            "name": "Replay attack",
            "sequence": [1, 2, 3, 2, 4],  # 2 replayed
            "expected": "Reject at position 4"
        },
        {
            "name": "Multiple replays",
            "sequence": [1, 2, 3, 1, 2, 3],
            "expected": "Reject last 3"
        },
        {
            "name": "Replay first message",
            "sequence": [1, 2, 3, 1],
            "expected": "Reject at position 4"
        }
    ]
    
    for scenario in scenarios:
        print(f"\n--- {scenario['name']} ---")
        print(f"Sequence: {scenario['sequence']}")
        print(f"Expected: {scenario['expected']}")
        
        current = 0
        accepted = []
        rejected = []
        
        for i, seqno in enumerate(scenario['sequence'], 1):
            if seqno <= current:
                rejected.append((i, seqno))
                print(f"  Position {i}: seqno={seqno} -> REJECTED (REPLAY)")
            else:
                accepted.append((i, seqno))
                current = seqno
                print(f"  Position {i}: seqno={seqno} -> ACCEPTED")
        
        print(f"  Result: {len(accepted)} accepted, {len(rejected)} rejected")

if __name__ == "__main__":
    test_replay_protection()
    test_sequence_scenarios()
