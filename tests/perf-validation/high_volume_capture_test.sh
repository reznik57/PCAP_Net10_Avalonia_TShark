#!/bin/bash
# High-Volume Packet Capture Performance Test
# Tests real-world performance under load

TEST_DIR="/tmp/perf_validation_$(date +%s)"
mkdir -p "$TEST_DIR"

echo "=== Phase 2B Real-World Performance Validation ==="
echo "Date: $(date)"
echo "TShark Version: $(tshark --version | head -1)"
echo "System: $(uname -r)"
echo ""

# Test 1: High-volume loopback capture
echo "Test 1: High-Volume Loopback Capture (10 seconds)"
echo "Starting background capture on loopback..."
tshark -i lo -w "$TEST_DIR/loopback_test.pcapng" -a duration:10 > /dev/null 2>&1 &
TSHARK_PID=$!

sleep 1  # Let TShark start

echo "Generating high-volume traffic (ping flood)..."
ping -f -c 100000 localhost > /dev/null 2>&1 &
PING_PID=$!

# Also generate some TCP traffic
for i in {1..10}; do
    timeout 1 nc -z localhost 80 2>/dev/null &
done

wait $TSHARK_PID
wait $PING_PID 2>/dev/null

# Analyze captured packets
echo ""
echo "Capture Statistics:"
TOTAL_PACKETS=$(tshark -r "$TEST_DIR/loopback_test.pcapng" -T fields -e frame.number | wc -l)
FILE_SIZE=$(stat -f%z "$TEST_DIR/loopback_test.pcapng" 2>/dev/null || stat -c%s "$TEST_DIR/loopback_test.pcapng")
echo "  Total packets captured: $TOTAL_PACKETS"
echo "  File size: $(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc) MB"
echo "  Packets per second: $(echo "scale=0; $TOTAL_PACKETS / 10" | bc) pps"

# Get protocol breakdown
echo ""
echo "Protocol Breakdown:"
tshark -r "$TEST_DIR/loopback_test.pcapng" -q -z io,phs | head -20

# Test 2: Sustained capture with statistics
echo ""
echo "Test 2: Sustained Capture with Statistics (30 seconds)"
tshark -i lo -a duration:30 -q -z io,stat,1 > "$TEST_DIR/stats_output.txt" 2>&1 &
TSHARK_PID=$!

# Generate sustained traffic
for i in {1..30}; do
    ping -c 100 -i 0.01 localhost > /dev/null 2>&1 &
    sleep 1
done

wait $TSHARK_PID

echo "Per-second packet statistics:"
grep "Interval" "$TEST_DIR/stats_output.txt" -A 30 | tail -15

# Test 3: Large file processing time
echo ""
echo "Test 3: Large File Processing Benchmark"
TEST_FILE="$TEST_DIR/loopback_test.pcapng"
if [ -f "$TEST_FILE" ]; then
    echo "Processing $TOTAL_PACKETS packets..."
    
    # Time packet extraction
    START=$(date +%s.%N)
    tshark -r "$TEST_FILE" -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol > "$TEST_DIR/extracted.txt"
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    echo "  Extraction time: ${DURATION}s"
    echo "  Throughput: $(echo "scale=0; $TOTAL_PACKETS / $DURATION" | bc) packets/sec"
fi

echo ""
echo "Test artifacts saved to: $TEST_DIR"
echo "Validation complete."
