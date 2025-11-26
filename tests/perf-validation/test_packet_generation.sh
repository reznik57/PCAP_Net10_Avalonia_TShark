#!/bin/bash
# Generate test PCAP file without needing network capture
TEST_DIR="/tmp/perf_validation_pcap"
mkdir -p "$TEST_DIR"

echo "=== Generating Test PCAP Files ===" 
echo "Using randpkt to generate high-volume test data..."

# Generate different sized PCAP files
echo "Generating 10,000 packet test file..."
tshark -i randpkt -a packets:10000 -w "$TEST_DIR/test_10k.pcapng" 2>&1 | tail -5

echo "Generating 50,000 packet test file..."
tshark -i randpkt -a packets:50000 -w "$TEST_DIR/test_50k.pcapng" 2>&1 | tail -5

echo "Generating 100,000 packet test file..."
tshark -i randpkt -a packets:100000 -w "$TEST_DIR/test_100k.pcapng" 2>&1 | tail -5

echo ""
echo "Test files created:"
ls -lh "$TEST_DIR"/*.pcapng

echo ""
echo "=== Performance Benchmarks ==="

for file in "$TEST_DIR"/test_*.pcapng; do
    filename=$(basename "$file")
    packet_count=$(tshark -r "$file" -T fields -e frame.number | wc -l)
    file_size=$(stat -c%s "$file")
    
    echo ""
    echo "File: $filename"
    echo "  Packets: $packet_count"
    echo "  Size: $(echo "scale=2; $file_size / 1024 / 1024" | bc) MB"
    
    # Benchmark packet extraction
    start=$(date +%s.%N)
    tshark -r "$file" -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol > /dev/null 2>&1
    end=$(date +%s.%N)
    duration=$(echo "$end - $start" | bc)
    throughput=$(echo "scale=0; $packet_count / $duration" | bc)
    
    echo "  Processing time: ${duration}s"
    echo "  Throughput: $throughput packets/sec"
done

echo ""
echo "Files saved to: $TEST_DIR"
