#!/bin/sh
# Start MinIO in background, create bucket, seed data, then foreground

minio server /data --console-address ":9001" &
MINIO_PID=$!

# Wait for MinIO to be ready
for i in $(seq 1 30); do
    if curl -sf http://localhost:9000/minio/health/live >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Install mc (MinIO Client) is already in the image
mc alias set local http://localhost:9000 minioadmin minioadmin123 2>/dev/null

# Create bucket and seed test data
mc mb local/testbucket 2>/dev/null || true
echo "Hello from S3" | mc pipe local/testbucket/readme.txt
echo "nested file" | mc pipe local/testbucket/subdir/nested.txt
dd if=/dev/urandom bs=1k count=64 2>/dev/null | mc pipe local/testbucket/bigfile.bin

echo "MinIO ready with testbucket seeded"

# Bring MinIO to foreground
wait $MINIO_PID
