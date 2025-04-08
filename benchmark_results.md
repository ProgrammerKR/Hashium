# 🔬 Hashium Benchmark Results

This benchmark compares the **Hashium** hashing algorithm with other popular hashing functions including SHA-256, BLAKE3, MurmurHash3, and xxHash.  
It evaluates the speed and performance of each function using large input data and multiple iterations.

---

## 🚀 Benchmark Script

```python
import time
import hashlib
import blake3
import mmh3
import xxhash
from hashium import Hashium

# Test Data
test_string = "Benchmarking Hash Functions" * 1000  # Large Input Data
iterations = 100000  # Number of Hash Calculations

# Initialize Hashium
hashium = Hashium()

# Benchmark Function
def benchmark_hash(func, name):
    start = time.time()
    for _ in range(iterations):
        func(test_string)
    end = time.time()
    return name, end - start

# Hash Functions
def sha256_hash(data): return hashlib.sha256(data.encode()).hexdigest()
def blake3_hash(data): return blake3.blake3(data.encode()).hexdigest()
def murmur3_hash(data): return mmh3.hash(data)
def xxhash64_hash(data): return xxhash.xxh64(data.encode()).hexdigest()
def hashium_hash(data): return hashium.hashium_basic(data)

# Run Benchmarks
results = [
    benchmark_hash(sha256_hash, "SHA-256"),
    benchmark_hash(blake3_hash, "BLAKE3"),
    benchmark_hash(murmur3_hash, "MurmurHash3"),
    benchmark_hash(xxhash64_hash, "xxHash64"),
    benchmark_hash(hashium_hash, "Hashium")
]

# Print Results
print("\n🔬 Benchmark Results:")
print("{:<15} | {:<10}".format("Algorithm", "Time (sec)"))
print("-" * 30)
for name, time_taken in results:
    print("{:<15} | {:<10.5f}".format(name, time_taken))

# Sample Output

🔬 Benchmark Results:
Algorithm       | Time (sec)
------------------------------
SHA-256         | 5.32100   
BLAKE3          | 3.22187   
MurmurHash3     | 1.02054   
xxHash64        | 0.82167   
Hashium         | 7.44219
