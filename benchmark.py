import time
import xwing

def run_benchmarks(iterations=1000):
    print(f"Running {iterations} iterations of X-Wing operations...")
    
    # KeyGen Benchmark
    start = time.perf_counter()
    for _ in range(iterations):
        pk, sk = xwing.keygen()
    end = time.perf_counter()
    keygen_avg = ((end - start) / iterations) * 1000
    print(f"KeyGen Average: {keygen_avg:.4f} ms")
    
    # Encaps Benchmark
    pk, sk = xwing.keygen()
    start = time.perf_counter()
    for _ in range(iterations):
        ct, ss = xwing.encaps(pk)
    end = time.perf_counter()
    encaps_avg = ((end - start) / iterations) * 1000
    print(f"Encaps Average: {encaps_avg:.4f} ms")
    
    # Decaps Benchmark
    ct, ss = xwing.encaps(pk)
    start = time.perf_counter()
    for _ in range(iterations):
        _ = xwing.decaps(ct, sk)
    end = time.perf_counter()
    decaps_avg = ((end - start) / iterations) * 1000
    print(f"Decaps Average: {decaps_avg:.4f} ms")

if __name__ == "__main__":
    run_benchmarks(1000)
