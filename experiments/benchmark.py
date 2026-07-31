import time
from prototype import prototype_algorithm

def run_benchmark(sample_data):
    start = time.time()
    result = prototype_algorithm(sample_data)
    elapsed = time.time() - start
    print(f"Processed {result['input_size']} items in {elapsed:.4f}s")

if __name__ == "__main__":
    run_benchmark(list(range(1000)))
