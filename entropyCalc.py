import math

def entropy(data):
    """
    Implements the actual shannon entropy calculation
    H(X) = -∑[P(xi) * log(P(xi))]
    """
    if not data:
        return 0.0

    counts = {}
    for c in data:
        counts[c] = counts.get(c,0) + 1

    total = len(data)

    return -sum(
        (freq / total) * math.log2(freq / total)
        for freq in counts.values()
    )

def file_entropy(filepath, block_size=None):
    with open(filepath, "rb") as f:
        data = f.read()
    #print(byte_distribution(data))
    if block_size is None:
        return entropy(data)

    return [
        entropy(data[i:i + block_size])
        for i in range(0, len(data), block_size)
    ]

def byte_distribution(data):
    counts = {}
    for c in data:
        counts[c] = counts.get(c,0) + 1
    total = len(data)
    return {byte: count / total for byte, count in sorted(counts.items())}

import sys
if __name__ == "__main__":
    print(file_entropy(sys.argv[1],1024))
