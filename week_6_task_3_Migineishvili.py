from binascii import unhexlify

BLOCK_SIZE = 16

# Ciphertext: IV + several blocks
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"  # IV
    "9404628dcdf3f003482b3b0648bd920b"  # C0
    "3f60e13e89fa6950d3340adbbbb41c12"  # C1
    "b3d1d97ef97860e9df7ec0d31d13839a"  # C2
    "e17b3be8f69921a07627021af16430e1"  # C3
)

# Dummy oracle function (in your lab you already have a real padding_oracle)
def padding_oracle(ciphertext: bytes) -> bool:
    """
    Example oracle function.
    In your lab, use the provided padding_oracle implementation.
    """
    return True  # Here it just returns True; in your lab it works differently.

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    if len(data) % block_size != 0:
        raise ValueError("Data length is not a multiple of the block size")
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block.
    """
    block_size = len(prev_block)
    plaintext = bytearray(block_size)
    intermediate = bytearray(block_size)

    # Work backwards (from last byte to first)
    for pad_len in range(1, block_size + 1):
        found = False
        for guess in range(256):
            prefix = bytearray(block_size - pad_len)
            suffix = bytearray(
                (intermediate[j] ^ pad_len) for j in range(block_size - pad_len, block_size)
            )
            test_block = prefix + bytes([guess]) + suffix
            # Oracle check
            if padding_oracle(bytes(test_block) + target_block):
                intermediate[block_size - pad_len] = guess ^ pad_len
                plaintext[block_size - pad_len] = intermediate[block_size - pad_len] ^ prev_block[block_size - pad_len]
                found = True
                break
        if not found:
            raise ValueError(f"Padding oracle attack failed at pad_len={pad_len}")

    return bytes(plaintext)

if __name__ == "__main__":
    ciphertext = unhexlify(CIPHERTEXT_HEX)
    blocks = split_blocks(ciphertext, BLOCK_SIZE)

    print("[*] Total ciphertext length:", len(ciphertext))
    print("[*] Number of blocks:", len(blocks))

    prev_block = blocks[0]
    target_block = blocks[1]
    decrypted = decrypt_block(prev_block, target_block)

    print("[*] Decrypted Block 1:", decrypted.hex())

