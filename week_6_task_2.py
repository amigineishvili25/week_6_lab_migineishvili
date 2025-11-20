from binascii import unhexlify

BLOCK_SIZE = 16

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

if __name__ == "__main__":
    ciphertext = unhexlify(CIPHERTEXT_HEX)
    blocks = split_blocks(ciphertext, BLOCK_SIZE)

    print("[*] Total length:", len(ciphertext))
    print("[*] Number of blocks:", len(blocks))
    for idx, block in enumerate(blocks):
        print(f"Block {idx}: {block.hex()}")

