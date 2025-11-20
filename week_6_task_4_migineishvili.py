from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ===== Config from assignment =====
BLOCK_SIZE = 16
KEY = b"this_is_16_bytes"
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"  # IV
    "9404628dcdf3f003482b3b0648bd920b"  # C0
    "3f60e13e89fa6950d3340adbbbb41c12"  # C1
    "b3d1d97ef97860e9df7ec0d31d13839a"  # C2
    "e17b3be8f69921a07627021af16430e1"  # C3
)

# ===== Oracle from assignment =====
def padding_oracle(ciphertext: bytes) -> bool:
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

# ===== Helpers (Tasks 2–3 minimal) =====
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    if len(data) % block_size != 0:
        raise ValueError("Ciphertext length must be a multiple of block size")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    n = len(prev_block)
    plaintext = bytearray(n)
    intermediate = bytearray(n)
    for pad_len in range(1, n + 1):
        pos = n - pad_len
        suffix = bytearray((intermediate[j] ^ pad_len) for j in range(pos + 1, n))
        found = False
        for guess in range(256):
            forged_prev = bytearray(b"\x00" * pos)
            forged_prev.append(guess)
            forged_prev.extend(suffix)
            test_ct = bytes(forged_prev) + target_block
            if padding_oracle(test_ct):
                inter = guess ^ pad_len
                intermediate[pos] = inter
                plaintext[pos] = inter ^ prev_block[pos]
                found = True
                break
        if not found:
            raise ValueError(f"Failed to recover byte at position {pos}")
    return bytes(plaintext)

# ===== Task 4: Full attack =====
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    if len(blocks) < 2:
        raise ValueError("Ciphertext must include IV + at least one block")
    recovered = []
    for i in range(1, len(blocks)):
        pt_block = decrypt_block(blocks[i - 1], blocks[i])
        recovered.append(pt_block)
    return b"".join(recovered)

# ===== Optional Task 5 decode (kept minimal for completeness) =====
def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()
    except Exception:
        return f"(invalid padding) hex={hexlify(plaintext).decode()}"
    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError:
        return f"(non-UTF8) hex={hexlify(unpadded).decode()}"

# ===== Main =====
if __name__ == "__main__":
    ct = unhexlify(CIPHERTEXT_HEX)
    print(f"[*] Ciphertext length: {len(ct)} bytes")
    print(f"[*] IV: {ct[:BLOCK_SIZE].hex()}")
    recovered = padding_oracle_attack(ct)
    print("\n[+] Decryption complete!")
    print(f"  Recovered plaintext (raw bytes): {recovered}")
    print(f"  Hex: {recovered.hex()}")
    print("\n  Final plaintext:")
    print(unpad_and_decode(recovered))
