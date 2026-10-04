import xwing

def main():
    print("==================================================")
    print("       X-Wing Hybrid Key Exchange Pipeline       ")
    print("==================================================")
    
    print("\n[Step 1] Alice generates her hybrid public and private keys...")
    pk_alice, sk_alice = xwing.keygen()
    print(f"-> Alice Public Key Length: {len(pk_alice)} bytes")
    print(f"-> Alice Private Key Length: {len(sk_alice)} bytes")
    
    print("\n[Step 2] Bob receives Alice's public key and encapsulates a shared secret...")
    ciphertext, ss_bob = xwing.encaps(pk_alice)
    print(f"-> Ciphertext Length: {len(ciphertext)} bytes")
    print(f"-> Bob's Derived Secret (Hex): {ss_bob.hex()[:32]}...")
    
    print("\n[Step 3] Alice receives the ciphertext and decapsulates it...")
    ss_alice = xwing.decaps(ciphertext, sk_alice)
    print(f"-> Alice's Derived Secret (Hex): {ss_alice.hex()[:32]}...")
    
    print("\n[Verification]")
    if ss_alice == ss_bob:
        print("Success! Alice and Bob share the exact same secure secret key.")
    else:
        print("Error: Shared secrets do not match.")
    print("==================================================")

if __name__ == "__main__":
    main()
