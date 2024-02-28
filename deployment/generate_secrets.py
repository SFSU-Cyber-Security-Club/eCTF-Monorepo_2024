import hashlib
import os

# Generate the pin

PIN_KEY_LENGTH = 12
TOKEN_KEY_LENGTH = 12

def generate_sequence(is_pin):
        sequence_length = PIN_KEY_LENGTH if is_pin else TOKEN_KEY_LENGTH
        print("Generating sequence of size", sequence_length) 

        # Generate a random sequence of bytes

        numbers_mason = []
        while len(numbers_mason) < sequence_length:
                number = int.from_bytes(os.urandom(1), "little")
                if(number >= 35 and number <= 125):
                        numbers_mason.append(chr(number))

        sequence = "".join(numbers_mason)
        print("PIN SEQUENCE ->", " > " + sequence + " < ")

        # Digest and hash the result, the result will be flashed to our chip
        m = hashlib.sha256()
        m.update(bytes(sequence, 'ascii'))
        hashed_goodies = m.hexdigest()

        print("Hexed input = ", hashed_goodies)

def generate_nonce():
        number = int.from_bytes(os.urandom(8), "little")
        
        generate_public_inonce = "#define INONCE " + hex(number)

        f = open("global_secrets.h", 'w')
        f.write(generate_public_inonce)
        f.close()

def main():
    # 0 - Token 
    # 1 - Pin
    generate_sequence(1)
    generate_sequence(0)
    generate_nonce()
if __name__ == "__main__":
    main()

