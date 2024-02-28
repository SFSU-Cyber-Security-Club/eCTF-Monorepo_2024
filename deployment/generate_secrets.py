import hashlib
import os

# Generate the pin

PIN_KEY_LENGTH = 12
TOKEN_KEY_LENGTH = 15

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
        typesequence = "PIN" if is_pin else "TOKEN"
        print(typesequence + " SEQUENCE ->", " > " + sequence + " < ")

        # Digest and hash the result, the result will be flashed to our chip
        m = hashlib.sha256()
        m.update(bytes(sequence, 'ascii'))
        hashed_goodies = m.hexdigest()

        generate_hash_pins = "#define " + typesequence + " " + '"' + hashed_goodies + '"\n'

        f = open("global_secrets.h", 'a')
        f.write(generate_hash_pins)
        f.close()
        
        print("Hexed input = ", hashed_goodies)

def generate_nonce():
        number = int.from_bytes(os.urandom(8), "little")
        
        generate_public_inonce = "#define INONCE " + hex(number) + "\n"

        f = open("global_secrets.h", 'a')
        f.write(generate_public_inonce)
        f.close()

def main():
    # 0 - Token 
    # 1 - Pin

    f = open("global_secrets.h", 'w')
    f.close() 

    generate_sequence(1)
    generate_sequence(0)
    generate_nonce()
if __name__ == "__main__":
    main()

