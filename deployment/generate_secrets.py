from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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

def generate_ap_seed():
        number = int.from_bytes(os.urandom(8), "little")
        
        seed = "#define AP_SEED " + hex(number) + "\n"

        f = open("global_secrets.h", 'a')
        f.write(seed)
        f.close()

def generate_comp_seed():
        number = int.from_bytes(os.urandom(8), "little")
        
        seed = "#define COMP_SEED " + hex(number) + "\n"

        f = open("global_secrets.h", 'a')
        f.write(seed)
        f.close()
def generate_ap_key_pair():
      private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                    )
      pem_private_key = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
      pem_public_key = private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
      ap_priv = "#define AP_PRIV " + '"' + pem_private_key.decode("ascii") + '"\n'
      ap_pub  = "#define AP_PUB  " + '"' + pem_public_key.decode("ascii") + '"\n'
      f = open("global_secrets.h", 'a')
      f.write(ap_priv)
      f.write(ap_pub)
      f.close()

def generate_comp_key_pair(n):
      f = open("global_secrets.h", 'a')
      for i in range(0, int(n)):
                private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                )
                
                pem_private_key = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                )
                pem_public_key = private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                comp_priv = "#define COMP"+str(i+1)+"_PRIV " + '"' + pem_private_key.decode("ascii") + '"\n'
                comp_pub  = "#define COMP"+str(i+1)+"_PUB  " + '"' + pem_public_key.decode("ascii") + '"\n'
                f.write(comp_priv)
                f.write(comp_pub)
                

      f.close() 


def main():
    # 0 - Token 
    # 1 - Pin

    f = open("global_secrets.h", 'w')
    f.close() 

    generate_sequence(1)
    generate_sequence(0)
    generate_nonce()
    generate_ap_seed()
    generate_comp_seed()
    generate_ap_key_pair()
    generate_comp_key_pair(input("How many components are you provisioning?"))

if __name__ == "__main__":
    main()

