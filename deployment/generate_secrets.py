from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import binascii
import hashlib
import os

# Generate the pin

PIN_KEY_LENGTH = 12
TOKEN_KEY_LENGTH = 15
RSA_KEY_LENGTH = 512 # Will convert to bytes

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
        generate_length = "#define " + typesequence + "_BUFSIZE" + " " + str(len(hashed_goodies)) + '\n'

        f = open("global_secrets.h", 'a')
        f.write(generate_hash_pins)
        f.write(generate_length)
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
                        key_size=RSA_KEY_LENGTH
                    )
      der_private_key = private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
      der_public_key = private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

      der_private_key_hex = binascii.hexlify(der_private_key).decode('utf-8')
      der_public_key_hex = binascii.hexlify(der_public_key).decode('utf-8')

      formatted_private_key = '\\x'+'\\x'.join(a+b for a,b in zip(der_private_key_hex[::2],der_private_key_hex[1::2]))
      formatted_public_key = '\\x'+'\\x'.join(a+b for a,b in zip(der_public_key_hex[::2],der_public_key_hex[1::2]))

      ap_priv = "#define AP_PRIV_AT " + '"' + formatted_private_key + '"\n'
      ap_pub  = "#define AP_PUB_AT  " + '"' + formatted_public_key + '"\n'
      f = open("global_secrets.h", 'a')
      f.write("\n\n")
      f.write(ap_priv)
      f.write("\n\n")
      f.write(ap_pub)
      f.write("\n\n")
      f.close()

def generate_comp_key_pair(n):
      f = open("global_secrets.h", 'a')
      for i in range(0, int(n)): # In case we ever wanted multiple keys because we're fancy
                private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=RSA_KEY_LENGTH
                )
                
                der_private_key = private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                )
                der_public_key = private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                der_private_key_hex = binascii.hexlify(der_private_key).decode('utf-8')
                der_public_key_hex = binascii.hexlify(der_public_key).decode('utf-8')

                formatted_private_key = '\\x'+'\\x'.join(a+b for a,b in zip(der_private_key_hex[::2],der_private_key_hex[1::2]))
                formatted_public_key = '\\x'+'\\x'.join(a+b for a,b in zip(der_public_key_hex[::2],der_public_key_hex[1::2]))


                comp_priv = "#define COMP"+str(i+1)+"_PRIV " + '"' + formatted_private_key + '"\n'
                comp_pub  = "#define COMP"+str(i+1)+"_PUB  " + '"' + formatted_public_key + '"\n'
                f.write("\n\n")
                f.write(comp_priv)
                f.write("\n\n")
                f.write(comp_pub)
                f.write("\n\n")
                

      f.close() 

def generate_key_length():
        f = open("global_secrets.h", 'a')
        f.write("#define RSA_KEY_LENGTH " + str(int(RSA_KEY_LENGTH/8)) + "\n")  
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

    # This gets ugly 
    generate_ap_key_pair() # FOR AT ENCRYPTION
    generate_comp_key_pair(1) # Just use one key pair for all components, ez
    generate_key_length() # Note the key size we chose

if __name__ == "__main__":
    main()

