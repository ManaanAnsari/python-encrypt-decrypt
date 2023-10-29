from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import argparse


def fill_0(str_to_fill, length):
    if len(str_to_fill) < length:
        str_to_fill = str_to_fill + '0' * (length - len(str_to_fill))
    return str_to_fill


class Crypt:

    def __init__(self, salt:str):
        if len(salt) < 32 and len(salt) > 0:
            salt = fill_0(salt, 16)
        else:
            raise ValueError('Password must be less than 32 characters long')
        
        
        self.salt = salt.encode('utf8')
        self.enc_dec_method = 'utf-8'

    def encrypt(self, str_to_enc):
        try:
            str_key = self.salt
            aes_obj = AES.new(str_key, AES.MODE_CFB, self.salt)
            hx_enc = aes_obj.encrypt(str_to_enc.encode('utf8'))
            mret = b64encode(hx_enc).decode(self.enc_dec_method)
            return mret
        except ValueError as value_error:
            if value_error.args[0] == 'IV must be 16 bytes long':
                raise ValueError('Encryption Error: SALT must be 16 characters long')
            elif value_error.args[0] == 'AES key must be either 16, 24, or 32 bytes long':
                raise ValueError('Encryption Error: Encryption key must be either 16, 24, or 32 characters long')
            else:
                raise ValueError(value_error)

    def decrypt(self, enc_str):
        try:
            str_key = self.salt
            aes_obj = AES.new(str_key, AES.MODE_CFB, self.salt)
            str_tmp = b64decode(enc_str.encode(self.enc_dec_method))
            str_dec = aes_obj.decrypt(str_tmp)
            mret = str_dec.decode(self.enc_dec_method)
            return mret
        except ValueError as value_error:
            if value_error.args[0] == 'IV must be 16 bytes long':
                raise ValueError('Decryption Error: SALT must be 16 characters long')
            elif value_error.args[0] == 'AES key must be either 16, 24, or 32 bytes long':
                raise ValueError('Decryption Error: Encryption key must be either 16, 24, or 32 characters long')
            else:
                raise ValueError(value_error)
            

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a message using Fernet encryption")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Specify 'encrypt' or 'decrypt' action")
    args = parser.parse_args()
    
    user_key = input("Enter your encryption key: ")
    
    if args.action == "encrypt":
        message = input("Enter the message you want to encrypt: ")
        test_crpt = Crypt(salt=user_key)
        test_enc_text = test_crpt.encrypt(message)
        print(f"Encrypted Message: {test_enc_text}")

    elif args.action == "decrypt":
        encrypted_message = input("Enter the encrypted message: ")
        test_crpt = Crypt(salt=user_key)
        test_dec_text = test_crpt.decrypt(encrypted_message)
        print(f"Decrypted Message: {test_dec_text}")


if __name__ == "__main__":
    main()
