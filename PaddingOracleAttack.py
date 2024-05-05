import requests
import sys

# Configuration for the target server
SERVER_HOST = "senshado.mywire.org"
SERVER_URL = f"http://{SERVER_HOST}/message"

# Session object (do not modify this)
_DO_NOT_TOUCH_session = requests.Session()

def send_message(message):
    """
    Submits an encrypted message to the server to be queued for delivery.
    `message` should be hex encoded.
    
    Errors from the server will be re-thrown as ValueErrors.
    """
    try:
        r = _DO_NOT_TOUCH_session.post(SERVER_URL, data=message, timeout=10)  # 10 seconds timeout
        if r.status_code == 200:
            return r.text
        else:
            raise ValueError(r.text)
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
        sys.exit(1)

#filenames for input/output
outputFile = 'plaintexts.txt'
inputFile = 'ciphers.txt'

#XOR two bytes 
def xor(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

#decrypt the last block for padding 
def decrypt_block(last_block, iv):
    intermediate = bytearray(16) 
    decrypted = bytearray(16) 
    test_iv = bytearray(iv) 

    for i in reversed(range(16)):
        padding = 16 - i
        for guess in range(256):
            test_iv[i] = guess
            modified_message = bytes(test_iv + last_block)
            try:
                send_message(modified_message.hex())
                #no exception -> correct padding
                intermediate[i] = guess ^ padding
                decrypted[i] = intermediate[i] ^ iv[i]
                
                #update IV for next round
                for j in range(i, 16):
                    test_iv[j] = intermediate[j] ^ (padding + 1)
                break
            except ValueError:
                continue

    return bytes(decrypted)


#remove padding (pcks7)
def unpad(plaintext):
    padding_len = plaintext[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    if plaintext[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid PKCS#7 padding.")
    return plaintext[:-padding_len]

def main():
    try:
        #read ciphertexts
        with open(inputFile, 'r') as file:
            lines = file.readlines()
        
        #first line is IV
        iv = bytes.fromhex(lines[0].strip())

        #open output file
        with open(outputFile, 'w', encoding='utf-8') as output_file:

            #decrypt each block; write decryption in file
            previous_block = iv
            for line in lines[1:]:
                ciphertext_block = bytes.fromhex(line.strip())
                decrypted_block = decrypt_block(ciphertext_block, previous_block)
                previous_block = ciphertext_block
                
                #check if last block (for unpadding)
                if line == lines[-1]:
                    try:
                        decrypted_block = unpad(decrypted_block)
                    except ValueError as e:
                        #handle padding error
                        print(f"Padding error: {e}")
                
                #write decryption
                output_file.write(decrypted_block.decode('utf-8'))

    except Exception as e:
        print("An error occurred:", e)

if __name__ == '__main__':
    main()
