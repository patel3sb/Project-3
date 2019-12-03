import os
import sys
from arguments import encryAES, decryAES, encrySHA256, key_generation, Index


#Reads from the file
def readFile(filename):
   with open(filename) as f:
        return f.read()
    
#writes in the file the output
def writeFile(filename, content):
    with open(filename, 'w+') as f:
        f.write(content)
        f.close()

#key generating function 
def keygen(args: list):
    expected = 1
    if len(args) != expected:
        print(f'Entered Invalid number of arugments for the function keygen, got {len(args)}, expected {expected}')
        return
    path = args[0]
    key = key_generation(256 / 8)
    writeFile(path, key)

#encryption function
def encryption(args: list):
    expected = 4
    if len(args) != expected:
        print(f'Entered Invalid number of arugments for function encryption, got {len(args)}, expected {expected}')
        return
    key_file = args[0]  
    # Read the key from this file
    index_file = args[1] 
     # Write the index to this file
    plaintext_folder = args[2] 
     # Read all plaintexts from this folder
    ciphertext_folder = args[3]  
    # Write all ciphertexts to this folder
    key_file_contents = readFile(key_file)
    # Create new inverted index
    inverted_index = Index()
    if not os.path.exists(ciphertext_folder):
        os.makedirs(ciphertext_folder)
    # Find the names of all files in the plaintext folder
    plaintext_file_names = list(filter(
        lambda file_name: os.path.isfile(
            os.path.join(plaintext_folder, file_name)),
        os.listdir(plaintext_folder))
    )
    for plaintext_file_name in plaintext_file_names:
        print(f'Processed file: {plaintext_file_name}')
        full_plaintext_path = os.path.join(
            plaintext_folder, plaintext_file_name)
        plaintext = readFile(full_plaintext_path)
        words = plaintext.split(' ')
        # Add file to index
        for word in words:
            inverted_index.addEntry(encrySHA256(word), plaintext_file_name.replace('f', 'c'))
        # Encrypt file and write to ciphertext folder
        iv_hex, encrypted_hex = encryAES(plaintext, key_file_contents)
        enc_file_content = f'{iv_hex}\n{encrypted_hex}'
        full_cipher_path = os.path.join(
            ciphertext_folder, plaintext_file_name.replace('f', 'c'))
        writeFile(full_cipher_path, enc_file_content)
    print('Encrypted Index')
    # Write inverted index file to disk
    writeFile(index_file, inverted_index.serialize())
    
#token function
def token(args: list):
    expected = 2
    if len(args) != expected:
        print(f'Entered Invalid number of arugments for function encryption, got {len(args)}, expected {expected}')
        return
    output_file = args[1]
    token = args[0]
    hashes = encrySHA256(token)
    print(f'Input Token: {token}')
    print(f'Output Hash: {hashes}')
    writeFile(output_file, hashes)

#search finction
def search(args: list):
    expected = 4
    if len(args) != expected:
        print(f'Entered Invalid number of arugments for function encryption, got {len(args)}, expected {expected}')
        return
    #Reads the index from this file
    index_file = args[0]  
    #Reads the token from this file
    token_file = args[1]  
    #Reads encrypted files from this directory
    ciphertext_folder = args[2] 
    #Reads decryption key from this file
    key_file = args[3] 
    index_file_contents = readFile(index_file)
    token_file_contents = readFile(token_file)
    key_file_contents = readFile(key_file)
    #print(f'test: {key_file_contents}')
    # Create new InvertedIndex from disk contents
    inverted_index = Index(index_file_contents)
    # Find file names under this token
    file_names = inverted_index.search(token_file_contents)
    print(f'Files matching token {token_file_contents}: {", ".join(file_names)}')
    # Decrypt each file and print its contents
    for file_name in file_names:
        full_ciphertext_path = os.path.join(ciphertext_folder, file_name)
        full_ciphertext_contents = readFile(full_ciphertext_path)
        iv_hex, ciphertext = full_ciphertext_contents.split('\n') 
        cleartext = decryAES(ciphertext, key_file_contents, iv_hex)
        print(f'${file_name} decrypted contents are: ${cleartext}')
        
key = 'key'
function = 'function'

#main 
def main(args: list):
    arg_functions = [
        {
            key: 'keygen',
            function: keygen
        },
        {
            key: 'enc',
            function: encryption
        },
        {
            key: 'token',
            function: token
        },
        {
            key: 'search',
            function: search
        }
    ]
    possible_args = ', '.join(map(lambda x: x[key], arg_functions))
    try:
        first_arg = args[1].lower()
    except IndexError:
        print(f'First argument missing, it should be one of the following: {possible_args}')
        return
    try:
        thing: dict = next(
            filter(lambda x: x[key] == first_arg, arg_functions)
        )
    except StopIteration:
        print(f'Invalid first argument, it should be one of the following: {possible_args}')
        return
    # Call the function with the rest of the arugments
    thing[function](args[2:])

if __name__ == "__main__":
    main(sys.argv)
