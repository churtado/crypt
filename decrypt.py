import nacl.secret
import nacl.utils
import nacl.pwhash
import base64

# key derivation function
kdf = nacl.pwhash.argon2i.kdf
salt_size = nacl.pwhash.argon2i.SALTBYTES

print('Decryption utility')
print('using XSalsa20 stream cipher and Poly1305 MAC authentication via PyNaCl')

# input password
password = input('input password:')
password = password.encode('utf-8')

# generate and print salt
print('reading salt...')
salt_file = open('salt', 'r')
salt = base64.b64decode(salt_file.read())

# generate key
print('generating key...')
key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
print('key generated. Opening file...')

# setting up encryption tools
box = nacl.secret.SecretBox(key)

# read passwd file
input_file = open('passwd', 'r')
encrypted = base64.b64decode(input_file.read())
# encrypt key and value
input_file.close()

print('contents read. Decrypting...')
plaintext = box.decrypt(encrypted)

print('contents decrypted. Saving to file...')
output_file = open('decrypted', 'w')
lines = plaintext.decode().split('\n')
for line in lines:
    output_file.write(line + '\n')
output_file.close()

print('contents decrypted and saved to file. Exiting...')
