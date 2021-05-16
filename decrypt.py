import nacl.secret
import nacl.utils
import nacl.pwhash
import base64

# key derivation function
kdf = nacl.pwhash.argon2i.kdf
salt_size = nacl.pwhash.argon2i.SALTBYTES

print('Decryption utility')

print('reading password...')
password = 'hello'.encode('utf-8')

# generate and print salt
print('reading salt...')
salt = base64.b64decode(b'OinavmSHZX7Ips/GLK/IAQ==')

print('generating key...')
# generate key
key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
print('key generated. Decrypting file...')

# setting up encryption tools
box = nacl.secret.SecretBox(key)

# read passwd file
input_file = open('passwd', 'r')
encrypted = base64.b64decode(input_file.read())
# encrypt key and value
input_file.close()

output_file = open('decrypted', 'w')
plaintext = box.decrypt(encrypted)
lines = plaintext.decode().split('\n')
print(lines)
for line in lines:
    output_file.write(line + '\n')

output_file.close()

print('contents decrypted and saved')
