import nacl.secret
import nacl.utils
import nacl.pwhash
import base64

# key derivation function
kdf = nacl.pwhash.argon2i.kdf
salt_size = nacl.pwhash.argon2i.SALTBYTES

print('Encryption utility. Starting encryption...')
print('using XSalsa20 stream cipher and Poly1305 MAC authentication via PyNaCl')

# get password
password = input('input password:')
password = password.encode('utf-8')

print('salt size:{}'.format(salt_size))
# generate and print salt
salt = nacl.utils.random(salt_size)
print('printing salt. Please write it down, it will not be saved.')
print('salt:{}\n'.format(base64.b64encode(salt)))

# generate key
key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
print('key obtained. Opening file...')

# setting up encryption tools
box = nacl.secret.SecretBox(key)

# read passwd.txt file
input_file = open('passwd.txt', 'r')
p = input_file.read()
print('file read. Encrypting...')

# encrypt contents
encrypted = box.encrypt(p.encode('utf-8')) 
print('contents encrypted. Saving to file...')

# output to file
output_file = open('passwd', 'wb')
output_file.write(base64.b64encode(encrypted)) 
input_file.close()

print('contents encrypted and saved. Exiting...')
