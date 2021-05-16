import nacl.secret
import nacl.utils
import nacl.pwhash
import base64

# key derivation function
kdf = nacl.pwhash.argon2i.kdf

print('Encryption utility. Starting encryption...')

# get key
password = 'hello'.encode('utf-8')

# generate and print salt
salt_size = nacl.pwhash.argon2i.SALTBYTES
print('salt size:{}'.format(salt_size))

salt = nacl.utils.random(salt_size)
print('saving salt to file...')
salt_file = open('salt', 'wb')
salt_file.write(base64.b64encode(salt))
salt_file.close()
# TODO write the salt to a file
print('salt saved. Obtaining key...')

# generate key
key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
print('key obtained. Encrypting and writing to file...')

# setting up encryption tools
box = nacl.secret.SecretBox(key)

# read passwd.txt file
input_file = open('passwd.txt', 'r')
p = input_file.read()

output_file = open('passwd', 'wb')
# encrypt contents
encrypted = box.encrypt(p.encode('utf-8')) 
# output to file
output_file.write(base64.b64encode(encrypted)) 
input_file.close()

print('contents encrypted and saved')
