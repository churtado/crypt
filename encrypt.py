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
lines = input_file.readlines()

output_file = open('passwd', 'wb')
 
for line in lines:
    # split into array
    l = line.split()

    # encrypt key and value
    key = box.encrypt(l[0].encode('utf-8'))
    value = box.encrypt(l[1].encode('utf-8'))
    output_file.write(base64.b64encode(key)) 
    output_file.write(base64.b64encode(value))
input_file.close()

print('contents encrypted and saved')
