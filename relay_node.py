import socket
import platform
import subprocess
import urllib2
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random


#### Functions ####

#
#   Pings at server number_of_iteration times
#
def ping(server, number_of_iterations):

    # Change param depending on operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Create command for pinging
    command = ['ping', param, str(number_of_iterations), server]

    # Run command
    return subprocess.check_output(command)



#
# Calculate mean latency of ping
#
def calculate_mean_latency(ping_output):

    ping_output_split = ping_output.split('\n')

    latency_times = []

    for line in ping_output_split:
        time_index = line.find("time=")
        if time_index != -1:
            ms_index = line.find("ms")
            latency_times.append(float(line[time_index+5:ms_index-1]))

    return sum(latency_times)/len(latency_times)


#
# Checks if a string is a number or not
#
def is_number(s):
    try:
        int(s)
        return True
    except:
        return False

#
# Run traceroute to given server and return number_of_hops
#
def traceroute(server):

    # Change param depending on operating system
    param = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'

    # Create command for pinging
    command = [param, server]

    # Run command
    traceroute_output = subprocess.check_output(command)

    traceroute_output_split = traceroute_output.split('\n')

    number_of_hops = 0

    for line in traceroute_output_split:
        if is_number(line[0:2]):
            number_of_hops += 1

    return number_of_hops


#
# Generate RSA pair keys
#
def generate_RSA_pair():

    key = RSA.generate(2048, e=65537)

    return key


#
# Verify publickey sent from other
#
def verify_publickey(publickey_message):

    begin_index = publickey_message.find("-----BEGIN PUBLIC KEY-----")

    signature_str = publickey_message[0:begin_index]
    publickey_str = publickey_message[begin_index:]

    publickey_hash = SHA256.new(publickey_str).digest()
    signature_tuple = eval(signature_str)
    publickey =  RSA.importKey(publickey_str)

    if publickey.verify(publickey_hash, signature_tuple):
        return publickey
    else:
        print " >> Error: Can not verify public key."
        exit()


#
# Class for AES Encryption
#
class AES_encryption:
    def __init__(self, key):
        self.key = key

    def pad(self, message):
        return message + b"\0" * (AES.block_size - len(message) % AES.block_size)

    def encrypt(self, message, key, key_size = 256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, cipher_text, key):
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(cipher_text[AES.block_size:])
        return plain_text.rstrip(b"\0")


def rsa_decrypt(cipher, priv_key):
    decrypted_message = PKCS1_OAEP.new(priv_key)
    return decrypted_message.decrypt(cipher)


def verify(message, signature, pub_key):
    hash = SHA256.new()
    hash.update(message)
    verifier = PKCS1_PSS.new(pub_key)
    return verifier.verify(hash, signature)


#### Get my hostname and my ip address ####

hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)


#### Read port from file ####

file_port = open("relay_nodes.txt", "r")

for line in file_port:
    words = line.split()
    if(words[0] == hostname):
        if(words[1] != IPAddr):
            print "Error: this is not my IP Address!"
        port = int(words[2])
        break
file_port.close()

print "=========================================="
print "|| My name is: " + hostname + "\t\t\t||"
print "|| My IP Address is: " + IPAddr + "\t||"
print "|| My port is: " + str(port) + "\t\t\t||"
print "=========================================="


#### Generate keys ####

key = generate_RSA_pair()
public_key = key.publickey()

while True:
    #### Establish TCP socket and wait for client ####

    relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            relay_socket.bind(('', port))
            break
        except:
            print " >> Port not available. Trying again in 5 seconds"
            time.sleep(5)
    relay_socket.listen(1)

    print "\n==================================="
    print "I'm ready to take action."
    connection_socket = relay_socket.accept()[0]


    #### Reading, verifying client's public key ####

    clients_publickey_message = connection_socket.recv(2048)
    clients_publickey = verify_publickey(clients_publickey_message)


    #### Send signed public key to relay ####

    public_key_str = public_key.exportKey("PEM")
    hash = SHA256.new(public_key_str).digest()
    signature = key.sign(hash, '')
    signature_str = str(signature)
    signed_publickey_message = signature_str + public_key_str

    connection_socket.send(signed_publickey_message)


    #### Get aes key ####

    aes_key_message = connection_socket.recv(2048)

    decrypted_message1 = rsa_decrypt(aes_key_message[0:256], key)
    decrypted_message2 = rsa_decrypt(aes_key_message[256:], key)
    decrypted_message = decrypted_message1 + decrypted_message2
    aes_key = decrypted_message[0:32]
    signature = decrypted_message[32:]

    if verify(aes_key, signature, clients_publickey) == False:
        print "Error: Verifying message including client's public key failed."
        connection_socket.close()
        exit()

    aes_obj = AES_encryption(aes_key)

    print "Just got aes key"

    #### Receive hostname and number of pings ####

    cipher = connection_socket.recv(2048)
    try:
        plaintext = aes_obj.decrypt(cipher, aes_key)
    except:
        continue
    mode = plaintext
    print("Command from client: " + plaintext)
    if mode != "offline":
        plaintext = plaintext.split(" ")
        end_server = plaintext[0]
        number_of_iterations = plaintext[1]


        #### Perform measurements and send response to client ####

        try:
            ping_output = ping(end_server, number_of_iterations)
            mean_latency = calculate_mean_latency(ping_output)
        except:
            mean_latency = -1
        try:
            number_of_hops = traceroute(end_server)
        except:
            number_of_hops = -1

        response = str(mean_latency) + " " + str(number_of_hops)
        cipher = aes_obj.encrypt(response, aes_key)
        connection_socket.send(cipher)
        connection_socket.close()
    else:
        cipher = aes_obj.encrypt("ok", aes_key)
        connection_socket.send(cipher)

    #### Wait for client to send file to download ####
    port_unusable = 0

    if mode != "offline":
        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            try:
                relay_socket.bind(('', port + 1))
                print "Ready for phase 2"
                break
            except:
                print " >> Port not available. Trying again in 5 seconds"
                time.sleep(5)
        #         port_unusable = 1
        #         break
        # if port_unusable == 1:
        #     continue
        relay_socket.listen(1)
        connection_socket = relay_socket.accept()[0]

    cipher = connection_socket.recv(2048)
    try:
        message = aes_obj.decrypt(cipher, aes_key)
    except:
        continue

    if message == 'close':
        print "I'm not the chosen one. ;("
    else:
        print "File to download: " + message
        filedata = urllib2.urlopen(message)
        data_to_write = filedata.read()

        cipher = aes_obj.encrypt(data_to_write, aes_key)
        cipher_len = str(len(cipher))
        encrypted_cipher_len = aes_obj.encrypt(cipher_len, aes_key)
        connection_socket.send(encrypted_cipher_len)

        cipher_ok = connection_socket.recv(2048)
        message = aes_obj.decrypt(cipher_ok, aes_key)
        if message != 'ok':
            connection_socket.close()
            exit()

        data_len = len(cipher)
        chunks = data_len/1000
        remainder = data_len % 1000
        for i in range(0, chunks + 1):
            if i == chunks:
                start = i * 1000
                end = start + remainder
            else:
                start = i * 1000
                end = start + 1000

            connection_socket.send(cipher[start:end])

    #### Terminate connection with client ####
    connection_socket.close()