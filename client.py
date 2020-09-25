import sys
import socket
import platform
import subprocess
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import urllib2
import threading
import time
import csv
import datetime
import pandas
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
import random
import matplotlib.pyplot as plt
import numpy as np


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
			latency_times.append(float(line[time_index+5:ms_index]))

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
	if platform.system().lower() == 'windows':
		command = ["tracert", "-d", "-w", "100", server]
	else:
		command = ["traceroute", server]

	# Run command
	traceroute_output = subprocess.check_output(command)

	traceroute_output_split = traceroute_output.split('\n')

	number_of_hops = 0

	for line in traceroute_output_split:
		if is_number(line[0:3]):
			number_of_hops += 1

	return number_of_hops


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
# Initiate client-relay and relay-end host communication using threads
#
def initiate(relay_nodes_list, hostname, number_of_pings):
	threads_relay_to_end = []
	threads_client_to_relay = []

	direct_thread = threading.Thread( target = direct_func, args = (hostname, number_of_pings))
	direct_thread.start()

	for i in relay_nodes_list:
		t1 = threading.Thread( target = relay_to_end, args = (hostname, i, number_of_pings))
		t2 = threading.Thread( target = client_to_relay, args = (hostname, i, number_of_pings))
		threads_relay_to_end.append(t1)
		threads_client_to_relay.append(t2)

	for i in threads_client_to_relay:
		i.start()
	for i in threads_relay_to_end:
		i.start()
	for i in threads_client_to_relay:
		i.join()
	for i in threads_relay_to_end:
		i.join()
	direct_thread.join()

	# print "All threads for measurements joined!"


#
# Initiate threads to download file from relay using TCP Sockets
#
def download_threads(url, chosen_relay, data_to_write, mode):
	threads = []

	if mode == "online":
		for relay in relay_nodes_list:
			command = url if relay.relay_name == chosen_relay else 'close'
			curr_thread = threading.Thread( target = download_file_online, args = (relay, command, data_to_write))
			threads.append(curr_thread)
	elif mode == "offline":
		for relay in relay_nodes_list:
			command = url if relay.relay_name == chosen_relay else 'close'
			curr_thread = threading.Thread( target = download_file_offline, args = (relay, command, data_to_write))
			threads.append(curr_thread)


	for i in threads:
		i.start()

	for i in threads:
		i.join()

	# print "All threads for downloading image joined!"


#
# Open TCP Socket and send command to relay.
# Exchange RSA key pair
# Exchange AES
# Send command to download file
#
def download_file_offline(relay, command, data_to_write):
	relay_name = relay.relay_name
	relay_ip = relay.ip
	relay_port = relay.port

	#### Generate AES key and object ####
	aes_key = generate_aes_key()
	aes_obj = AES_encryption(aes_key)

	try:
		clientSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		clientSocket.connect((relay_ip , relay_port))

		#### Exchange public keys ####
		clientSocket.send(signed_publickey_message)
		relays_publickey = clientSocket.recv(2048)
		relays_publickey = verify_publickey(relays_publickey)

		#### Send AES key ####
		signature = sign(aes_key, key)
		signature_str = str(signature)
		signed_message =  aes_key + signature_str

		cipher1 = rsa_encrypt(signed_message[0:200], relays_publickey)
		cipher2 = rsa_encrypt(signed_message[200:], relays_publickey)
		cipher = cipher1 + cipher2
		clientSocket.send(cipher)
		relay.aes_key = aes_key

		#### Send offline-mode announcement command ####
		message = "offline"
		cipher = aes_obj.encrypt(message, aes_key)
		clientSocket.send(cipher)
		cipher = clientSocket.recv(2048)
		plaintext = aes_obj.decrypt(cipher, aes_key)
		if plaintext != "ok":
			print " >> Error: Did not receive ok from relay in offline-mode"
			clientSocket.close()
			return

		#### Send command to download file ####
		cipher = aes_obj.encrypt(command, aes_key)
		clientSocket.send(cipher)
		if command == 'close':
			clientSocket.close()
			return

		#### Receive length of file ####
		cipher = clientSocket.recv(2048)
		plaintext = aes_obj.decrypt(cipher, aes_key)
		file_size = int(plaintext)
		# print "File's size to receive is: " + plaintext
		cipher = aes_obj.encrypt("ok", aes_key)
		clientSocket.send(cipher)

		#### Receive, decrypt and save file ####
		cipher = ""
		iter = 0
		while 1:
			iter += 1
			cipher += clientSocket.recv(2048)
			# print "Length of cipher: " + str(len(cipher))
			if len(cipher) == file_size or iter == 30:
				break

		message = aes_obj.decrypt(cipher, aes_key)
		# print "Length of message: " + str(len(message))
		data_to_write.append(message)

	except:
		clientSocket.close()
		return


#
# Open TCP Socket and send command to relay(download file if this is chosen relay)
#
def download_file_online(relay, command, data_to_write):
	relay_name = relay.relay_name
	relay_ip = relay.ip
	relay_port = relay.port + 1

	#### Create AES object with previous aes key ####
	aes_key = relay.aes_key
	aes_obj = AES_encryption(aes_key)

	try:
		clientSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		clientSocket.connect((relay_ip , relay_port))

		#### Send command ####
		cipher = aes_obj.encrypt(command, aes_key)
		clientSocket.send(cipher)
		if command == 'close':
			clientSocket.close()
			return

		#### Receive length of file ####
		cipher = clientSocket.recv(2048)
		plaintext = aes_obj.decrypt(cipher, aes_key)
		file_size = int(plaintext)
		# print "File's size to receive is: " + plaintext
		cipher = aes_obj.encrypt("ok", aes_key)
		clientSocket.send(cipher)

		#### Receive, decrypt and save file ####
		cipher = ""
		iter = 0
		while 1:
			iter += 1
			cipher += clientSocket.recv(2048)
			# print "Length of cipher: " + str(len(cipher))
			if len(cipher) == file_size or iter == 30:
				break

		message = aes_obj.decrypt(cipher, aes_key)
		# print "Length of message: " + str(len(message))
		data_to_write.append(message)

	except:
		clientSocket.close()
		return


#
# Send order to relay to execute measurements from relay to end-users
#
def relay_to_end(hostname, relay, number_of_pings):

	relay_name = relay.relay_name
	relay_ip = relay.ip
	relay_port = relay.port
	connection_failed = 0

	#### Generate AES key and object ####
	aes_key = generate_aes_key()
	aes_obj = AES_encryption(aes_key)

	try:
		clientSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		clientSocket.connect((relay_ip , relay_port))
		
		#### Exchange public keys ####
		clientSocket.send(signed_publickey_message)
		relays_publickey = clientSocket.recv(2048)
		relays_publickey = verify_publickey(relays_publickey)

		#### Send AES key ####
		signature = sign(aes_key, key)
		signature_str = str(signature)
		signed_message =  aes_key + signature_str

		cipher1 = rsa_encrypt(signed_message[0:200], relays_publickey)
		cipher2 = rsa_encrypt(signed_message[200:], relays_publickey)
		cipher = cipher1 + cipher2
		clientSocket.send(cipher)

		#### Send hostname and number of pings to relay ####
		sentence = hostname+" "+number_of_pings
		cipher = aes_obj.encrypt(sentence, aes_key)
		clientSocket.send(cipher)

		#### Get measurements from relay ####
		cipher = clientSocket.recv(1024)
		plaintext = aes_obj.decrypt(cipher, aes_key)
		plaintext = plaintext.split(" ")

		#### Close connection with relay ####
		relay.aes_key = aes_key
		clientSocket.close()
	except:
		connection_failed = 1

	#### Save data ####
	if connection_failed == 0:
		results_relay_to_end_dict[relay_name] = log(float(plaintext[0]), int(plaintext[1]))
	else:
		results_relay_to_end_dict[relay_name] = log(-1, -1)


#
# Execute pings and traceroute from client to each relay
#
def client_to_relay(hostname, relay_nodes_list, number_of_pings):

	ping_output = ping(relay_nodes_list.ip, number_of_pings)
	mean_latency = calculate_mean_latency(ping_output)
	number_of_hops = traceroute(relay_nodes_list.ip)
	results_client_to_relay_dict[relay_nodes_list.relay_name] = log(mean_latency,number_of_hops)


#
# Execute direct client-end pings and traceroute
#
def direct_func(hostname, number_of_pings):

	try:
		direct_ping_output = ping(hostname, number_of_pings)
		direct_mean_latency = calculate_mean_latency(direct_ping_output)
		direct_number_of_hops = traceroute(hostname)
	except:
		print " >> Warning: End server is not reachable via direct path."
		globals()["direct_path"] = log(-1, -1)
		return

	globals()["direct_path"] = log(direct_mean_latency,direct_number_of_hops)

#
# Results object definition
#
class log(object):
	def __init__(self, latency, number_of_hops):
		self.latency = latency
		self.number_of_hops = number_of_hops


#
# Generate RSA pair keys
#
def generate_RSA_pair(key_size = 2048):
	random_generator = Random.new().read
	key = RSA.generate(key_size, e=65537)

	return key


#
# Relay node object definition
#
class relay_node(object):
	def __init__(self, relay_name, ip, port):
		self.relay_name = relay_name
		self.ip 		= ip
		self.port 		= port
		self.aes_key	= -1


#
# Class used for coloring
#
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

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


#
# Generate a key for AES CBC 256 encryption
#
def generate_aes_key(length = 32):
	return os.urandom(length)


#
# RSA Padding and encrypting
#
def rsa_encrypt(message, public_key):
	cipher = PKCS1_OAEP.new(public_key)
	return cipher.encrypt(message)


#
# RSA Padding and decrypting
#
def rsa_decrypt(cipher, priv_key):
	decrypted_message = PKCS1_OAEP.new(priv_key)
	return decrypted_message.decrypt(cipher)


#
# RSA signing
#
def sign(message, priv_key):
	hash = SHA256.new()
	hash.update(message)
	signer = PKCS1_PSS.new(priv_key)
	return signer.sign(hash)


#
# RSA verifying signature
#
def verify(message, signature, pub_key):
	hash = SHA256.new()
	hash.update(message)
	verifier = PKCS1_PSS.new(public_key)
	return verifier.verify(hash, signature)


#
# Creating log file entry
#
def insert_to_log_file(hour, best_path, file_size, url):

	relay_names_list = ["direct"]
	url_list = []


	for i in relay_nodes_list:
		relay_names_list.append(i.relay_name)
	for i in files2download:
		url_list.append(files2download[i])

	# print relay_names_list
	# print url_list

	counter = 1
	for i in relay_names_list:
		if best_path == i:
			best_path_label = counter
			break
		counter += 1

	#### Decide end_user based on url ####
	counter = 1
	for i in url_list:
		if url == i:
			end_user_label = counter
			break
		counter += 1

	#### Decide time by splitting the day into 4 parts ####
	if 0 <= hour <= 5:
		hour_entry = 1
	elif 6 <= hour <= 11:
		hour_entry = 2
	elif 12 <= hour <= 17:
		hour_entry = 3
	else:
		hour_entry = 4

	#### Decide label for criteria ####
	if criteria == 'latency':
		criteria_label = 1
	else:
		criteria_label = 2

	#### Writing to logfile ####
	row = [hour_entry, end_user_label, file_size, criteria_label, best_path_label]
	print "Logfile entry: " + str(row)

	if os.path.isfile('logFile.csv') == False:
		with open('logFile.csv', 'a+') as logFile:
			writer = csv.writer(logFile)
			header = ["Hour", "Endserver", "Filesize", "Criteria", "Path"]
			writer.writerow(header)

	with open('logFile.csv', 'a+') as logFile:
		writer = csv.writer(logFile)
		writer.writerow(row)

	logFile.close()

#
# Class used for analysis when reading from csv
#
class log_file_entry:
	def __init__(self, hour, end_server, file_size, criteria, path):
		self.hour = hour
		self.end_server = end_server
		self.file_size = file_size
		self.criteria = criteria
		self.path = path


#
# Class used for analysis when reading from csv
#
class path_analysis:
	def __init__(self, name, selected_latency, selected_number_of_hops):
		self.name = name
		self.selected_latency = selected_latency
		self.selected_number_of_hops = selected_number_of_hops


#
# Function for generating labels for every rect in the plot
#
def autolabel(rects, xpos='center'):

	ha = {'center': 'center', 'right': 'left', 'left': 'right'}
	offset = {'center': 0, 'right': 1, 'left': -1}

	for rect in rects:
		height = rect.get_height()
		ax.annotate('{}'.format(height),
					xy=(rect.get_x() + rect.get_width() / 2, height),
					xytext=(offset[xpos]*3, 3),  # use 3 points offset
					textcoords="offset points",  # in both directions
					ha=ha[xpos], va='bottom')


#### Read servers and relay nodes from file ####

end_servers = dict()
relay_nodes_list = []
files2download = dict()
results = dict()

results_relay_to_end_dict = dict()
results_client_to_relay_dict = dict()
end_servers_list = []

if sys.argv[1] == "-e" and sys.argv[3] == "-r":
	try:
		with open(sys.argv[2]) as file:
			data = file.readline()
			while data:
				data = data.split(',')
				data[1] = data[1].strip()
				end_servers[data[1]] = data[0]
				end_servers_list.append(data[0])
				data = file.readline()
	except:
		print " >> Error: Couldn't open end servers file."
		exit()
	try:
		with open(sys.argv[4]) as file:
			data = file.readline()
			while data:
				data = data.split(' ')
				relay_nodes_list.append(relay_node(data[0],data[1],int(data[2])))
				data = file.readline()
	except:
		print " >> Error: Couldn't open relay nodes file."
		exit()
else :
	print " >> Error: Wrong arguments, possible call is:"
	print "  > python client.py -e endservers.txt -r relaynodes.txt"
	exit()


#### Generate RSA keys pair ####

key = generate_RSA_pair()
public_key = key.publickey()


#### Create public key signed message ####

public_key_str = public_key.exportKey("PEM")
hash = SHA256.new(public_key_str).digest()
signature = key.sign(hash, '')
signature_str = str(signature)
signed_publickey_message = signature_str + public_key_str


#### Select mode ####

print "[1] Default"
print "[2] Offline"
print "[3] Train"
print "[4] Analysis"
while True:
	input = raw_input("Please select one of the modes above (1-4): ")
	if is_number(input) == False:
		continue
	input = int(input)

	if input < 1 or input > 4:
		continue
	elif input == 1:
		mode = "default"
		print "\n ## Default mode ## \n"
	elif input == 2:
		mode = "offline"
		print "\n ## Offline mode ## \n"
	elif input == 3:
		mode = "train"
		print "\n ## Train mode ## \n"
	else:
		mode = "analysis"
		print "\n ## Analysis mode ## \n"
	break


#### Offline-mode ####

correct_input = 0

if mode == 'offline':
	print "Please choose which file you want to download:"

	with open("files2download.txt") as file:
		counter = 1
		for f in file:
			files2download[counter] = f.rstrip()
			print "[" + str(counter) + "]\t" + f
			counter = counter + 1
	while True:
		input = raw_input("Enter number from 1-%d:\n" %len(files2download))
		if is_number(input) == False or int(input) < 1 or int(input) > len(files2download):
			continue
		break

	end_user_label = int(input)
	url = files2download[end_user_label]
	file = urllib2.urlopen(url)
	meta = file.info()
	file_size = meta.getheaders("Content-Length")[0]

	while True:
		input = raw_input("\nPlease enter (l)atency or number_of_(h)ops to pick your criteria: ")
		if input == 'l' or input == 'L':
			criteria_label = 1
			break
		elif input == 'h' or input == 'H':
			criteria_label = 2
			break

	hour = datetime.datetime.now().hour
	if 0 <= hour <= 5:
		hour_entry = 1
	elif 6 <= hour <= 11:
		hour_entry = 2
	elif 12 <= hour <= 17:
		hour_entry = 3
	else:
		hour_entry = 4

	#### Create relays list to match indexes ####
	relay_names_list = ["direct"]
	for i in relay_nodes_list:
		relay_names_list.append(i.relay_name)

	#### Machine learning algorithm ####
	df_base = pandas.read_csv("logFile.csv", header=0)
	df = df_base.dropna(how='any')
	X = df.iloc[:, :-1]
	y = df.iloc[:, -1]
	clf_0 = SVC(gamma='auto').fit(X, y)
	# clf_1 = LogisticRegression().fit(X, y)
	# clf_2 = RandomForestClassifier().fit(X, y)
	# print "Score of LR: " + str(clf_1.score(X,y))
	# print "Score of RF: " + str(clf_2.score(X,y))

	ML_result = clf_0.predict([[hour, end_user_label, file_size, criteria_label]])

	#### Translate ML_result ####
	ML_result_int = int(ML_result[0])
	if ML_result_int == 1:
		best_path = "direct"
	else:
		ML_result_int -= 1
		best_path = relay_names_list[ML_result_int]
	scores = cross_val_score(clf_0, X, y, cv=5)

	print "\nMachine Learning"
	print "=================="
	# print "ML_result = " + str(ML_result)
	print "Best path: " + str(best_path)
	print "Score: " + str(scores.mean())

	#### Download file ####
	t0 = time.time()
	file_name_list = url.split('/')
	file_name = file_name_list[len(file_name_list) - 1]
	path_to_save = './' + file_name
	data_to_write = []

	if best_path == "direct":
		try:
			filedata = urllib2.urlopen(url)
		except:
			print " >> Error: Couldn't download file."
			exit()
		data_to_write.append(filedata.read())
		download_threads(url, best_path, data_to_write, "offline")
	else:
		download_threads(url, best_path, data_to_write, "offline")
	t1 = time.time()

	total_time_for_download = t1-t0
	print "\nTotal time to download image is: %.2f seconds" %total_time_for_download

	try:
		with open(path_to_save, 'wb') as f:
			f.write(data_to_write[0])
	except:
		print " >> Error: Couldn't save file."

	exit()


#### Training mode ####

if mode == "train":

	while True:
		input = raw_input("Please enter number of iterations: ")
		if is_number(input):
			break

	iterations = int(input)
	mode = "train"

	for z in range(0, iterations):
		#### Decide Randomly ####
		hostname_rand = random.randint(0,len(end_servers) - 1)
		number_of_pings = random.randint(1, 20)
		criteria = random.randint(1,2)
		if criteria == 1:
			criteria = "latency"
		else:
			criteria = "number_of_hops"

		#### Get hostname and url ####
		hostname = end_servers_list[hostname_rand]

		print "\n===================================================================="
		print "Random: " + hostname + " " + str(number_of_pings) + " " + criteria

		#### Inititate threads for measurements ####
		initiate(relay_nodes_list, hostname, str(number_of_pings))

		#### Calculate results ####
		for i in relay_nodes_list:
			log1 = results_client_to_relay_dict[i.relay_name]
			log2 = results_relay_to_end_dict[i.relay_name]
			if log2.latency == -1:
				results[i.relay_name] = log(-1, -1)
			else:
				results[i.relay_name] = log(log1.latency + log2.latency, log1.number_of_hops + log2.number_of_hops)

		results["direct"] = log(direct_path.latency, direct_path.number_of_hops)

		print "\nPATH\t" + " Latency\t" + " Number of hops"
		print "========================================="
		for i in results:
			if results[i].latency == -1:
				continue
			print str(i) + "\t" + str(results[i].latency) + "\t\t" + str(results[i].number_of_hops)

		#### Find best baths ####
		min_latency_path = "none"
		min_number_of_hops_path = "none"
		min_latency = -1
		min_number_of_hops = -1

		for i in results:
			if results[i].latency == -1:
				continue

			if min_latency == -1:
				min_latency = results[i].latency
				min_latency_path = i
			elif results[i].latency == min_latency:
				if results[i].number_of_hops < results[min_latency_path].number_of_hops:
					min_latency_path = i
			elif results[i].latency < min_latency:
				min_latency = results[i].latency
				min_latency_path = i

			if min_number_of_hops == -1:
				min_number_of_hops = results[i].number_of_hops
				min_number_of_hops_path = i
			elif results[i].number_of_hops == min_number_of_hops:
				if results[i].latency < results[min_number_of_hops_path].latency:
					min_number_of_hops_path = i
			elif results[i].number_of_hops < min_number_of_hops:
				min_number_of_hops = results[i].number_of_hops
				min_number_of_hops_path = i

		#### Choose best path based on criteria ####
		best_path = "none"
		if min_latency_path == "none":
			print "Sorry no paths found"
		if criteria == "latency":
			best_path = min_latency_path
		else:
			best_path = min_number_of_hops_path
		print "\nBased on " + criteria + " best path is: " + best_path + "\n"

		#### Choose file to download ####
		data_to_write = []

		with open("files2download.txt") as file:
			counter = 1
			for f in file:
				files2download[counter] = f.rstrip()
				counter = counter + 1
		url = files2download[hostname_rand + 1]
		download_threads(url, "none", data_to_write, "online")

		if best_path == "none":
			continue

		#### Get size of file ####
		file = urllib2.urlopen(url)
		meta = file.info()
		file_size = meta.getheaders("Content-Length")[0]

		#### Create entry ####
		hour = datetime.datetime.now().hour
		insert_to_log_file(hour, best_path, file_size, url)

	exit()


#### Analysis mode ####

if mode == "analysis":

	#### Read logfile, create list with entries ####
	log_file_entries = []
	line_count = 0

	with open('logfile.csv') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
				continue
			elif len(row) == 0:
				continue
			log_file_entries.append(log_file_entry(int(row[0]), int(row[1]), int(row[2]), int(row[3]), int(row[4])))
			line_count += 1

	#### Count for paths ####
	paths_analysis_list = []

	paths_analysis_list.append(path_analysis('direct', 0, 0))

	for i in relay_nodes_list:
		paths_analysis_list.append(path_analysis(i.relay_name, 0, 0))

	for i in log_file_entries:
		if i.criteria == 1:
			paths_analysis_list[i.path - 1].selected_latency += 1
		else:
			paths_analysis_list[i.path - 1].selected_number_of_hops += 1

	#### Find top selected path ####
	max_selected_latency_path = 0
	max_selected_hops_path = 0
	max_selected_path = 0
	index_counter = 0

	for i in paths_analysis_list:
		# print str(i.selected_latency) + " < " + str(paths_analysis_list[max_selected_latency_path].selected_latency)
		if i.selected_latency > paths_analysis_list[max_selected_latency_path].selected_latency:
			max_selected_latency_path = index_counter

		# print str(i.selected_number_of_hops) + " < " + str(paths_analysis_list[max_selected_latency_path].selected_number_of_hops)
		if i.selected_number_of_hops > paths_analysis_list[max_selected_hops_path].selected_number_of_hops:
			max_selected_hops_path = index_counter

		# print str(i.selected_number_of_hops + i.selected_latency) + " < " + str(paths_analysis_list[max_selected_path].selected_latency + paths_analysis_list[max_selected_path].selected_number_of_hops)
		if i.selected_number_of_hops + i.selected_latency > paths_analysis_list[max_selected_path].selected_latency + paths_analysis_list[max_selected_path].selected_number_of_hops:
			max_selected_path = index_counter

		index_counter += 1

	print "Name\t" + "#Latency\t" + "#Hops"
	print "======================================="
	for i in paths_analysis_list:
		print i.name + "\t" + str(i.selected_latency) + "\t\t" + str(i.selected_number_of_hops)

	print "\nTop selected path regarding latency is: " + paths_analysis_list[max_selected_latency_path].name
	print "Top selected path regarding number of hops is: " + paths_analysis_list[max_selected_hops_path].name
	print "Top selected path in general is: " + paths_analysis_list[max_selected_path].name
	print "Number of entries: " + str(line_count)

	#### Need for plotting ####
	paths_names_list = []
	for i in paths_analysis_list:
		paths_names_list.append(i.name)

	paths_scores_latency_list = []
	for i in paths_analysis_list:
		paths_scores_latency_list.append(i.selected_latency)

	paths_scores_hops_list = []
	for i in paths_analysis_list:
		paths_scores_hops_list.append(i.selected_number_of_hops)

	paths_scores_percent_list = []
	for i in paths_analysis_list:
		sum_score = i.selected_number_of_hops + i.selected_latency
		paths_scores_percent_list.append((sum_score * 100) / line_count)
		# print (i.selected_number_of_hops + i.selected_latency) / line_count


	#### Plotting Bars ####
	ind = np.arange(len(paths_analysis_list))
	width = 0.35

	fig, ax = plt.subplots()
	rects1 = ax.bar(ind - width/2, paths_scores_latency_list, width, label='Selected Latency')
	rects2 = ax.bar(ind + width/2, paths_scores_hops_list, width, label='Selected Number of Hops')

	ax.set_ylabel('Scores')
	ax.set_title("Scores by Path")
	ax.set_xticks(ind)
	ax.set_xticklabels(paths_names_list)
	ax.legend()

	autolabel(rects1, "left")
	autolabel(rects2, "right")

	fig.tight_layout()

	# plt.show()

	#### Plotting Pie ####
	labels = paths_names_list
	sizes = paths_scores_percent_list
	# explode =

	fig1, ax1 = plt.subplots()
	wedges, texts, autotexts = ax1.pie(sizes, autopct = '', pctdistance=1.1, labeldistance=1.2, shadow=False, startangle=90, radius=0.1)
	ax1.legend(wedges, labels, title="Paths", loc="upper left", bbox_to_anchor=(-0.1,1.15))
	ax1.set_title("Path's Selection Percentage")

	ax1.axis('equal')

	plt.show()

	exit()


#### Read server, number_of_pings, criteria from user ####

while correct_input != 1:
	input = raw_input("Please enter 'endserver' 'number_of_pings' 'criteria':\n")
	input = input.split()

	try:
		hostname = end_servers.get(input[0])
		number_of_pings = input[1]
		criteria = input[2]
		correct_input = 1
	except:
		print " >> Error: Wrong arguments, example input:"
		print "    google 10 latency"
		continue

	if is_number(number_of_pings) == False:
		correct_input = 0
		print " >> Error: number_of_pings is not a number."
	if criteria.lower() != "latency" and criteria.lower() != "number_of_hops":
		correct_input = 0
		print " >> Error: Criteria is not valid. Please enter 'latency' or 'number_of_hops'."
	if hostname == None:
		correct_input = 0
		print " >> Error: Hostname is not valid."


#### Inititate threads for direct path, client to relay and relay to end measurements ####

initiate(relay_nodes_list, hostname, number_of_pings)


#### Print results sent from relays ####

for i in relay_nodes_list:
	log1 = results_client_to_relay_dict[i.relay_name]
	log2 = results_relay_to_end_dict[i.relay_name]
	if log2.latency == -1:
		results[i.relay_name] = log(-1, -1)
	else:
		results[i.relay_name] = log(log1.latency + log2.latency, log1.number_of_hops + log2.number_of_hops)


results["direct"] = log(direct_path.latency, direct_path.number_of_hops)

print "\nPATH\t" + " Latency\t" + " Number of hops"
print "========================================="

for i in results:
	if results[i].latency == -1:
		continue
	print str(i) + "\t" + str(results[i].latency) + "\t\t" + str(results[i].number_of_hops)


#### Find best baths ####

min_latency_path = "none"
min_number_of_hops_path = "none"
min_latency = -1
min_number_of_hops = -1

for i in results:
	if results[i].latency == -1:
		continue

	if min_latency == -1:
		min_latency = results[i].latency
		min_latency_path = i
	elif results[i].latency == min_latency:
		if results[i].number_of_hops < results[min_latency_path].number_of_hops:
			min_latency_path = i
	elif results[i].latency < min_latency:
		min_latency = results[i].latency
		min_latency_path = i

	if min_number_of_hops == -1:
		min_number_of_hops = results[i].number_of_hops
		min_number_of_hops_path = i
	elif results[i].number_of_hops == min_number_of_hops:
		if results[i].latency < results[min_number_of_hops_path].latency:
			min_number_of_hops_path = i
	elif results[i].number_of_hops < min_number_of_hops:
		min_number_of_hops = results[i].number_of_hops
		min_number_of_hops_path = i

#print "Min number of hops: " + min_number_of_hops_path + " " + str(min_number_of_hops)
#print "Min latency: " + min_latency_path + " " + str(min_latency)


#### Choose best path based on criteria ####

best_path = "none"

if min_latency_path == "none":
	print "Sorry no paths found"
	exit()

if criteria == "latency":
	best_path = min_latency_path
else:
	best_path = min_number_of_hops_path

print "\nBased on " + criteria + " best path is: " + best_path + "\n"


#### Choose file to download ####

print "Please choose which file you want to download:"

with open("files2download.txt") as file:
	counter = 1
	for f in file:
		files2download[counter] = f.rstrip()
		print "[" + str(counter) + "]\t" + f
		counter = counter + 1
while True:
	input = raw_input("Enter number from 1-%d:\n" %len(files2download))
	if is_number(input) == False or int(input) < 1 or int(input) > len(files2download):
		continue
	break


#### Download file choosen ####

image_index = int(input)
url = files2download[image_index]
file_name_list = url.split('/')
file_name = file_name_list[len(file_name_list) - 1]
path_to_save = './' + file_name
data_to_write = []

t0 = time.time()
if best_path == "direct":
	try:
		filedata = urllib2.urlopen(url)
	except:
		print " >> Error: Couldn't download file."
		exit()
	data_to_write.append(filedata.read())
	download_threads(url, best_path, data_to_write, "online")
else:
	download_threads(url, best_path, data_to_write, "online")
t1 = time.time()

total_time_for_download = t1-t0
print "\nTotal time to download image is: %.2f seconds\n" %total_time_for_download

with open(path_to_save, 'wb') as f:
	f.write(data_to_write[0])
	

#### Log file creation ####

file_size = len(data_to_write[0])
#print "file size = " + str(file_size/1000)
hour = datetime.datetime.now().hour
#print "hour = " + str(hour)
insert_to_log_file(hour, best_path, file_size, url)
