# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. 
# Author: Daniel Fokum 2018-11-08
# Version: 0.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import pickle
import simplified_AES

# 
def rollDice(dice, toRoll=[0,1,2,3,4]):
        """Rolls specified dice. If no dice are specified, all dice are rolled."""
        for i in toRoll:
                dice[i] = random.randint(1,6)

def expMod(b,n,m):
	"""Computes the modular exponent of a number"""
	"""returns (b^n mod m)"""
	if n==0:
		return 1
	elif n%2==0:
		return expMod((b*b)%m, n/2, m)
	else:
		return(b*expMod(b,n-1,m))%m

def RSAcrypt(txt, exponent, n):
    """Encryption/decryption side of RSA. Operation invoked will depend on 
		txt and exponent.
    """
	"""You need to implement this function."""
    return 5        ## Add code here to do encryption

def gcd(u, v):
    """Iterative Euclidean algorithm"""
    ## Write code to compute the gcd of two integers

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""
    ## Write code to implement the Extended Euclidean algorithm. See Tutorial 7
    ## This method should return the multiplicative inverse of n mod m.
    ## i.e., (n*e^(-1) mod m = 1
    ## If this method returns a negative number add m to that number until
    ## it becomes positive.

def generateNonce():
	"""This method returns a 16-bit random integer derived from hashing the
	    current time. This is used to test for liveness"""
	hash = hashlib.sha1()
	hash.update(str(time.time()).encode('utf-8'))
	return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

def findE(phi):
	"""Method to randomly choose a good e given phi"""
	return 7

def genKeys(p, q):
	"""Generate n, phi(n), e, and d."""
	n = ## Complete this
	phi = ## Complete this
	e = findE(phi)
	
	d = ext_Euclid(phi, e) #Using the extended Euclidean algorithm to compute d
	if (d < 0):
		d += phi
	print ("n = "+ str(n))
	print ("phi(n) = "+ str(phi))
	print ("e = "+ str(e))
	print ("d = "+ str(d))
	print
	return n, e, d	

def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "101 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "120 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
       from the client."""
    if (nonce == decryptedNonce):
    	status = "200 OK"
    else:
    	status = "400 Error Detected"
    return status

def RollDiceACK(dice):
    """Sends client their rolled dice"""
    strDice = ','.join([str(x) for x in new])
    status = "205 Roll Dice ACK " + strDice
    return status

def bidACK(dice, query):
    """Generates message with query"""
    strDice = ','.join([str(x) for x in dice])
    if query == 'b':
        status = "305 Bid ACK " + strDice
    elif (query == 'c'):
        status = "305 Bid ACK Challenge" 
    return status

def rollDice(dice, toRoll=[0,1,2,3,4]):
    """Rolls the dice."""
    randomText = " "
    for i in toRoll:
        dice[i] = random.randint(1,6)
        strDice = str(dice[i])
        randomText += strDice + ", "
        randomText.rstrip(',')
    return randomText


def make_bid(bid, msg):
     """This function processes messages that are read through the socket. It
    determines whether or not the bid made is valid and returns a status.
    """

    """You will need to complete this method """
    msg = msg.split(' ')
    frequency = bid[0]
    value = bid[1]

def challenge(roll, clientRoll, msg):
    print("Server roll is: " + roll)
    print("Client's roll is: " + clientRoll)
   """This function processes messages that are read through the socket. It
    receives the client's roll and shows the server's roll. It also determines
    whether or not the challenge made is valid and returns a status.
    """

    """You will need to complete this method """


# s      = socket
# msg     = initial message being processed
def processMsgs(s, msg):
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
    """You will need to complete this method """
	status = -2
	modulus = int(state['modulus'])			# modulus    = modulus for RSA
	pub_exp = int(state['pub_exp'])			# pub_exp    = public exponent
	priv_exp = int(state['priv_exp'])		# priv_exp   = secret key
	challenge = int(state['nonce'])			# challenge  = nonce sent to client
	SymmKey = int(state['SymmetricKey'])	# SymmKey    = shared symmetric key
    bids = int(state['Bids'])               # bids       = number of bids made
    ClientDice  = state['ClientDice']       # ClientDice = values of dice
    ServerDice  = state['ServerDice']       # ServerDice = values of dice
    ClientDice = list(map(int,ClientDice))  # Converting dice values to ints
    ServerDice = list(map(int,ServerDice))  # Converting dice values to ints
	
	strTest = "100 Hello"
	if strTest in msg and status == -2:
		msg = clientHelloResp(modulus, pub_exp)
		s.sendall(bytes(msg,'utf-8'))
		status = 1
	
	strSessionKey = "110 SessionKey"
	if strSessionKey in msg and status == -2:
		RcvdStr = msg.split(' ')
		encSymmKey = int(RcvdStr[2])
		SymmKey = ## Add code to decrypt symmetric key
		state['SymmetricKey'] = SymmKey
		# The next line generates the round keys for simplified AES
		simplified_AES.keyExp(SymmKey)
		challenge = generateNonce()
		# Add code to ensure that the challenge can always be encrypted
		#  correctly with RSA.
		state['nonce'] = challenge
		msg = SessionKeyResp(RSAcrypt(challenge, priv_exp, modulus))
		s.sendall(bytes(msg, 'utf-8'))
		status = 1
	
	strSessionKeyResp = "130 "
	if strSessionKeyResp in msg and status == -2:
		RcvdStr = msg.split(' ')
		encryptedChallenge = int(RcvdStr[1])
		# The next line runs AES decryption to retrieve the key.
		decryptedChallenge = simplified_AES.decrypt(encryptedChallenge)
		msg = nonceVerification(challenge, decryptedChallenge)
		s.sendall(bytes(msg,'utf-8'))
		status = 0	# To terminate loop at server.
	
	# status can only be -2 if none of the other branches were followed
	if status==-2:
		print("Incoming message was not processed. \r\n Terminating")
		status = -1
	return status
    

def main():
	"""Driver function for the project"""
	args = sys.argv
	if len(args) != 2:
		print ("Please supply a server port.")
		sys.exit()
	HOST = ''		# Symbolic name meaning all available interfaces
	PORT = int(args[1])     # The port on which the server is listening
	if PORT < 1023 or PORT > 65535:
		print("Invalid port specified.")
		sys.exit()
	print ("Enter prime numbers. One should be between 907 and 1013, and\
 the other between 53 and 67")
	p = int(input('Enter P : '))
	q = int(input('Enter Q: '))
	n, e, d = genKeys(p, q)
    random.seed()
	bids = 0
	lastBid = [0,0]
    ClientDice = [random.randint(1,6), random.randint(1,6), random.randint(1,6),
            random.randint(1,6),random.randint(1,6)]
    ServerDice = [random.randint(1,6), random.randint(1,6), random.randint(1,6),
            random.randint(1,6),random.randint(1,6)]

	
	SymmKey = 1013	# Initializing symmetric key with a bogus value.
	nonce = generateNonce()
	
	state = {'nonce': nonce, 'modulus': n, 'pub_exp': e, 'priv_exp': d,
		'SymmetricKey': SymmKey, 'LastBid': lastBid, 'Bids': bids,
	 	'ClientDice': ClientDice, 'ServerDice': ServerDice}
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((HOST, PORT))
		s.listen(1)
		conn, addr = s.accept()
		with conn:
			print('Connected by', addr)
			status = 1
			while (status==1):
				msg = conn.recv(1024).decode('utf-8')
				if not msg:
					status = -1
				else:
					status = processMsgs(conn, msg, state)
			if status < 0:
				print("Invalid data received. Closing")
			conn.close()
			print("Closed connection socket")

if __name__ == "__main__":
	main()
