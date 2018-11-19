# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Next,
# the server sends the client a message with a status code. If the status code
# is "250" then the client can ask for the server to roll the dice. Otherwise,
# the client's connection to the server will be terminated.
# Author: Daniel Fokum
# Version: 0.1
#!/usr/bin/python3

import socket
import math
import random
import sys
import time
import simplified_AES


def expMod(b,n,m):
    """Computes the modular exponent of a number returns (b^n mod m)"""
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
    pass

def serverHello():
    """Generates server hello message"""
    status = "100 Hello message"
    return status

def sendSessionKey(s):
    """Sends server session key"""
    status = "110 SessionKey " + str(s)
    return status

def sendTransformedNonce(xform):
    """Sends server nonce encrypted with session key"""
    status = "130 Transformed Nonce " + str(xform)
    return status

def computeSessionKey():
    """Computes this node's session key"""
    sessionKey = random.randint(1, 65536)
    return sessionKey

def RollDice():
    """Generates message to get server to roll some or all dice."""
    toRoll = input('Roll all the dice? (y/n): ')
    toRoll = str(toRoll)
    if toRoll == 'y' or toRoll == 'Y':
        status = "200 Roll Dice"
    else:
		print("You exited the game!")
        status = ""
    return status
    
def make_bid(state):
    """This function determines whether the bid made is valid and
       returns a status.
    """
	bid  = state['lastBid']    
    bid = list(map(int,bid)) 
	status = -1
    frequency = bid[0]
    value = bid[1]
	
	face = input('Enter face value for your bid. Enter 0 to challenge: ')
    numFaces = input('Enter number of face value in your bid. Enter 0 to challenge: ')
	if (face !=0 and numFaces !=0):
		if (numFaces > frequency or face > value):
			status = 1
		else:
			print("Last bid was invalid")
			face = input('Enter face value for your bid. Enter 0 to challenge: ')
			numFaces = input('Enter number of face value in your bid. Enter 0 to challenge: ')
			status=1
	bid[0] = numFaces
	bid[1] = face
	state['lastBid'] = bid
	return status

def MakeBidMsg(state):
    """Generates message to send a bid to the server."""
	"""A bid of '300 Bid 0 0' is a challenge. """
	make_bid(state)
	bid  = state['lastBid']    
    bid = list(map(int,bid)) 
	status = "300 Bid " + str(bid[1]) + " " + str(bid[0])
    return status  

def challenge(roll, msg):
    """This function processes messages that are read through the socket. It
    receives the client's roll and shows the server's roll. It also determines
    whether or not the challenge made is valid and returns a status.
    """

    """You will need to complete this method """
    
    print('Client roll is: ' + roll)
    print('Opponent\'s roll is: ' + msg[8])



# s       = socket
# msg     = initial message being processed
def processMsgs(s, msg, state):
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
        
    status = -2
    rcvr_mod = int(state['modulus'])            # Receiver's modulus for RSA
    rcvr_exp = int(state['pub_exp'])            # Receiver's public exponent
    symmetricKey = int(state['SymmetricKey'])   # shared symmetric key

    bids = int(state['Bids'])                # bids       = number of bids made
    DiceValues  = state['Dice']              # DiceValues = values of dice
    dice = list(map(int,dice))               # Converting dice values to ints

	strTest = "101 Hello "
	if (strTest in msg and status==-2):
		RcvdStr = msg.split(' ')
		sndr_mod = int(RcvdStr[2]) # Modulus for public key encryption
		sndr_exp = int(RcvdStr[3]) # Exponent for public key encryption
		symmetricKey = computeSessionKey()
		## Add code to handle the case where the symmetricKey is
		## greater than the modulus.
		encSymmKey = ## Add code to encrypt the symmetric key.
		msg = sendSessionKey(encSymmKey)
		s.sendall(bytes(msg,'utf-8'))
		state['modulus'] = sndr_mod
		state['pub_exp'] = sndr_exp
		state['SymmetricKey'] = symmetricKey
		status = 1
	
	strNonce = "120 Nonce"
	if (strNonce in msg and status==-2):
		RcvdStr = msg.split(' ')
		encNonce = int(RcvdStr[2])
		nonce = ## Add code to decrypt nonce
		"""Setting up for Simplified AES encryption"""
		plaintext = nonce
		simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
		ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
		msg = sendTransformedNonce(ciphertext)
		s.sendall(bytes(msg,'utf-8'))
		status = 1

    strDiceRoll = "205 Roll Dice ACK"
    if (strDiceRoll in msg and status==-2):
        print("Message received: " + msg)
        DiceValues = msg[18:].split(',')
        if bids < 2:
            msg = MakeBidMsg(state):
            s.sendall(bytes(msg,'utf-8'))
            bids += 1
            status = 1
        else:
            status = 0
        state['Bids'] = bids

    strBidAck = "305 Bid ACK"
    if (strBidAck in msg and status==-2):
        print("Message received: " + msg)
        BidReceived = msg[12:].split(' ')
        if bids < 2:
            msg = MakeBidMsg(state):
            s.sendall(bytes(msg,'utf-8'))
            bids += 1
            status = 1
        else:
            status = 0
        state['Bids'] = bids

	strSuccess = "200 OK"
	strFailure = "400 Error"
	if ((strSuccess in msg or strFailure in msg) and status==-2):
		status = 0 # To terminate loop at client
	
	if status==-2:
		print("Incoming message was not processed. \r\n Terminating")
		status = -1
	return status                

def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("Please supply a server address and port.")
        sys.exit()
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server
    
    print("\nClient of _____")
    print('''
      The dice in this program have a face value in the range 1--6.
    No error checking is done, so ensure that the bids are in the correct range.
    Follow the on-screen instructions.
    ''')
    random.seed()
    dice = [random.randint(1,6), random.randint(1,6), random.randint(1,6),
            random.randint(1,6),random.randint(1,6)]
    bids = 0
	lastBid = [0,0]
	# Bogus values that will be overwritten with values read from the socket.
	sndr_exp = 3
	sndr_mod = 60769
	symmKey = 32767
    state = {'LastBid': lastBid, , 'Bids': bids, 'Dice': dice, 
			 'modulus': sndr_mod, 'pub_exp': sndr_exp, 'SymmetricKey': symmKey}
  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((serverHost, serverPort))
    msg = serverHello()
    s.sendall(bytes(msg,'utf-8'))
    status = 1
    while (status==1):
        msg = s.recv(1024).decode('utf-8')
        if not msg:
            status = -1
        else:
            status = processMsgs(s, msg, state)
    if status < 0:
        print("Invalid data received. Closing")
    s.close()

if __name__ == "__main__":
    main()

