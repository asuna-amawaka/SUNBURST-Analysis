# Written by Asuna Amawaka
# Last Modified 20 Dec 2020

import sys
import random

def reverse_Base64Decode(string):
    # this function is taken from QiAnXin's decode.py
	text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj"
	text2 = "0_-."
	retstring = ""
	flag = False
	for i in range(len(string)):
		ch = string[i]
		tx_index = -1
		tx2_index = -1
		if flag:
			t1i = text.find(ch)
			x = t1i - ((random.randint(0,8) % (len(text) / len(text2))) * len(text2))
			retstring = retstring+text2[x % len(text2)]
			flag = False
			continue
		if ch in text2:
			tx2_index = text2.find(ch)
			flag = True
			pass
		else:
			tx_index = text.find(ch)
			oindex = tx_index - 4
			retstring = retstring+text[oindex % len(text)]

		pass
	return retstring
    
    
def reverse_Base64Encode(string, length):
    # my implementation of the reversal of the base32-like encoding
	text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	result = []
	s1 = text.find(string[0]) 
	s2 = text.find(string[1]) << 5 
	result.append(s1|s2 & 255)
	if len(string) < 3:
		return result
	accumulator = s1|s2
	index = 2
	i = 3
	firstloop = True
	for c in range(length):
		j = i
		accumulator >>= 8
		loopcount = 0
		i += 8
		while (i >= 5 and index < len(string)):
			accumulator |= text.find(string[index]) << 5 >> j << (5 * loopcount)
			loopcount += 1	
			index += 1
			i -= 5
		result.append(accumulator & 255)
	return result 
    
    
def reverse_CreateSecureString(string, length):
    # first byte is the XOR key
	result = ""
	for i in range(1, length + 1):
		result += str.format('0x{:02X}',(string[i] ^ string[0]))[2:]
	return result


def reverse_UpdateBuffer(string, length):
    # string[9] and string[10] are the XOR keys
	result = ""
	string_h = [int(string[i:i+2], 16) for i in range(0, len(string), 2)]
	for i in range(length):
		x = length + 2 - i % 2
		result += str.format('0x{:02X}',(string_h[i] ^ string_h[x]))[2:]
	return result


def getVictimGUID_fromDGA_type2(string):
    # if the DGA string is an output from OrionImprovementBusinessLayer.CryptoHelper.UpdateBuffer
    # then retrieve encoded victim GUID from DGA string.
    # what UpdateBuffer does is append 3 bytes of timestamp to the 8byte victim GUID 
    # last two bytes of time value is used as the XOR key to code the victim GUID
    
    # reversing the logic in OrionImprovementBusinessLayer.CryptoHelper.Base64Encode
    temp = reverse_Base64Encode(string, 11)
    
    # reversing the logic in OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString
    enc_guid = reverse_CreateSecureString(temp, 11)
    
    # reversing the logic in OrionImprovementBusinessLayer.CryptoHelper.UpdateBuffer
    return reverse_UpdateBuffer(enc_guid, 8)
    
    
def getVictimGUID_fromDGA_type1(string):
    # this function helps to retrieve the original 8byte victim GUID to identify 
    # dga that belongs to same victim
    # e.g.   1fik67gkncg86q6daovthro0love0oe2.appsync-api.us-west-2.avsvmcloud.com
    
    # reversing the logic in OrionImprovementBusinessLayer.CryptoHelper.Base64Encode
	temp = reverse_Base64Encode(string, 8)
    
    # reversing the logic in OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString
	return reverse_CreateSecureString(temp, 8)
    
    
def getChunkIndex(enc_indx, c):
    # try to discover value of n
    n = ord(enc_indx) + 10 - 97
    if ((35 + ord(c)) % 36 == n):
        return 35
    if n < 10:
        n = ord(enc_indx) - 48
    n = (n - ord(c)) % 36
    return n
    
# run with this:
# cat uniq-hostnames.txt | py -2 decode_dga.py  > decoded_uniq_hostnames
for line in sys.stdin:
	data = line.rstrip().split(".")[0]
    #there is a min length of 20 for DGA-generated domain strings (excluding the appended .appsync-api.....)
    #use this requirement to filter out those that are unlikely to be DGA-generated strings from the input file
	if len(data) < 20:
		continue
	encoded_guid = data[:15]
	encoded_chunk_index = data[15]
	encoded_domain = data[16:]
	chunk_index = getChunkIndex(encoded_chunk_index,encoded_guid[0])
	try:
		domain = ""
        # the idea: if chunk_index == 0, it means that the domain name is fragmented
        # and this is the first piece of the fragments. 
        # then the length of the DGA string must be 32 bytes (anything less won't have caused fragmentation)
        # if chunk_index == 0 but total length of DGA string != 32, 
        # means can try doing the other type of decoding (the one with timestamp XOR)
        
		if ((chunk_index == 0 and len(data) != 32) or (chunk_index != 35)) and (len(data) == 20 or len(data) == 23):
			guid = getVictimGUID_fromDGA_type2(data)
			print line.rstrip()
			print "Victim GUID    = {}".format(guid)
		else:
			guid = getVictimGUID_fromDGA_type1(encoded_guid)            
			if  encoded_domain[0] == "0" and encoded_domain[1] == "0":
				encoded_domain = encoded_domain[2:]
				domain = ''.join([chr(i) for i in reverse_Base64Encode(encoded_domain, len(encoded_domain))]).rstrip(b"\x00\x0a\x0d")
			else:
				domain = reverse_Base64Decode(encoded_domain)
			print line.rstrip()
			print "Victim GUID    = {}".format(guid)
			print "Chunk Index    = {}".format(chunk_index)
			print "Victim Domain  = {}".format(domain)
            
	except:
		pass
	print "------"
    
