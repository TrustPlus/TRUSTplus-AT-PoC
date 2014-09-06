import Crypto.Hash.SHA256 as hash, binascii
import struct

#Define Transactions
#Genesis TrustPlus Transaction
version = '01000000'
numInputs = '01'
prevHash = '0000000000000000000000000000000000000000000000000000000000000000'
prevOut_n = '4294967295'
script_sig_in = '00012a0634204a756c79'
sequence = '4294967295'
numOutputs = '01'
value_out = '0000000000000000'
script_sig_out = ''
n_lock_time = '00000000'

tx = version+numInputs+prevHash+prevOut_n+script_sig_in+sequence+numOutputs+value_out+script_sig_out+n_lock_time

#First TrustPlusTransaction
version = '01000000'
#lockTime = 'e6ecb553'
lockTime = hex(1404431590)
lockTime = "".join(map("".join, reversed(zip(*[iter(lockTime)]*2)))).replace('0x','')
numInputs = '01'
prevTransHash = '0000000000000000000000000000000000000000000000000000000000000000'
prevOut_n = 'ffffffff'
script_sig_in = '03510101'
sequence = 'ffffffff'
numOutputs = '01'
#value_out = '002c2fced8380100'
value_out = hex(343978800000000).replace('0x','')
while len(value_out) < 16: value_out = '0'+value_out
value_out = "".join(map("".join, reversed(zip(*[iter(value_out)]*2))))
script_sig_out = '1976a914309e3021aa07143350f97c75a2d82ea79bec892988ac'
n_lock_time = '00000000'

#tx = '01000000e6ecb553010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff01002c2fced83801001976a914309e3021aa07143350f97c75a2d82ea79bec892988ac00000000'
tx = version+lockTime+numInputs+prevTransHash+prevOut_n+script_sig_in+sequence+numOutputs+value_out+script_sig_out+n_lock_time
print tx

print 'Check length of the transaction: ',len(binascii.unhexlify(tx))
# Should output: 92 

#Calculate the initial hash for the Transaction
firstHash = hash.new(binascii.unhexlify(tx)).digest().encode('hex_codec')
print 'Initial hash: ', firstHash
#Chould output: '96bdbd0f5ffb90181ca53abe40c3e04cefd80ce725c23687878522490732daae'

#Calculate the second hash of the Transaction
secondHash = hash.new(hash.new(binascii.unhexlify(tx)).digest()).digest().encode('hex_codec')
print 'Second hash: ', secondHash
#Should output: 'd676a61a5f3807ef351b6df497e10d685698d6f8470cb86a44c43813cc62e57c'

#Reorder bits of the hash.
print 'Reordered Hash:',"".join(map("".join, reversed(zip(*[iter(secondHash)]*2))))
print 'Expected Hash: 7ce562cc1338c4446ab80c47f8d69856680de197f46d1b35ef07385f1aa676d6' 
