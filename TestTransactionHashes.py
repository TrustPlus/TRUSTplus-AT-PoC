import Crypto.Hash.SHA256 as hash, binascii
import struct

##IN trustpluscoinj use Utils.bytesToHexString(Bytes) to get hex

#Define Transactions
#Genesis TrustPlus Transaction
#version = '01000000'
#print 'Length of version:',len(version)

#time = hex(1404416230)
#time = "".join(map("".join, reversed(zip(*[iter(time)]*2)))).replace('0x','')
#print 'Length of time:',len(time)

#numInputs = '01'
#print 'Length of numInputs:',len(numInputs)

#prevTransHash = '0000000000000000000000000000000000000000000000000000000000000000'
#print 'Length of prevTransHash:',len(prevTransHash)

#prevOut_n = 'ffffffff'
#print 'Length of prevOut_n:',len(prevOut_n)

#script_sig_in = '0300012a0634204a756c79'
#print 'Length of script_sig_in:',len(script_sig_in)

#sequence = 'ffffffff'
#print 'Length of sequence:',len(sequence)

#numOutputs = '00'
#print 'Length of numOutputs:',len(numOutputs)

#value_out = '0000000000000000'
#print 'Length of value_out:',len(value_out)

#script_sig_out = '19'
#print 'Length of script_sig_out:',len(script_sig_out)

#n_lock_time = '00000000'
#print 'Length of n_lock_time:',len(n_lock_time)

##First TrustPlusTransaction
version = '01000000'
time = hex(1404431590)
time = "".join(map("".join, reversed(zip(*[iter(time)]*2)))).replace('0x','')
numInputs = '01'
prevTransHash = '0000000000000000000000000000000000000000000000000000000000000000'
prevOut_n = 'ffffffff'
script_sig_in = '03510101'
sequence = 'ffffffff'
numOutputs = '01'
value_out = hex(343978800000000).replace('0x','')
while len(value_out) < 16: value_out = '0'+value_out
value_out = "".join(map("".join, reversed(zip(*[iter(value_out)]*2))))
script_sig_out = '1976a914309e3021aa07143350f97c75a2d82ea79bec892988ac'
n_lock_time = '00000000'

#   tx = '01000000e6ecb553010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff01002c2fced83801001976a914309e3021aa07143350f97c75a2d82ea79bec892988ac00000000'

gen_tx = '01000000e6b0b553010000000000000000000000000000000000000000000000000000000000000000ffffffff0a00012a0634204a756c79ffffffff01000000000000000000000000'

magicBytes = "a0a1a3a2"
gen_blk = "00 9c 0000 0001 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 fffa 1c7a a0f6 2a27 ec42 0cf7 03a6 0e93 0c98 851f 3e22 4515 15d6 6bc6 316b 884d b0e6 53b5 ffff 1e0f acaf 0009 0101 0000 e600 b5b0 0153 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 ffff ffff 000a 2a01 3406 4a20 6c75 ff79 ffff 01ff 0000 0000 0000 0000 0000 0000 0000"

#tx = version+time+numInputs+prevTransHash+prevOut_n+script_sig_in+sequence+numOutputs+value_out+script_sig_out+n_lock_time
#tx = "0100000035c0135401c6a1004d7c3f997682cfd34ad18bc8d361eea2c74df44d0e243fb34893f669e80100000049483045022100b311ae30900df45627f34344f080eff2354116bcd26ae02cb8e3f05dfaad9b8702200f3bc402a6ae8b52d4317ac30dfcbe3a34adda1b2a9f0b3fcf274f541ba7116e01ffffffff0300000000000000000080fc45ab0f00000023210295907e786fed1d0d6175ee8acd01b2aec8370e32ee1976aca1e6fb40f2d5b85eac33ca58ab0f00000023210295907e786fed1d0d6175ee8acd01b2aec8370e32ee1976aca1e6fb40f2d5b85eac00000000"

#blk = "060000000fea6a068e1b1e272281e073e7553d2422912e6e53d4a7988499cd7645ede5a45e83a1f4a74c5a98b96524e308d5a2e985b8ed260d096a907d69cba65a1e2c8b35c01354c040131d00000000020100000035c01354010000000000000000000000000000000000000000000000000000000000000000ffffffff0403259202ffffffff01000000000000000000000000000100000035c0135401c6a1004d7c3f997682cfd34ad18bc8d361eea2c74df44d0e243fb34893f669e80100000049483045022100b311ae30900df45627f34344f080eff2354116bcd26ae02cb8e3f05dfaad9b8702200f3bc402a6ae8b52d4317ac30dfcbe3a34adda1b2a9f0b3fcf274f541ba7116e01ffffffff0300000000000000000080fc45ab0f00000023210295907e786fed1d0d6175ee8acd01b2aec8370e32ee1976aca1e6fb40f2d5b85eac33ca58ab0f00000023210295907e786fed1d0d6175ee8acd01b2aec8370e32ee1976aca1e6fb40f2d5b85eac000000004730450221008c1f6256cf4ed675932805b192bcbbccff8a86f6d05ba9c0438228a568b67a10022018cbc1f6c9189efb24c0dabd563cab7c1fb55a8285f9fa09779daa4f63dba35a"

tx = gen_tx
blk = gen_blk

print tx
print blk

print 'Check length of the transaction: ',len(binascii.unhexlify(tx))
# Should output: 92 

#Calculate the initial hash for the Transaction
firstHash = hash.new(binascii.unhexlify(tx)).digest().encode('hex_codec')
print 'Initial hash: ', firstHash
#Should output: '96bdbd0f5ffb90181ca53abe40c3e04cefd80ce725c23687878522490732daae'

#Calculate the second hash of the Transaction
secondHash = hash.new(hash.new(binascii.unhexlify(tx)).digest()).digest().encode('hex_codec')
print 'Second hash: ', secondHash
#Should output: 'd676a61a5f3807ef351b6df497e10d685698d6f8470cb86a44c43813cc62e57c'

#Reorder bits of the hash.
print 'Reordered Hash:',"".join(map("".join, reversed(zip(*[iter(secondHash)]*2))))
#print 'Expected Hash: 7ce562cc1338c4446ab80c47f8d69856680de197f46d1b35ef07385f1aa676d6' 
#For Genesis Block:
print 'Expected Hash: 884d316b6bc615d645153e22851f0c980e9303a60cf7ec422a27a0f61c7afffa' 
