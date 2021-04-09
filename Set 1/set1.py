import math
import base64

from Crypto.Cipher import AES  #pycrypto

character_frequency = {
    "E": 1000*529117365./4374127904,
    "T": 1000*390965105./4374127904,
    "A": 1000*374061888./4374127904,
    "O": 1000*326627740./4374127904,
    "I": 1000*320410057./4374127904,
    "N": 1000*313720540./4374127904,
    "S": 1000*294300210./4374127904,
    "R": 1000*277000841./4374127904,
    "H": 1000*216768975./4374127904,
    "L": 1000*183996130./4374127904,
    "D": 1000*169330528./4374127904,
    "C": 1000*138416451./4374127904,
    "U": 1000*117295780./4374127904,
    "M": 1000*110504544./4374127904,
    "F": 1000*95422055./4374127904,
    "G": 1000*91258980./4374127904,
    "P": 1000*90376747./4374127904,
    "W": 1000*79843664./4374127904,
    "Y": 1000*75294515./4374127904,
    "B": 1000*70195826./4374127904,
    "V": 1000*46337161./4374127904,
    "K": 1000*35373464./4374127904,
    "J": 1000*9613410./4374127904,
    "X": 1000*8369915./4374127904,
    "Z": 1000*4975847./4374127904,
    "Q": 1000*4550166./4374127904,
    " ": 2
}
# every function with a "data" parameter receives it in bytes object format

def plaintext_score(data):
    if not bytes.isascii(data):
        return -99999999
    return sum([math.log2(character_frequency[letter]) for letter in data.decode().upper() if letter in character_frequency.keys()])

def xor_repeating_byte(data, key):
    return bytes((''.join([chr(byte ^ key) for byte in data])), 'utf-8')

def xor_repeating_byte_bruteforce(data):
    candidates = [xor_repeating_byte(data, i) for i in range(256)]
    return [(x, plaintext_score(x)) for x in candidates]

def best_plaintext_score(scores):
    scores_values = [i[1] for i in scores]
    max_i = scores_values.index(max(scores_values))
    return max_i


def xor_repeating_key(data, key):
    return bytes(''.join([chr(data[i] ^ key[i%len(key)])for i in range(len(data))]), 'utf-8')


def hamming_distance(s1,s2):
    xor = int(xor_repeating_key(s1, s2).hex(), 16)
    return sum([ 1 for i in [j for j in range(math.ceil(math.log2(xor+1)))] if (((1<<i) & xor) != 0)])


def hamming_distance_mean(data, keysize, max_blocks = 10):
    blocks = len(data)//keysize
    blocks = blocks if blocks < max_blocks else max_blocks
    mean = 0
    for i in range(blocks - 1):
        mean += hamming_distance(data[keysize*i:keysize*(1+i)],data[keysize*(1+i):keysize*(2+i)])
    return mean/((blocks-1)*keysize)


def guess_keysize(data, max_key_len):
    return sorted([(i, hamming_distance_mean(data, i)) for i in range(1, max_key_len+1)], key= lambda x:x[1])


def break_repeating_key(data, keysize):
    data_blocks = [data[i::keysize] for i in range(keysize)]
    blocks_scores = [xor_repeating_byte_bruteforce(i) for i in data_blocks]
    keys = [chr(best_plaintext_score(i)) for i in blocks_scores]
    return "".join(keys).encode('utf-8')


def detect_ecb(data, keysize=16):
    n_different_chars = []
    for i in data:
        sum = 0
        for j in range(keysize):
            sum += len(set(i[j::keysize]))
        n_different_chars.append(sum)
    return n_different_chars.index(min(n_different_chars))

c3_cipher = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
c3_scores = xor_repeating_byte_bruteforce(c3_cipher)
c3_key = best_plaintext_score(c3_scores)
c3_answer = xor_repeating_byte(c3_cipher, c3_key).decode()


c4_candidates = [ bytes.fromhex(x) for x in open("c4.txt", 'r')]
c4_candidates_scores = [xor_repeating_byte_bruteforce(x) for x in c4_candidates]
c4_candidates_scores_flat = []
for i in c4_candidates_scores:
    c4_candidates_scores_flat += i
c4_position = best_plaintext_score(c4_candidates_scores_flat)
c4_key = c4_position % 256
c4_cipher = c4_candidates[c4_position//256]
c4_answer = xor_repeating_byte(c4_cipher, c4_key).decode()

c5_plaintext = bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'utf-8')
c5_key = "ICE".encode('utf-8')
c5_answer = xor_repeating_key(c5_plaintext, c5_key)

c6_test1 = 'this is a test'.encode('utf-8')
c6_test2 = 'wokka wokka!!!'.encode('utf-8')
c6_cipher_b64 = "".join([i for i in open("c6.txt", 'r')]).replace("\n", '')
c6_cipher = base64.b64decode(c6_cipher_b64)
c6_keysize_guesses = guess_keysize(c6_cipher, 200)
c6_key = break_repeating_key(c6_cipher, c6_keysize_guesses[0][0])
c6_plaintext = xor_repeating_key(c6_cipher, c6_key)
#below are some tests of challenge 6
# for i in range(10):
#     key = c6_keysize_guesses[i][0]
#     print(i)
#     print("keysize: "+str(key))
#     print("distance: "+str(c6_keysize_guesses[i][1]))
#     print(break_repeating_key(c6_cipher, key))
#     print(xor_repeating_key(c6_cipher, break_repeating_key(c6_cipher, key).decode())[:10])
#     print("")

c7_key = bytes("YELLOW SUBMARINE", 'utf-8')
c7_aes = AES.new(c7_key,AES.MODE_ECB)
c7_cipher_b64 = "".join([i for i in open("c7.txt", 'r')]).replace("\n", '')
c7_cipher = base64.b64decode(c7_cipher_b64)
c7_answer = c7_aes.decrypt(c7_cipher)


c8_data = [bytes.fromhex(i) for i in open('c8.txt', 'r')]
c8_answer = c8_data[detect_ecb(c8_data)]
