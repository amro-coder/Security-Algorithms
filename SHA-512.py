################################################# AES128 code #################################################
# Aes prerequisites
import time

Rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

multiplication_matrix=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
# AES encryption code
def convert_from_int_to_2Dmatrix(integer_value):
    ans=[[0,0,0,0] for _ in range(4)]
    for i in range(16):
        byte = integer_value & (255 << (8 * (15-i)))
        byte >>= 8 * (15-i)
        ans[i%4][i//4]=byte
    return ans

def convert_state_to_hex(state):
    ans=""
    for j in range(4):
        for i in range(4):
            temp=hex(state[i][j])[2:]
            ans+=(temp if len(temp)==2 else "0"+temp)
    return ans

def binary_mul(byte1,byte2):
    if byte1==3:
        return byte2^((byte2<<1)&255)^(0x1b if byte2&128 else 0)
    if byte1==2:
        return ((byte2<<1)&255)^(0x1b if byte2&128 else 0)
    return byte2

def substitute_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j]=Sbox[state[i][j]]
    return state

def shift_rows(state):
    for i in range(4):
        state[i]=state[i][i:]+state[i][:i]
    return state

def mix_column(state):
    ans = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                ans[i][j] ^= binary_mul(multiplication_matrix[i][k],state[k][j])
    return ans

def add_round_key(state,key):
    for i in range (4):
        for j in range(4):
            state[i][j] ^= key[i][j]
    return state

def g_function(word,round_number):
    word=word[1:]+word[:1]
    word=[Sbox[i] for i in word]
    word[0]^=Rcon[round_number]
    return word

def expand_key(key,round_number):
    prev_word=g_function([key[i][3] for i in range(4)],round_number)
    for j in range(4):
        for i in range(4):
            key[i][j] ^= prev_word[i]
        prev_word=[key[i][j] for i in range(4)]
    return key

def AES(plain_text,key):
    # state and key are 4*4 2D matrices of bytes
    state = convert_from_int_to_2Dmatrix(plain_text)
    key = convert_from_int_to_2Dmatrix(key)
    state = add_round_key(state,key)
    for round_number in range(10):
        state =substitute_bytes(state)
        state =shift_rows(state)
        if round_number!=9:# Notice: no mix_column operation in the last round
            state = mix_column(state)
        key = expand_key(key ,round_number)
        state = add_round_key(state,key)
    return convert_state_to_hex(state)

################################################# SHA2 512 code #################################################

# I am using ascii encoding so no special characters can be used. Only the alphabet and numbers.

round_keys=['428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
            '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
            'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
            '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
            'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
            '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
            '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
            'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
            '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
            '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
            'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
            'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
            '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
            '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
            '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
            '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
            'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
            '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
            '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
            '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817']

Initial_value="6A09E667F3BCC908BB67AE8584CAA73B3C6EF372FE94F82BA54FF53A5F1D36F1510E527FADE682D19B05688C2B3E6C1F1F83D9ABFB41BD6B5BE0CD19137E2179"

def convert_eightBytes_to_int(eightBytes):
    ans=0
    for i in range(8):
        ans+=eightBytes[7-i]<<(i*8)
    return ans

def convert_eightWords_to_int(eightWords):
    ans=0
    for i in range(8):
        ans+=eightWords[7-i]<<(i*64)
    return ans

def rotate_right(word,n):
    breaker=(1<<n)-1
    right_part=word&breaker
    left_part=word>>n
    ans=left_part+(right_part<<(64-n))
    return ans

def sigma_0_512(word):
    return rotate_right(word,1)^rotate_right(word,8)^(word>>7)

def sigma_1_512(word):
    return rotate_right(word,19)^rotate_right(word,61)^(word>>6)

def summation_0_512(word):
    return rotate_right(word,28)^rotate_right(word,34)^rotate_right(word,39)

def summation_1_512(word):
    return rotate_right(word,14)^rotate_right(word,18)^rotate_right(word,41)

def Maj(a,b,c):
    return (a&b)^(a&c)^(b&c)

def Ch(e,f,g):
    return (e&f)^((e^((1<<64)-1))&g)
    # return (e&f)^((~e)&g)

def modulo_2_to_64(x):
    return x&((1<<64)-1)

def pad_text(plain_text_in_bytes):
    size_of_block_in_bytes=128#1024//8
    target_remainder_bytes=112# last 16 blocks are for length of the message
    remainder_in_bytes=len(plain_text_in_bytes)%size_of_block_in_bytes
    if remainder_in_bytes==target_remainder_bytes:
        number_of_bytes_to_pad=size_of_block_in_bytes
    elif remainder_in_bytes<target_remainder_bytes:
        number_of_bytes_to_pad=target_remainder_bytes-remainder_in_bytes
    else:
        number_of_bytes_to_pad=(size_of_block_in_bytes-remainder_in_bytes)+target_remainder_bytes
    padded_plain_text_in_bytes=plain_text_in_bytes+(bytes([128]+[0]*(number_of_bytes_to_pad-1)))
    return padded_plain_text_in_bytes

def get_length(plain_text_in_bytes):
    size_of_plain_text_length_in_bytes=16 # 128//8
    length_in_bits=len(plain_text_in_bytes)*8
    length_in_list_of_bytes=[]
    for i in range(size_of_plain_text_length_in_bytes):
        current_byte=255&length_in_bits>>(i*8)
        length_in_list_of_bytes.append(current_byte)
    length_in_list_of_bytes.reverse()
    return bytes(length_in_list_of_bytes)

def round(previous_a,previous_b,previous_c,previous_d,previous_e,previous_f,previous_g,previous_h,current_word,current_key):
    T1=modulo_2_to_64(Ch(previous_e,previous_f,previous_g)+previous_h+summation_1_512(previous_e)+current_word+current_key)
    T2=modulo_2_to_64(Maj(previous_a,previous_b,previous_c)+summation_0_512(previous_a))
    h=previous_g
    g=previous_f
    f=previous_e
    e=modulo_2_to_64(T1+previous_d)
    d=previous_c
    c=previous_b
    b=previous_a
    a=modulo_2_to_64(T1+T2)
    return [a,b,c,d,e,f,g,h]

def f(current_block,prev_hash):
    # getting the a,b,c,d,e,f,g,h
    words_of_hash=[]
    for i in range(8):
        words_of_hash.append((prev_hash>>(64*i)) & ((1<<64)-1))
    words_of_hash.reverse()
    a,b,c,d,e,f,g,h=words_of_hash

    # getting the k0,k1....k79
    keys = []
    for i in range(80):
        keys.append(int(round_keys[i], 16))

    # getting the w0,w1... w79
    words = []
    for i in range(16):
        words.append(convert_eightBytes_to_int(current_block[i * 8:i * 8 + 8]))
    for i in range(16, 80):
        current_word = modulo_2_to_64(sigma_1_512(words[i - 2]) + words[i - 7] + sigma_0_512(words[i - 15]) + words[i - 16])
        words.append(current_word)

    # preforming the rounds
    for i in range(80):
        a, b, c, d, e, f, g, h = round(a, b, c, d, e, f, g, h, words[i],keys[i])

    the_8_letters=[a, b, c, d, e, f, g, h]
    a, b, c, d, e, f, g, h=[modulo_2_to_64(the_8_letters[i]+words_of_hash[i]) for i in range(8)]

    return convert_eightWords_to_int([a, b, c, d, e, f, g, h])

def SHA2_512(plain_text):
    hash = int(Initial_value,16)
    number_of_blocks_in_the_message = len(plain_text) // 128
    for i in range(number_of_blocks_in_the_message):
        current_block = plain_text[i * 128:i * 128 + 128]
        hash = f(current_block, hash) # outputs an integer
    return hash

plain_text=input("Enter the plain text you want to hash\n").strip()
str=plain_text
plain_text=plain_text.encode()
length=get_length(plain_text)
plain_text=pad_text(plain_text)
plain_text+=length
hash=SHA2_512(plain_text)
print(f"The hash of the plaintext is (using sha2 512):\n{hex(hash)[2:]}\n")
answer=input("Do you want to encrypt the hash using AES128? (y = Yes, n = No)\n")
if answer[0].lower()=="y":
    key = int(input("Enter the key (in hex):\n").replace(" ", ""), 16)
    print("\nThe hash is 512 bit and the AES accepts 128 bit as plain text."
          " So I divided the hash to 4 blocks and encrypted each block individually. Each block is 16 byte.\n"
          "The blocks are separated with spaces and are showed from left to right starting with block0.")
    encrypted_hash=[]
    for i in range(4):
        current_block=(hash>>(i*128)) &((1<<128)-1)
        current_encrypted_block=AES(current_block,key)
        encrypted_hash.append(current_encrypted_block)
    encrypted_hash.reverse()
    print("\nThe 4 blocks of the encrypted hash from left to right are:")
    print(*encrypted_hash)
input("\nPress Enter to exit")