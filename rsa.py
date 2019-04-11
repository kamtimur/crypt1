import asn1tools
import hashlib


exp = int("C7A5F75C51CF2A716DA054332286215", 16);

secret = int("1CC0B27F41D50F6FC35DEA2AB420DEBD", 16);

module = int("2378343E4BDCC3AB1B98F47997E72B77", 16);
rsa_sign_file = asn1tools.compile_files('rsa_sign_file.asn')


def GenerateSign():
    signeble_file = open("otvety.txt", "r", encoding="utf-8")
    sing_file = open("sign.dat", 'wb')
    readFile = signeble_file.read()
    sha1Hash = hashlib.sha1(readFile.encode('utf-8'))
    hash_int = int(sha1Hash.hexdigest(), 16)
    enc_hash_int = pow(hash_int, secret, module)

    sign = rsa_sign_file.encode('RSASignedFile',{
        'keyset':{
            'key':{
                'algid': b'\x00\x06', 'test': 'testSign',
                'keydata':
                    {
                        'module': int("11317e789c45cccc7436c384d4354945",16),
                        'exp' : 3
                    },
                'param':{},
                'ciphertext':
                    {
                    'c':enc_hash_int
                    }
            }
        },
        'last':{}
    })
    sing_file.write(sign)
    sing_file.close()



def AuthSign():
    source_file = open("otvety.txt", "r", encoding="utf-8")
    readFile = source_file.read()
    sha1Hash = hashlib.sha1(readFile.encode('utf-8'))
    message_hash = int(sha1Hash.hexdigest(), 16) % module

    print(message_hash)



    sign_file = open("sign.dat", 'rb')
    sign_data = sign_file.read()
    sign_str = rsa_sign_file.decode('RSASignedFile', sign_data)
    sign_hash = sign_str['keyset']['key']['ciphertext']['c']
    dec_hash_int = pow(sign_hash, exp, module)

    print(dec_hash_int)
    if dec_hash_int == message_hash:
        print("sign true")


# rsa_enc_file = asn1tools.compile_files('rsa_enc_file.asn')
# rsa_sign_file = asn1tools.compile_files('rsa_enc_file.asn')
GenerateSign()
AuthSign()
# rsa = open("rsa.asn", 'wb')
# encoded = rsa_enc_file.encode('RSAEncodedFile',{
#     'keyset':{
#         'key':{
#             'algid': b'\x00\x01', 'test': 'test',
#             'keydata':
#                 {'module': int("11317e789c45cccc7436c384d4354945",16), 'exp' : 3
#                  },
#             'param':{},
#             'ciphertext': {
#                 'c':int("0a0b0c0a0b0c0a0b0c",16)
#             }
#         }
#     },
#     'last':
#         {'algid':b'\x01\x32','length':1259632
#          }
# })
#
# print(encoded.hex())
# rsa.write(encoded)
# rsa.close()
# rsa = open("rsa.asn", 'rb')
# r = rsa.read()
# print(rsa_enc_file.decode('RSAEncodedFile', r))
#
# f=rsa_enc_file.decode('RSAEncodedFile',r)
# print(f['keyset']['key']['keydata']['module'])

