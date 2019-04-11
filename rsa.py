from typing import BinaryIO

import asn1tools
import hashlib
import chilkat

deskey = "000102030405060708090A0B0C0D0E0F0001020304050607"

exp = int("C7A5F75C51CF2A716DA054332286215", 16);

secret = int("1CC0B27F41D50F6FC35DEA2AB420DEBD", 16);

module = int("2378343E4BDCC3AB1B98F47997E72B77", 16);

rsa_enc_file = asn1tools.compile_files('schemes/rsa_enc_file.asn')

rsa_sign_file = asn1tools.compile_files('schemes/rsa_sign_file.asn')

def EncFile(file):

    crypt = chilkat.CkCrypt2()

    success = crypt.UnlockComponent("Anything for 30-day trial")

    if success != True:
        print(crypt.lastErrorText())
        return

    crypt.put_CryptAlgorithm("3des")  # выбор алгоритма
    crypt.put_CipherMode("ecb") # выбор режима простой замены
    crypt.put_KeyLength(192) # длина ключа
    crypt.put_PaddingScheme(0);
    crypt.put_EncodingMode("hex")  # вывод в hex
    crypt.SetEncodedKey(deskey, "hex") #ключ шифрования

    index = file.rindex('.') # индекс последней точки
    fileExtension = file[index:len(file)] # чтения расширения

    # Encrypting file
    in_file = file #вход. файл
    out_file = file[0:index] + "_enc" + fileExtension #создание файла для шифра
    success = crypt.CkEncryptFile(in_file, out_file)  # шифрование файла 3des

    if not success:
        print(crypt.lastErrorText())
        return

    # Encrypting 3DES key with RSA
    encrypted_des_key1 = int(deskey[0:24], 16)

    encrypted_des_key2 = int(deskey[24:48], 16)

    encrypted_des_key1 = pow(encrypted_des_key1, exp, module)
    encrypted_des_key2 = pow(encrypted_des_key2, exp, module)
    des1 = str(hex(encrypted_des_key1))

    des2 = str(hex(encrypted_des_key2))

    des = des1[des1.rindex('x')+1:len(des1)]+des2[des2.rindex('x')+1:len(des1)]

    key_file = open(file + "_key.dat", 'wb')
    encoded = rsa_enc_file.encode('RSAEncodedFile', {
        'keyset': {
            'key': {
                'algid': b'\x00\x01', 'test': 'test',
                'keydata':
                    {'module': module, 'exp': exp
                     },
                'param': {},
                'ciphertext': {
                    'c': int(des, 16)
                }
            }
        },
        'last':
            {'algid': b'\x01\x32', 'length': des.__len__()
             },
        'file' : des
    })

    key_file.write(encoded)
    key_file.close()
    print("File successfully encrypted to " + out_file)
    # print("File successfully encrypted to " + key_file)
    return out_file, file + "_key.dat"

def DecFile(file, key_file):
    # Read file with encrypted 3DES key

    #index
    key_file = open(key_file, 'rb')
    r = key_file.read()
    f = rsa_enc_file.decode('RSAEncodedFile', r)
    key_des = f['keyset']['key']['ciphertext']['c']
    key_file.close()

    des1 = str(hex(key_des))
    des = des1[des1.rindex('x') + 1:len(des1)]

    des1 = int(des[0:32], 16)
    des2 = int(des[32:64], 16)

    tdes1 = pow(des1, secret, module)
    tdes2 = pow(des2, secret, module)

    tdes1 = str(hex(tdes1))
    tdes1 = tdes1[tdes1.rindex('x') + 1:len(tdes1)]
    tdes2 = str(hex(tdes2))
    tdes2 = tdes2[tdes2.rindex('x') + 1:len(tdes2)]

    while (len(tdes1) < 24):
        tdes1 = "0" + tdes1

    while (len(tdes2) < 24):
        tdes2 = "0" + tdes2
    fulldes = tdes1+tdes2
    crypt = chilkat.CkCrypt2()

    success = crypt.UnlockComponent("Anything for 30-day trial")

    if success != True:
        print(crypt.lastErrorText())
        return

    crypt.put_CryptAlgorithm("3des")  # выбор алгоритма
    crypt.put_CipherMode("ecb")  # выбор режима простой замены
    crypt.put_KeyLength(192)  # длина ключа
    crypt.put_PaddingScheme(0);
    crypt.put_EncodingMode("hex")  # вывод в hex
    crypt.SetEncodedKey(fulldes, "hex")  # ключ шифрования

    index = file.rindex('.')  # индекс последней точки
    file_extension = file[index:len(file)]  # чтения расширения

    out_file = file[0:index] + "_dec" + file_extension  # создание файла для шифра

    success = crypt.CkDecryptFile(file, out_file)  # шифрование файла 3des

    if success != True:
        print(crypt.lastErrorText())
        return
    print("File successfully decrypted to " + out_file)
    return out_file

def GenerateSign(file):
    signeble_file = open(file, "rb")
    sing_file = open(file+"_sign.dat", 'wb')
    readFile = signeble_file.read()
    sha1Hash = hashlib.sha1(readFile)
    hash_int = int(sha1Hash.hexdigest(), 16)
    enc_hash_int = pow(hash_int, secret, module)

    sign = rsa_sign_file.encode('RSASignedFile', dict(keyset={
        'key': dict
        (
            algid=b'\x00\x06', test='testSign', keydata=
            {
                'module': module,
                'exp': 3
            }
            , param={},
            ciphertext=dict
                (
                c=enc_hash_int
                )
        )
    }, last={}))
    sing_file.write(sign)
    sing_file.close()
    return file+"_sign.dat"



def AuthSign(file, sign):
    sign_file = open(sign, 'rb')
    sign_data = sign_file.read()
    sign_str = rsa_sign_file.decode('RSASignedFile', sign_data)
    sign_hash = sign_str['keyset']['key']['ciphertext']['c']
    sign_module = sign_str['keyset']['key']['keydata']['module']
    dec_hash_int = pow(sign_hash, exp, sign_module)


    source_file = open(file, "rb")
    readFile = source_file.read()
    sha1Hash = hashlib.sha1(readFile)
    message_hash = int(sha1Hash.hexdigest(), 16) % sign_module

    if dec_hash_int == message_hash:
        print("sign true")
        return True


encfile, keyfile = EncFile("otvety.txt")
DecFile(encfile, keyfile)
sign_file = GenerateSign(encfile)
AuthSign(encfile,sign_file)


