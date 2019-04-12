
import asn1tools
import hashlib
import chilkat
import random
from sympy import mod_inverse

deskey = "000102030405060708090A0B0C0D0E0F0001020304050607"

rsa_enc_file = asn1tools.compile_files('schemes/rsa_enc_file.asn')

rsa_sign_file = asn1tools.compile_files('schemes/rsa_sign_file.asn')

rsa_pub_file = asn1tools.compile_files('schemes/rsa_pub.asn')

rsa_priv_file = asn1tools.compile_files('schemes/rsa_priv.asn')


def jacob(a, n):
    g = 1
    s = 1
    if (a == 1):
        return g
    while (a != 0):
        a1 = a
        k = 0
        while (a1 % 2 == 0):
            k += 1
            a1 //= 2
        if (k % 2 == 0):
            s = 1
        elif (n % 8 == 1 or n % 8 == 7):
            s = 1
        elif (n % 8 == 3 or n % 8 == 5):
            s = -1
        if (a1 == 1):
            return (g * s)
        if (n % 4 == 3 and a1 % 4 == 3):
            s = -s
        a = n % a1
        n = a1
        g = g * s
    if (a == 0):
        return 0


def solovey(n, test_count):
    prime = 1
    k = 0
    for i in range(test_count):
        a = (int)(random.uniform(2, n - 2))
        r = pow(a, (n - 1) // 2, n)
        if (r != 1 and r != n - 1):
            return False
        j = jacob(a, n)
        if (r != (j % n)):
            l = j % n
            return False
        if (prime != 0):
            k += 1
    return True


def next_simple_after(num):
    next_num = num + 1
    while not solovey(next_num, 10):
        next_num += 1
    return next_num


def GenPrime(bitlen):
    tmp = random.getrandbits(bitlen)
    while tmp.bit_length() < bitlen:
        tmp = random.getrandbits(bitlen)
    tmp = next_simple_after(tmp)
    while tmp.bit_length() < bitlen:
        tmp = next_simple_after(tmp)
        # print(tmp.bit_length())
    # print(tmp)
    return tmp


def GenRsaKey(exp):
    p = 1
    q = 1
    bitlen = 34
    while p == q:
        p = GenPrime(bitlen)
        q = GenPrime(bitlen)
    module = p * q
    euc = (p - 1) * (q - 1)
    d = mod_inverse(exp, euc)

    pub_key_file = open("pub_key.dat", 'wb')
    encoded = rsa_pub_file.encode('PublicRSAKey', {
        'module': module,
        'exp': exp
    })

    pub_key_file.write(encoded)
    pub_key_file.close()

    priv_key_file = open("priv_key.dat", 'wb')
    encoded = rsa_priv_file.encode('PrivateRSAKey', {
        'modulus': module,
        'publicExponent': exp,
        'privateExponent':d,
        'prime1':p,
        'prime2':q
    })

    priv_key_file.write(encoded)
    priv_key_file.close()
    return "pub_key.dat", "priv_key.dat"



def EncFile(file, pubkey):
    key_file = open(pubkey, 'rb')
    r = key_file.read()
    f = rsa_pub_file.decode('PublicRSAKey', r)
    module = f['module']
    exp = f['exp']
    key_file.close()


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
    crypt.SetEncodedKey(deskey, "hex")  # ключ шифрования

    index = file.rindex('.')  # индекс последней точки
    fileExtension = file[index:len(file)]  # чтения расширения

    # Encrypting file
    in_file = file  # вход. файл
    out_file = file[0:index] + "_enc" + fileExtension  # создание файла для шифра
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

    des = des1[des1.rindex('x') + 1:len(des1)] + des2[des2.rindex('x') + 1:len(des1)]

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
        'file': des
    })

    key_file.write(encoded)
    key_file.close()
    print("File successfully encrypted to " + out_file)
    # print("File successfully encrypted to " + key_file)
    return out_file, file + "_key.dat"


def DecFile(file, key_file, priv_key):

    priv_key_file = open(priv_key, 'rb')
    r = priv_key_file.read()
    f = rsa_priv_file.decode('PrivateRSAKey', r)
    module = f['modulus']
    exp = f['publicExponent']
    secret = f['privateExponent']
    priv_key_file.close()

    # index
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
    fulldes = tdes1 + tdes2
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


def GenerateSign(file, priv_key):

    priv_key_file = open(priv_key, 'rb')
    r = priv_key_file.read()
    f = rsa_priv_file.decode('PrivateRSAKey', r)
    module = f['modulus']
    exp = f['publicExponent']
    secret = f['privateExponent']
    priv_key_file.close()


    signeble_file = open(file, "rb")
    sing_file = open(file + "_sign.dat", 'wb')
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
    return file + "_sign.dat"


def AuthSign(file, sign, pubkey):
    key_file = open(pubkey, 'rb')
    r = key_file.read()
    f = rsa_pub_file.decode('PublicRSAKey', r)
    module = f['module']
    exp = f['exp']
    key_file.close()

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


pub, priv = GenRsaKey(65537)
encfile, keyfile = EncFile("otvety.txt", pub)
DecFile(encfile, keyfile, priv)
sign_file = GenerateSign(encfile, priv)
AuthSign(encfile, sign_file, pub)
