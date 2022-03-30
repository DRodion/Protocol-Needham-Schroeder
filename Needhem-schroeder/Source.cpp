#include <iostream>
#include <string> 
#include <cmath>
#include <tuple>
#include <vector>
#include <typeinfo>

#include "../cryptopp860/cryptlib.h"
#include "../cryptopp860/modes.h"
#include "../cryptopp860/filters.h"
#include "../cryptopp860/osrng.h" // PNG AutoSeededRandomPool
#include "../cryptopp860/integer.h"
#include "../cryptopp860/nbtheory.h"
#include "../cryptopp860/hex.h"
#include "../cryptopp860/algebra.h"
#include "../cryptopp860/secblock.h"
#include "../cryptopp860/aes.h"
#include "../cryptopp860/files.h"
#include "../cryptopp860/config_int.h"
#include "../cryptopp860/des.h" // DES algorithm


using namespace CryptoPP;
using namespace std;


string Encrypt(string plain, string strkey) {

    byte key[AES::MAX_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    byte iv[16];

    for (int i = 0; i < AES::BLOCKSIZE; i++)
        iv[i] = 0;

    for (int i = 0; i < AES::MAX_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;
    string ciphertextEncode, ciphertext;
    cout << "\nplain text :" << plain << endl ;
    cout << "\n key to encrypt: " << key << endl;
    ciphertextEncode.clear();
    ciphertext.clear();
    CryptoPP::AES::Encryption aesEncryption(key, AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*> (plain.c_str()), plain.length() + 1);
    stfEncryptor.MessageEnd();
    cout << "\n encrypted text: " << ciphertext << endl;
    StringSource ss(ciphertext, true, new HexEncoder(new StringSink(ciphertextEncode)));
    cout << "\n encoded encrypted text: " << ciphertextEncode << endl;
    return ciphertextEncode;
}

string Decrypt(string cipher, string strkey) {

    byte key[AES::MAX_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    byte iv[16];

    for (int i = 0; i < AES::BLOCKSIZE; i++)
        iv[i] = 0;

    for (int i = 0; i < AES::MAX_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;
    string ciphertextDecode, decryptedtext;
    cout << "\n cipher text : " << cipher << endl;
    cout << "\n key to decrypt: " << key << endl;
    ciphertextDecode.clear();
    decryptedtext.clear();

    StringSource ss(cipher, true, new HexDecoder(new StringSink(ciphertextDecode)));
    cout << "\n cipher decoded: " << ciphertextDecode << endl;
    CryptoPP::AES::Decryption aesDecryption(key, AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*> (ciphertextDecode.c_str()), ciphertextDecode.size());
    stfDecryptor.MessageEnd();

    cout << "\n decrypted text: " << decryptedtext << endl;
    return decryptedtext;
}




int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    string plain = "C469BEA09DFCAC0A555E74175F1A614F471A5205FEB13A72C2DFFE8C4B52AA4";
    string strkey = "1234";

    string encode;

    encode = Encrypt(plain, strkey);

    Decrypt(encode, strkey);


   
    system("pause");
    return 0;
}