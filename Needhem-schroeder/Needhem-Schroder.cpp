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

const unsigned int SIZE = 16;

//функция генерации простого числа
Integer get_prime(unsigned int bytes) {
    AutoSeededRandomPool prng;
    Integer x;
    do {
        x.Randomize(prng, bytes);
    } while (!IsPrime(x));

    return x;
}

// функция генерация секретных ключей
string generate_k() {
    AutoSeededX917RNG<DES_EDE3> prng;
    string encoded;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);

    prng.GenerateBlock(key, key.size());

    //конвертирование в читаему строку
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encoded)));
 
    return encoded;
}

// функция шифрования, с помощью AES
string aes_encoder(string strkey, string plain) {
    byte iv[AES::BLOCKSIZE];
    for (int i = 0; i < AES::BLOCKSIZE; i++)
        iv[i] = 0;

    byte key[AES::MAX_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    for (int i = 0; i < AES::MAX_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;

    string ciphertextEncode, ciphertext;
    
    ciphertextEncode.clear();
    ciphertext.clear();

    AES::Encryption aesEncryption(key, AES::MAX_KEYLENGTH);
    CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext), StreamTransformationFilter::PKCS_PADDING);
    stfEncryptor.Put(reinterpret_cast<const unsigned char*> (plain.c_str()), plain.length() + 1);
    
    //конвертирование в hex строку
    StringSource ss(ciphertext, true, new HexEncoder(new StringSink(ciphertextEncode)));
   
    return ciphertextEncode;
}

// функция расшифрования, с помощью AES
string aes_decoder(string strkey, string cipher) {
    
    byte iv[AES::BLOCKSIZE];
    for (int i = 0; i < AES::BLOCKSIZE; i++)
        iv[i] = 0;

    byte key[AES::MAX_KEYLENGTH];
    byte* k = (byte*)strkey.c_str();

    for (int i = 0; i < AES::MAX_KEYLENGTH; i++)
        if (i < sizeof(k))
            key[i] = k[i];
        else
            key[i] = 0;

    string ciphertextDecode, decryptedtext;
    
    ciphertextDecode.clear();
    decryptedtext.clear();

    //конвертирование из hex строки
    StringSource ss(cipher, true, new HexDecoder(new StringSink(ciphertextDecode)));
    
    AES::Decryption aesDecryption(key, AES::MAX_KEYLENGTH);
    CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext), StreamTransformationFilter::PKCS_PADDING);
    stfDecryptor.Put(reinterpret_cast<const unsigned char*> (ciphertextDecode.c_str()), ciphertextDecode.size() + 16);
    
    return decryptedtext;
}


// Центр доверия
class Cert_T {
private:
    string K_AT, K_BT, new_k, M1, A_K;
    Integer::Signedness sign = Integer::UNSIGNED;
    string str_A, str_B, str_Na;

public:
    // функция генерации секретного ключа для Alice
    string get_ka() {
        cout << "Cert T: Генерация долговременного секретного ключа K_AT..." << endl;
        K_AT = generate_k();
        cout << "Cert T: Сгенерировано K_AT = " << K_AT << endl;
        return K_AT;
    }

    // функция генерации секретного ключа для Bob
    string get_kb() {
        cout << "Cert T: Генерация долговременного секретного ключа K_BT..." << endl;
        K_BT = generate_k();
        cout << "Cert T: Сгенерировано K_BT = " << K_BT << endl;
        return K_BT;
    }

    // функция возвращающая секретные ключи K_AT и K_BT
    tuple<string, string> get_parametrs() {
        return make_tuple(K_AT, K_BT);
    }

    // функция генерации ключа К и зашифрование сообщения М1
    tuple<string, string> step_2(Integer N_a, Integer ind_A, Integer ind_B) {
        cout << "Cert T: Получено N_a = " << N_a << ", A = "<< ind_A << ", B = " << ind_B << endl;
        cout << "Cert T: Генерация сеансового ключа K..." << endl;
        new_k = generate_k();
        cout << "Cert T: Сгенерирован сеансовый ключ K = " << new_k << endl;


        byte key_a[AES::DEFAULT_KEYLENGTH];
        byte key_b[AES::DEFAULT_KEYLENGTH];
        byte key_Na[AES::DEFAULT_KEYLENGTH];

        // конвертирование Integer в string
        ind_A.Encode(key_a, AES::DEFAULT_KEYLENGTH, sign);
        ind_B.Encode(key_b, AES::DEFAULT_KEYLENGTH, sign);
        N_a.Encode(key_Na, AES::DEFAULT_KEYLENGTH, sign);

        str_A.clear();
        str_B.clear();
        str_Na.clear();
        StringSource(key_a, sizeof(ind_A), true, new HexEncoder(new StringSink(str_A)));
        StringSource(key_b, sizeof(ind_B), true, new HexEncoder(new StringSink(str_B)));
        StringSource(key_Na, sizeof(N_a), true, new HexEncoder(new StringSink(str_Na)));

        // Кодирование K+A на K_BT
        A_K = aes_encoder(K_BT, new_k + str_A);

        cout << "Cert T: N_a = " << str_Na << endl;

        // Кодирование M1
        M1 = aes_encoder(K_AT, str_Na + str_B + new_k + A_K);

        cout << "Cert T: М1 = " << M1 << endl;
        cout << endl;

        return make_tuple(M1, new_k);
    }

};

class Alice {
private:
    Integer N_a, ind_A, ind_B, M3_int, new_N_b;
    string K_AT, KAt, K_BT, M1, M1_des, K, str_Na, M2, str_A, str_B, M3_des, M4, str_new_Nb, str_Na1, M1_Na;
    Integer::Signedness sign = Integer::UNSIGNED;

public:
    // функция получения секретного ключа
    string get_K_at(Cert_T& T) {
        K_AT = T.get_ka();
        cout << "Alice: Получение K_AT = " << K_AT << endl;
        return K_AT;
    }

    // функция генерации Na
    Integer get_Na() {
        cout << "Alice: Генерация случайного одноразового числа Na..." << endl;
        N_a = get_prime(SIZE);
        cout << "Alice: Сгенерировано Na = " << N_a << endl;

        byte key_Na[AES::DEFAULT_KEYLENGTH];
        N_a.Encode(key_Na, AES::DEFAULT_KEYLENGTH, sign);
        StringSource(key_Na, sizeof(N_a), true, new HexEncoder(new StringSink(str_Na)));

        return N_a;
    }

    // функция генерации идентификаторов A и B, отправка сообщения M0 и получение сообщения M1
    string step_1(Cert_T& T, Integer N_a) {
        cout << "Alice: Генерация идентификаторов А и В..." << endl;
        ind_A = get_prime(SIZE);
        ind_B = get_prime(SIZE);
        while (ind_A == ind_B) {
            ind_B = get_prime(SIZE);
        }
        cout << "Alice: Сгенерирован идентификатор A = " << ind_A << endl;
        cout << "Alice: Сгенерирован идентификатор B = " << ind_B << endl;

        byte key_a[AES::DEFAULT_KEYLENGTH];
        byte key_b[AES::DEFAULT_KEYLENGTH];

        ind_A.Encode(key_a, AES::DEFAULT_KEYLENGTH, sign);
        ind_B.Encode(key_b, AES::DEFAULT_KEYLENGTH, sign);

        str_A.clear();
        str_B.clear();
        StringSource(key_a, sizeof(ind_A), true, new HexEncoder(new StringSink(str_A)));
        StringSource(key_b, sizeof(str_B), true, new HexEncoder(new StringSink(str_B)));
        

        // Получение М1
        tie(M1, K) = T.step_2(N_a, ind_A, ind_B);
        cout << "Alice: Получено M1 = " << M1 << endl;
        cout << endl;
        
        return M1;
    }

    // функция расшифрования M1 и зашифрования M2
    string step_3(Cert_T& T) {

        cout << "Alice: Расшифровка M1..." << endl;

        // Расшифрование M1
        M1_des = aes_decoder(K_AT, M1);

        cout << "Alice: Расшифрованное сообщение M1 = " << M1_des << endl;
        cout << endl;

        // негативный пример
        // --------
        N_a = 66666666;
        byte key_nna[AES::DEFAULT_KEYLENGTH];
        N_a.Encode(key_nna, AES::DEFAULT_KEYLENGTH, sign);
        StringSource(key_nna, sizeof(N_a), true, new HexEncoder(new StringSink(str_Na1)));
        cout << "Alice: N_a новый = " << str_Na1 << endl;
        M1_Na = M1_des.substr(0, 96);
        // --------

        
        // Проверка N_a
        //size_t pos = M1_des.find_first_of(str_Na1, 0);
        if (M1_Na == str_Na1) {
            cout << "Alice: Совпалие N_a" << endl;
            cout << "Alice: Кодирование сообщения M2..." << endl;
            tie(KAt, K_BT) = T.get_parametrs();
            cout << "Alice: Ключ Bob K_BT = " << K_BT << endl;
            cout << endl;
            // Кодирование М2
            M2 = aes_encoder(K_BT, K + str_A);
            cout << "Alice: Зашифрованное сообщение M2 = " << M2 << endl;
            cout << endl;
            return M2;
        }
        else {
            cout << "Alice: N_a не совпадают" << endl;
            return "0";
        }
    }

    // функция расшифрования M3 и зашифрования M4
    string step_5(string M3) {
        cout << "Alice: Получение сообщения M3 = " << M3 << endl;
        cout << endl;
        cout << "Alice: Расшифровка сообщения M3" << endl;
        M3_des = aes_decoder(K, M3);
        cout << "Alice: Полученный шифртекст = " << M3_des << endl;
        cout << endl;

        // Конвертирование String в Integer
        string destination;
        StringSource ss(M3_des, true, new HexDecoder(new StringSink(destination)));
        const byte* result = (const byte*)destination.data();
        M3_int.Decode(result, AES::DEFAULT_KEYLENGTH, sign);

        cout << "Alice: Число N_b = " << M3_int << endl;
        new_N_b = M3_int - 1;

        byte key_New_Nb[AES::DEFAULT_KEYLENGTH];
        new_N_b.Encode(key_New_Nb, AES::DEFAULT_KEYLENGTH, sign);
        str_new_Nb.clear();
        StringSource(key_New_Nb, sizeof(new_N_b), true, new HexEncoder(new StringSink(str_new_Nb)));

        // Зашифрование М4
        M4 = aes_encoder(K, str_new_Nb);
        cout << "Alice: Зашифровано сообщение M4 = " << M4 << endl;
        cout << endl;

        return M4;
    }


};

class Bob {
private:
    Integer N_b;
    string K_BT, M2, M2_des, K, M3, str_Nb;
    int size;
    Integer::Signedness sign = Integer::UNSIGNED;

public:
    // функция получения секретного ключа
    string get_K_bt(Cert_T& T) {
        K_BT = T.get_kb();
        cout << "Bob: Получение K_BT = " << K_BT << endl;
        size = K_BT.size();
        return K_BT;
    }

    // функция генерации Nb
    Integer get_Nb() {
        cout << "Bob: Генерация случайного одноразового числа Nb..." << endl;
        N_b = get_prime(SIZE);

        byte key_Nb[AES::DEFAULT_KEYLENGTH];
        N_b.Encode(key_Nb, AES::DEFAULT_KEYLENGTH, sign);
        str_Nb.clear();
        StringSource(key_Nb, sizeof(N_b), true, new HexEncoder(new StringSink(str_Nb)));

        cout << "Bob: Сгенерировано Nb = " << N_b << endl;
        cout << "Bob: Nb = " << str_Nb << endl;
        return N_b;
    }

    // функция получения M2 и его расшифрования и зашифрование сообщения M3 на ключе K
    string step_4(Alice& A, Cert_T& T) {
        M2 = A.step_3(T);
        if (M2 != "0") {
            cout << "Bob: Получение сообщения M2..." << endl;
            cout << "Bob: Получено сообщение M2 = " << M2 << endl;
            cout << endl;
        
            cout << "Bob: Расшифровка M2..." << endl;
            M2_des = aes_decoder(K_BT, M2);

            cout << "Bob: M2 = " << M2_des << endl;
            cout << endl;

            K = M2_des.substr(0, size);

            cout << "Bob: Полученный ключ = " << K << endl;
            cout << "Bob: Шифрование сообщения M3..." << endl;

            M3 = aes_encoder(K, str_Nb);

            cout << "Bob: зашифровано M3 = " << M3 << endl;
            cout << endl;

            return M3;
        }
        else {
            return "0";
        }
        
    }

    // функция получения сообщения M4
    void get_M4(string M4) {
        cout << "Bob: Получено M4 = " << M4 << endl;
        cout << endl;
        cout << "И Alice и Bob получили секретный ключ K." << endl;
    }

};

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    Cert_T T;
    Bob B;
    Alice A;
    string M3, M4_A, M4_B;

    Integer N_a;

    A.get_K_at(T);
    B.get_K_bt(T);

    N_a = A.get_Na();
    B.get_Nb();

    A.step_1(T, N_a);

    M3 = B.step_4(A, T);

    if (M3 != "0") {
        M4_A = A.step_5(M3);
        B.get_M4(M4_A);
    }
    else {
        cout << "Opps, N_a не совпадают" << endl;
    }
    

    system("pause");
    return 0;
}
