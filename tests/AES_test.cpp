#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "AES.h"
}


// Загружает 16 байт plaintext в uint32_t[4] через BYTE-макрос
static uint32_t* LoadBlock(const uint8_t src[16]) {

    uint32_t* s = AllocWords(BLOCK_DIM);
    for (uint8_t i = 0, j = 0, k = 0; i < 16; i++, k++) {
        if (k > BLOCK_DIM - 1) { k = 0; j++; }
        BYTE(s[j], k) = src[i];
    }
    return s;
}

// Выгружает uint32_t[4] обратно в 16 байт
static void UnloadBlock(const uint32_t* s, uint8_t dst[16]) {
    for (uint8_t i = 0, j = 0, k = 0; i < 16; i++, k++) {
        if (k > BLOCK_DIM - 1) { k = 0; j++; }
        dst[i] = BYTE(s[j], k);
    }
}



class CipherTest : public ::testing::Test {

protected:
    // Ключ, plaintext и ciphertext из NIST FIPS-197 Appendix B
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t expected_ct[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    uint32_t* km  = nullptr;
    uint32_t* rk  = nullptr;

    void SetUp() override {
        km = KeyToMatrix(key);
        rk = KeyExpansion(km);
    }
    void TearDown() override {
        FreeWords(km);
        FreeWords(rk);
    }
};

// Шифрование даёт правильный ciphertext
TEST_F(CipherTest, EncryptMatchesNIST) {
    uint32_t* state = LoadBlock(plaintext);
    state = Cipher(state, rk);

    uint8_t result[16];
    UnloadBlock(state, result);
    FreeWords(state);

    EXPECT_EQ(memcmp(result, expected_ct, 16), 0)
        << "Cipher output does not match NIST FIPS-197 Appendix B";
}

// Расшифрование возвращает исходный plaintext
TEST_F(CipherTest, DecryptMatchesNIST) {
    uint32_t* state = LoadBlock(expected_ct);
    state = InvCipher(state, rk);

    uint8_t result[16];
    UnloadBlock(state, result);
    FreeWords(state);

    EXPECT_EQ(memcmp(result, plaintext, 16), 0)
        << "InvCipher output does not match original plaintext";
}

// Encrypt(Decrypt(ct)) == ct  и  Decrypt(Encrypt(pt)) == pt
TEST_F(CipherTest, EncryptDecryptRoundTrip) {
    // Encrypt -> Decrypt
    uint32_t* s1 = LoadBlock(plaintext);
    s1 = Cipher(s1, rk);
    s1 = InvCipher(s1, rk);
    uint8_t rt1[16];
    UnloadBlock(s1, rt1);
    FreeWords(s1);
    EXPECT_EQ(memcmp(rt1, plaintext, 16), 0) << "Encrypt->Decrypt roundtrip failed";

    // Decrypt -> Encrypt
    uint32_t* s2 = LoadBlock(expected_ct);
    s2 = InvCipher(s2, rk);
    s2 = Cipher(s2, rk);
    uint8_t rt2[16];
    UnloadBlock(s2, rt2);
    FreeWords(s2);
    EXPECT_EQ(memcmp(rt2, expected_ct, 16), 0) << "Decrypt->Encrypt roundtrip failed";
}

// Нулевой plaintext с нулевым ключом не должен давать нулевой ciphertext
// (проверяет что реализация вообще что-то делает с нулями)
TEST_F(CipherTest, ZeroInputNotZeroOutput) {
    uint8_t zero_key[16]  = {};
    uint8_t zero_pt[16]   = {};

    uint32_t* zkm = KeyToMatrix(zero_key);
    uint32_t* zrk = KeyExpansion(zkm);
    uint32_t* s   = LoadBlock(zero_pt);
    s = Cipher(s, zrk);

    uint8_t result[16];
    UnloadBlock(s, result);

    uint8_t zeros[16] = {};
    EXPECT_NE(memcmp(result, zeros, 16), 0)
        << "AES(0,0) should not produce all-zero output";

    FreeWords(s);
    FreeWords(zkm);
    FreeWords(zrk);
}



class KeyExpansionTest : public ::testing::Test {
protected:
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // NIST FIPS-197 Appendix A.1: все 44 слова расширенного ключа
    uint32_t expected_words[44] = {
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,  // round 0
        0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,  // round 1
        0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,  // round 2
        0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,  // round 3
        0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,  // round 4
        0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,  // round 5
        0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,  // round 6
        0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,  // round 7
        0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,  // round 8
        0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,  // round 9
        0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6   // round 10
    };
};

// Первые 4 слова (round key 0) совпадают с оригинальным ключом
TEST_F(KeyExpansionTest, FirstWordsEqualKey) {
    uint32_t* km = KeyToMatrix(key);
    uint32_t* rk = KeyExpansion(km);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(rk[i], expected_words[i])
            << "Round key word[" << i << "] mismatch";
    }

    FreeWords(km);
    FreeWords(rk);
}

// Все 44 слова совпадают с NIST
TEST_F(KeyExpansionTest, AllWordsMatchNIST) {
    uint32_t* km = KeyToMatrix(key);
    uint32_t* rk = KeyExpansion(km);

    for (int i = 0; i < 44; i++) {
        EXPECT_EQ(rk[i], expected_words[i])
            << "Round key word[" << i << "] (round " << i/4 << ", word " << i%4 << ") mismatch";
    }

    FreeWords(km);
    FreeWords(rk);
}

// Разные ключи дают разные расширения
TEST_F(KeyExpansionTest, DifferentKeysProduceDifferentSchedules) {
    uint8_t key2[16] = {
        0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
        0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
    };

    uint32_t* km1 = KeyToMatrix(key);
    uint32_t* rk1 = KeyExpansion(km1);

    uint32_t* km2 = KeyToMatrix(key2);
    uint32_t* rk2 = KeyExpansion(km2);

    // Хотя бы одно слово должно отличаться
    bool any_diff = false;
    for (int i = 0; i < 44; i++) {
        if (rk1[i] != rk2[i]) { any_diff = true; break; }
    }
    EXPECT_TRUE(any_diff) << "Different keys produced identical key schedules";

    FreeWords(km1); FreeWords(rk1);
    FreeWords(km2); FreeWords(rk2);
}

