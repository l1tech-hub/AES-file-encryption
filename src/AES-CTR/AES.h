#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define AES128 1		             //выбор размера ключа: 128, 192 или 256 бит
//#define AES192 1
//#define AES256 1



#define FILE_EXT_SIZE 16			 //количество символов, которое может содержать расширение шифруемого файла
#define BLOCK_DIM 4					 //размеры одного слова в байтах
#define BLOCK_SIZE 16				 //размеры одного блока (1 блок - 4 слова)

#if defined(AES256) && (AES256 == 1)
	#define KEY_LEN 32
	#define WORDS_NUM 8
	#define ROUNDS_NUM 14
	#define EXP_WORDS_NUM 60
#elif defined(AES192) && (AES192 == 1)
	#define KEY_LEN 24		
	#define WORDS_NUM 6
	#define ROUNDS_NUM 12
	#define EXP_WORDS_NUM 52
#else
	#define KEY_LEN 16			// Длина ключа в байтах.
	#define WORDS_NUM 4         // Количество 4-байтных слов в ключе.
	#define ROUNDS_NUM 10       // Количество раундов в AES шифровании.
	#define EXP_WORDS_NUM 44    // Количество 4-байтных слов в расширенном ключе.
#endif


extern const uint8_t sbox[256];
extern const uint8_t rsbox[256];
extern const uint8_t rcon[11];





/* трансформации при шифровании, которые обрабатывают state, используя нелинейную таблицу замещения sbox */
uint8_t** SubBytes(uint8_t** state);

/* трансформация при расшифровании, которая является обратной по отношению к SubBytes() */
uint8_t** InvSubBytes(uint8_t** state);

/* трансформации при шифровании, которые обрабатывают state, циклически смещая последние три строки на разные величины */
uint8_t** ShiftRows(uint8_t** state);

/* трансформация при расшифровании, которая является обратной по отношению к ShiftRows() */
uint8_t** InvShiftRows(uint8_t** state);

/* трансформация при шифровании, которая берёт все столбцы State и смешивает их данные (независимо друг от друга), чтобы получить новые столбцы */
uint8_t** MixColumns(uint8_t** state);

/* трансформация при шифровании и обратном шифровании, при которой Round Key XOR’ится c state */
uint8_t** AddRoundKey(uint8_t** state, uint8_t** round_keys, uint8_t round);

/* функция генерации раундовых ключей */
uint8_t** KeyExpansion(uint8_t** key);

/* функция, использующаяся в KeyExpansion, которая берёт 4-байтовое слово и производит над ним циклическую перестановку */
void RotWord(uint8_t* word);

/* используется в процедуре Key Expansion, вход: 4 байтовое слово, применяется sbox к каждому из 4 байтов, выход выходное слово */
void SubWord(uint8_t* word, uint8_t* word_out);

/* XOR слов */
void XorWords(uint8_t* word1, uint8_t* word2, uint8_t* word_out);

/* шифрование state */
uint8_t** Cipher(uint8_t** state, uint8_t** round_keys);

uint8_t** AllocUint8_tArray2(uint x, uint y);

void FreeUint8_tArray2(uint8_t** array, uint y);

uint8_t** KeyToMatrix(uint8_t key[KEY_LEN]);

#endif

