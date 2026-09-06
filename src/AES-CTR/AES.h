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

/* Доступ к байту j слова word.
   Байты хранятся в big-endian порядке AES: j=0 — старший байт (MSB), j=3 — младший (LSB).
   На little-endian машинах (x86) индекс инвертируется через (3-j). */
#define BYTE(word, j) (((uint8_t*)&(word))[3-(j)])

extern const uint8_t sbox[256];
extern const uint8_t rsbox[256];
extern const uint8_t rcon[11];


/* трансформации при шифровании, которые обрабатывают state, используя нелинейную таблицу замещения sbox */
uint32_t* SubBytes(uint32_t* state);

/* трансформация при расшифровании, которая является обратной по отношению к SubBytes() */
uint32_t* InvSubBytes(uint32_t* state);

/* трансформации при шифровании, которые обрабатывают state, циклически смещая последние три строки на разные величины */
uint32_t* ShiftRows(uint32_t* state);

/* трансформация при расшифровании, которая является обратной по отношению к ShiftRows() */
uint32_t* InvShiftRows(uint32_t* state);

/* трансформация при шифровании, которая берёт все столбцы State и смешивает их данные (независимо друг от друга), чтобы получить новые столбцы */
uint32_t* MixColumns(uint32_t* state);

/* трансформация при шифровании и обратном шифровании, при которой Round Key XOR'ится c state */
uint32_t* AddRoundKey(uint32_t* state, uint32_t* round_keys, uint8_t round);

/* функция генерации раундовых ключей */
uint32_t* KeyExpansion(uint32_t* key);

/* функция, использующаяся в KeyExpansion, которая берёт 4-байтовое слово и производит над ним циклическую перестановку */
void RotWord(uint32_t* word);

/* используется в процедуре Key Expansion, вход: 4 байтовое слово, применяется sbox к каждому из 4 байтов, выход выходное слово */
void SubWord(uint32_t* word, uint32_t* word_out);

/* XOR слов */
void XorWords(uint32_t* word1, uint32_t* word2, uint32_t* word_out);

/* шифрование state */
uint32_t* Cipher(uint32_t* state, uint32_t* round_keys);

/* расшифрование state */
uint32_t* InvCipher(uint32_t* state, uint32_t* round_keys);

/* трансформация при расшифровании, обратная к MixColumns */
uint32_t* InvMixColumns(uint32_t* state);

uint32_t* AllocWords(unsigned count);

void FreeWords(uint32_t* array);

uint32_t* KeyToMatrix(uint8_t key[KEY_LEN]);

#endif

