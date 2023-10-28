// Shared ESP decryption from gamesense
// Build Options: Non-CRT / Optimizations: Minumim Code Size, etc
#include <vector>
#include <iostream>
#include <stdint.h>
#include <intrin.h>
#include <bit>

#if defined(__GNUC__)
typedef          long long ll;
typedef unsigned long long ull;
#define __int64 long long
#define __int32 int
#define __int16 short
#define __int8  char
#define MAKELL(num) num ## LL
#define FMT_64 "ll"
#elif defined(_MSC_VER)
typedef          __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num ## i64
#define FMT_64 "I64"
#elif defined (__BORLANDC__)
typedef          __int64 ll;
typedef unsigned __int64 ull;
#define MAKELL(num) num ## i64
#define FMT_64 "L"
#else
#error "unknown compiler"
#endif

// Partially defined types:
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
#define _QWORD uint64
#if !defined(_MSC_VER)
#define _LONGLONG __int128
#endif

typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
//typedef unsigned long ulong;

typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;
typedef ll              int64;
typedef ll              sint64;
typedef ull             uint64;

#ifndef _WINDOWS_
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
#endif
typedef int64 QWORD;
#ifndef __cplusplus
typedef int bool;       // we want to use bool in our C programs
#endif
// Some convenience macros to make partial accesses nicer
// first unsigned macros:
#define LOBYTE(x)   (*((_BYTE*)&(x)))   // low byte
#define LOWORD(x)   (*((_WORD*)&(x)))   // low word
#define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword
#define HIBYTE(x)   (*((_BYTE*)&(x)+1))
#define HIWORD(x)   (*((_WORD*)&(x)+1))
#define HIDWORD(x)  (*((_DWORD*)&(x)+1))
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)
#define BYTE5(x)   BYTEn(x,  5)
#define BYTE6(x)   BYTEn(x,  6)
#define BYTE7(x)   BYTEn(x,  7)
#define BYTE8(x)   BYTEn(x,  8)
#define BYTE9(x)   BYTEn(x,  9)
#define BYTE10(x)  BYTEn(x, 10)
#define BYTE11(x)  BYTEn(x, 11)
#define BYTE12(x)  BYTEn(x, 12)
#define BYTE13(x)  BYTEn(x, 13)
#define BYTE14(x)  BYTEn(x, 14)
#define BYTE15(x)  BYTEn(x, 15)
#define WORD1(x)   WORDn(x,  1)
#define WORD2(x)   WORDn(x,  2)         // third word of the object, unsigned
#define WORD3(x)   WORDn(x,  3)
#define WORD4(x)   WORDn(x,  4)
#define WORD5(x)   WORDn(x,  5)
#define WORD6(x)   WORDn(x,  6)
#define WORD7(x)   WORDn(x,  7)

inline uint8  __ROL1__(uint8  value, int count) { return _rotl8((uint8)value, count); }
inline uint16 __ROL2__(uint16 value, int count) { return _rotl16((uint16)value, count); }
inline uint32 __ROL4__(uint32 value, int count) { return _rotl((uint32)value, count); }
inline uint64 __ROL8__(uint64 value, int count) { return _rotl64((uint64)value, count); }

inline uint8  __ROR1__(uint8  value, int count) { return _rotr8((uint8)value, count); }
inline uint16 __ROR2__(uint16 value, int count) { return _rotr16((uint16)value, count); }
inline uint32 __ROR4__(uint32 value, int count) { return _rotr((uint32)value, count); }
inline uint64 __ROR8__(uint64 value, int count) { return _rotr64((uint64)value, count); }

struct voicedata_t
{
	char pad_0000[8];
	_DWORD client;
	_DWORD audible_mask;
	_QWORD xuid;
	void* voice_data_;
	_DWORD proximity;
	_DWORD format;
	_DWORD sequence_bytes;
	_DWORD section_number;
	_DWORD uncompressed_sample_offset;
};

__forceinline char encrypt_packet(uint8_t* pthis, uint8_t* buffer, unsigned int size)
{
	unsigned __int8 v3; // bl
	unsigned int i; // eax
	unsigned __int8 v6; // dh
	unsigned int j; // esi
	char v8; // dl
	unsigned int v9; // ebx
	int v10; // edi
	unsigned __int8 v11; // ah
	char v12; // dl
	char result; // al
	char v14; // dl
	char v15[256]; // [esp+14h] [ebp-100h]

	v3 = 0;
	for (i = 0; i < 0x100; ++i)
		v15[i] = i;

	v6 = 0;
	for (j = 0; j < 0x100; ++j)
	{
		v8 = v15[j];
		v3 += v8 + pthis[(j & 0xF)];
		v15[j] = v15[v3];
		v15[v3] = v8;
	}

	v9 = 0;
	v10 = 128;
	v11 = 0;
	do
	{
		v12 = v15[++v6];
		v11 += v12;
		result = v15[v11];
		v15[v6] = result;
		v15[v11] = v12;
		--v10;
	} while (v10);
	if (size)
	{
		do
		{
			v14 = v15[++v6];
			v15[v6] = v15[(unsigned __int8)(v14 + v11)];
			v15[(unsigned __int8)(v14 + v11)] = v14;
			result = v15[(unsigned __int8)(v14 + v15[v6])];
			buffer[v9++] ^= result;
			v11 += v14;
		} while (v9 < size);
	}
	return result;
}

// Program Entry
bool __fastcall main(voicedata_t* msg, uint32_t xuid_low)
{
	_DWORD* v1; // edi
	int v3; // eax
	int v4; // ecx
	int v5; // eax
	int i; // eax
	int v7; // ecx
	int v8; // ecx
	unsigned int v9; // edi
	int v10; // ecx
	__int16 v11; // bx
	unsigned int v12; // eax
	int v13; // edx
	int v14; // esi
	__int16 v15; // bx
	int v16; // eax
	__int16 v17; // dx
	int v18; // edx
	int v19; // eax
	int v20; // edi
	unsigned int v23; // esi
	__int16 signature; // eax^2
	int v25; // xmm3_4
	unsigned int v26; // edx
	int v27; // ebx
	int v28; // ecx
	unsigned int v29; // eax
	int v30; // xmm2_4
	signed int v31; // ecx
	unsigned int v32; // eax
	int v33; // xmm0_4
	unsigned int v34; // edx
	int v35; // ebx
	int v36; // ecx
	unsigned int v37; // eax
	float v38; // xmm0_4
	unsigned int v39; // ebx
	unsigned int v40; // esi
	_DWORD* v41; // ebx
	float* v42; // edi
	float v43; // xmm1_4
	float v44; // xmm0_4
	int v45; // eax
	int v46; // eax
	int v49[3]; // [esp+164h] [ebp-40h] BYREF
	int v50; // [esp+170h] [ebp-34h]
	int v51; // [esp+174h] [ebp-30h]
	unsigned int v52; // [esp+178h] [ebp-2Ch]
	int v53; // [esp+17Ch] [ebp-28h]
	unsigned int who_shared; // [esp+180h] [ebp-24h]
	unsigned int shared_buffer[5]; // [esp+184h] [ebp-20h]
	unsigned int v56 = 0; // [esp+198h] [ebp-Ch]
	int v57; // [esp+19Ch] [ebp-8h]
	int v58; // [esp+1A0h] [ebp-4h]

	unsigned char rawData[16] = {
		0x68, 0x33, 0x05, 0x97, 0x36, 0x06, 0xD4, 0xEA, 0x4F, 0xC4, 0xA4, 0x3E,
		0x85, 0xB2, 0xAC, 0x0F
	};

	(*(_QWORD*)&shared_buffer) = msg->xuid;
	shared_buffer[2] = msg->section_number;
	shared_buffer[3] = msg->sequence_bytes;
	shared_buffer[4] = msg->uncompressed_sample_offset;

	encrypt_packet(rawData, (uint8_t*)&shared_buffer[0], 20);

	v9 = 0;
	v57 = 0;
	do
	{
		v10 = HIWORD(shared_buffer[v9 / 2]);
		v50 = LOWORD(shared_buffer[v9 / 2 + 1]);
		v11 = v50;
		v51 = v10;
		v12 = 0x91D58E85;
		v13 = (short)v10;
		v14 = 15;
		do
		{
			v15 = v11 - v12;
			v16 = __ROL4__(v12, 1);
			v11 = v13 ^ __ROR2__(v15, v13 & 0xF);
			v17 = v13 - v16;
			v12 = __ROL4__(v16, 1);
			v13 = (unsigned __int16)(v11 ^ __ROR2__(v17, v11 & 0xF));
			--v14;
		} while (v14);
		v52 = v12;
		LOWORD(shared_buffer[v9 / 2 + 1]) = v56 ^ (v11 - v12);
		v18 = v57 ^ (v13 - __ROL4__(v12, 1));
		v19 = (unsigned __int16)v51;
		HIWORD(shared_buffer[v9 / 2]) = v18;
		v9 += 2;
		v57 = v19;
		v56 = (unsigned __int16)v50;
	} while (v9 < 9);

	int buffer_hash = shared_buffer[0];
	buffer_hash ^= xuid_low;
	buffer_hash = buffer_hash >> 0x10;
	buffer_hash = (unsigned short)buffer_hash;

	return buffer_hash == 0x2424; // '$$'
}
