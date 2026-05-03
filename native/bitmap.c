/*
 * Copyright 2017-2019  Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Parts of this file are adopted from American Fuzzy Lop by Michal Zalewski
 * - Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved.
 * - Released under terms and conditions of Apache License, Version 2.0.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

static const uint8_t bucket_lut[256] = { // bitmap의 값을 8단계로 bucket화
  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128
};

static void con() __attribute__((constructor));
void init() {

}

/**
 * @brief Checks if two bitmaps differ.
 * @param bitmap The bucket bitmap.
 * A zero bit indicates that the specific bucket of the given byte is free.
 * @param new_bitmap A bitmap from a recent run.
 * Each byte value of this map is assigned to one of 9 buckets.
 * @param bitmap_size The length of both bitmaps.
 * @return true if the maps differ after "bucketing".
 */
uint64_t are_new_bits_present_do_apply_lut(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  uint64_t bit_count = 0;
  uint64_t byte_count = 0;
  for (uint64_t i = 0; i < bitmap_size; i++) {
		uint8_t a = bucket_lut[new_bitmap[i]];
		new_bitmap[i] = a; //THIS ONE is not availble below at no_apply_lut
		if( (a | bitmap[i]) != bitmap[i] )  {   // 뭔가 새롭게 실행된 것임
			if (bitmap[i]==0){  // 이 위치에 아무것도 기록된 적 없음. 즉, 처음으로 커버된 새로운 branch
				byte_count++;     // 새로운 branch → byte_count 증가
			} else {            // 이미 발견됐었던 경로이지만, 새로운 빈도 등급(bucket_lut)으로 실행됨 == 커버리지가 깊어짐
				bit_count++;      // 미세한 변화 → bit_count 증가
			}
		}
	}
  // 상위 32비트는 byte_count, 하위 32비트는 bit_count로 구성된 uint64_t 반환
  return (uint64_t)((byte_count << 32) + (bit_count));
}

uint64_t are_new_bits_present_no_apply_lut(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  uint64_t bit_count = 0;
  uint64_t byte_count = 0;

  for (uint64_t i = 0; i < bitmap_size; i++) {
		uint8_t a = new_bitmap[i];
		if( (a | bitmap[i]) != bitmap[i] )  {
			if (bitmap[i]==0){
				byte_count++;
			} else {
				bit_count++;
			}
		}
  }
  return (uint64_t)((byte_count << 32) + (bit_count));
}

void update_global_bitmap(uint8_t* bitmap, uint8_t* new_bitmap, uint64_t bitmap_size) {
  for (uint64_t i = 0; i < bitmap_size; i++) {
        bitmap[i] |= new_bitmap[i];
  }
}

void apply_bucket_lut(uint8_t * bitmap, uint64_t bitmap_size) {
  for (uint64_t i = 0; i < bitmap_size; i++) {
		bitmap[i] = bucket_lut[bitmap[i]];
  }
}

/* Adopted from American Fuzzy Lop (AFL) by Michal Zalewski */
uint8_t could_be_bitflip(uint32_t xor_val) {

  uint32_t sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}

/* 64비트 버전 추가 */
uint8_t could_be_bitflip_64(uint64_t xor_val) {

  uint64_t sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, 32-, and 64-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xffLL || xor_val == 0xffffLL || 
      xor_val == 0xffffffffLL || xor_val == 0xffffffffffffffffLL)
    return 1;

  return 0;

}

/* Adopted from American Fuzzy Lop (AFL) by Michal Zalewski */
#define SWAP16(_x) ({ \
    uint16_t _ret = (_x); \
    (uint16_t)((_ret << 8) | (_ret >> 8)); \
  })

/* Adopted from American Fuzzy Lop (AFL) by Michal Zalewski */
#define SWAP32(_x) ({ \
    uint32_t _ret = (_x); \
    (uint32_t)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) | \
          ((_ret >> 8) & 0x0000FF00)); \
  })

#if defined(__GNUC__) || defined(__clang__)
#define SWAP64(_x) __builtin_bswap64(_x)
#else
/* Microsoft 컴파일러 또는 기타 */
#define SWAP64(_x) ({ \
    uint64_t _ret = (_x); \
    _ret = ((_ret & 0x00000000FFFFFFFFLL) << 32) | ((_ret & 0xFFFFFFFF00000000LL) >> 32); \
    _ret = ((_ret & 0x0000FFFF0000FFFFLL) << 16) | ((_ret & 0xFFFF0000FFFF0000LL) >> 16); \
    _ret = ((_ret & 0x00FF00FF00FF00FFLL) <<  8) | ((_ret & 0xFF00FF00FF00FF00LL) >>  8); \
    _ret; \
})
#endif


/* Adopted from American Fuzzy Lop (AFL) by Michal Zalewski */
uint8_t could_be_arith(uint32_t old_val, uint32_t new_val, uint8_t blen, uint8_t ARITH_MAX) {

  uint32_t i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {

    uint8_t a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((uint8_t)(ov - nv) <= ARITH_MAX ||
        (uint8_t)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    uint16_t a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((uint32_t)(old_val - new_val) <= ARITH_MAX ||
        (uint32_t)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((uint32_t)(old_val - new_val) <= ARITH_MAX ||
        (uint32_t)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}

/* 64비트 버전 추가 */
uint8_t could_be_arith_64(uint64_t old_val, uint64_t new_val, uint8_t blen, uint8_t ARITH_MAX) {

  uint64_t i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */
  for (i = 0; i < blen; i++) {
    uint8_t a = old_val >> (8 * i),
            b = new_val >> (8 * i);
    if (a != b) { diffs++; ov = a; nv = b; }
  }
  if (diffs == 1) {
    if ((uint8_t)(ov - nv) <= ARITH_MAX ||
        (uint8_t)(nv - ov) <= ARITH_MAX) return 1;
  }
  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */
  diffs = 0;
  for (i = 0; i < blen / 2; i++) {
    uint16_t a = old_val >> (16 * i),
             b = new_val >> (16 * i);
    if (a != b) { diffs++; ov = a; nv = b; }
  }
  if (diffs == 1) {
    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;
    ov = SWAP16(ov); nv = SWAP16(nv);
    if ((uint16_t)(ov - nv) <= ARITH_MAX ||
        (uint16_t)(nv - ov) <= ARITH_MAX) return 1;
  }
  if (blen == 2) return 0;

  /* See if four-byte adjustments to any byte would produce this result. */
  diffs = 0;
  for (i = 0; i < blen / 4; i++) {
    uint32_t a = old_val >> (32 * i),
             b = new_val >> (32 * i);
    if (a != b) { diffs++; ov = a; nv = b; }
  }
  if (diffs == 1) {
    if ((uint32_t)(ov - nv) <= ARITH_MAX ||
        (uint32_t)(nv - ov) <= ARITH_MAX) return 1;
    ov = SWAP32(ov); nv = SWAP32(nv);
    if ((uint32_t)(ov - nv) <= ARITH_MAX ||
        (uint32_t)(nv - ov) <= ARITH_MAX) return 1;
  }
  if (blen == 4) return 0;

  /* Finally, let's do the same thing for qwords. */
  if (blen == 8) {
    if ((uint64_t)(old_val - new_val) <= ARITH_MAX ||
        (uint64_t)(new_val - old_val) <= ARITH_MAX) return 1;
    new_val = SWAP64(new_val);
    old_val = SWAP64(old_val);
    if ((uint64_t)(old_val - new_val) <= ARITH_MAX ||
        (uint64_t)(new_val - old_val) <= ARITH_MAX) return 1;
  }

  return 0;
}

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

#define INTERESTING_64 \
  -9223372036854775808LL, /* 64-bit min (signed) */ \
  -2147483649LL,          /* 32-bit min (signed) - 1 */ \
  2147483648LL,           /* 32-bit max (signed) + 1 */ \
  4294967295LL,           /* 32-bit max (unsigned) */ \
  4294967296LL,           /* 32-bit max (unsigned) + 1 */ \
  9223372036854775807LL   /* 64-bit max (signed) */


static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
static s64 interesting_64[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32, INTERESTING_64 };


/* Adopted from American Fuzzy Lop (AFL) by Michal Zalewski */
uint8_t could_be_interest(uint32_t old_val, uint32_t new_val, uint8_t blen, uint8_t check_le) {

  uint32_t i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      uint32_t tval = (old_val & ~(0xff << (i * 8))) |
                 (((uint8_t)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      uint32_t tval = (old_val & ~(0xffff << (i * 8))) |
                 (((uint16_t)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (uint32_t)interesting_32[j]) return 1;

  }

  return 0;

}

/* 64비트 버전 추가 */
uint8_t could_be_interest_64(uint64_t old_val, uint64_t new_val, uint8_t blen, uint8_t check_le) {

  uint64_t i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */
  for (i = 0; i < blen; i++) {
    for (j = 0; j < sizeof(interesting_8); j++) {
      uint64_t tval = (old_val & ~(0xffLL << (i * 8))) |
                    (((uint8_t)interesting_8[j]) << (i * 8));
      if (new_val == tval) return 1;
    }
  }
  if (blen == 1) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */
  for (i = 0; i < blen - 1; i++) {
    for (j = 0; j < sizeof(interesting_16) / 2; j++) {
      uint64_t tval = (old_val & ~(0xffffLL << (i * 8))) |
                    (((uint16_t)interesting_16[j]) << (i * 8));
      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */
      if (blen > 2) {
        tval = (old_val & ~(0xffffLL << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));
        if (new_val == tval) return 1;
      }
    }
  }
  if (blen == 2) return 0;
  
  /* See if four-byte insertions over old_val could give us new_val. */
  for (i = 0; i < blen - 3; i++) {
      for (j = 0; j < sizeof(interesting_32) / 4; j++) {
          uint64_t tval = (old_val & ~(0xffffffffLL << (i * 8))) |
                         (((uint32_t)interesting_32[j]) << (i * 8));
          if (new_val == tval) return 1;

          if (blen > 4) {
              tval = (old_val & ~(0xffffffffLL << (i * 8))) |
                     (SWAP32(interesting_32[j]) << (i * 8));
              if (new_val == tval) return 1;
          }
      }
  }
  if (blen == 4) return 0;

  /* See if eight-byte insertions could produce the same result (LE only). */
  if (blen == 8 && check_le) {
    for (j = 0; j < sizeof(interesting_64) / 8; j++)
      if (new_val == (uint64_t)interesting_64[j]) return 1;
  }

  return 0;
}