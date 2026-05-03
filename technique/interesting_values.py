# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style 'interesting values' mutations (deterministic stage).
"""

from kafl_fuzzer.technique.helper import *
from kafl_fuzzer.common.util import MAX_INTERESTING_SIZE

def mutate_seq_8_bit_interesting(irp_list, index, func, skip_null=False, effector_map=None, verbose=False, mutation_part="all"):
    if mutation_part == "header":
        original_data = irp_list[index].header
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length
    elif mutation_part == "body":
        original_data = irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].InBuffer_length
    elif mutation_part == "all":
        original_data = irp_list[index].header + irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length + irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_INTERESTING_SIZE:
        end = MAX_INTERESTING_SIZE

    label="afl_int_1"
    for i in range(start, end):
        if effector_map:
            if not effector_map[i]:
                continue

        orig = data[i]

        if skip_null and orig == 0:
            continue

        for j in range(len(interesting_8_Bit)):
            value = in_range_8(interesting_8_Bit[j])
            if (is_not_bitflip(orig ^ value) and
                is_not_arithmetic(orig, value, 1)):
                    data[i] = value
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

        data[i] = orig
    if mutation_part == "header":
        irp_list[index].header = original_data
    elif mutation_part == "body":
        irp_list[index].InBuffer = original_data
    elif mutation_part == "all":
        irp_list[index].header = original_data[:irp_list[index].header_length]
        irp_list[index].InBuffer = original_data[irp_list[index].header_length:]


def mutate_seq_16_bit_interesting(irp_list, index, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False, mutation_part="all"):
    if mutation_part == "header":
        original_data = irp_list[index].header
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length
    elif mutation_part == "body":
        original_data = irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].InBuffer_length
    elif mutation_part == "all":
        original_data = irp_list[index].header + irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length + irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_INTERESTING_SIZE:
        end = MAX_INTERESTING_SIZE

    label="afl_int_2"
    for i in range(start, end - 1):
        if effector_map:
            if not effector_map[i] and not effector_map[i+1]:
                continue

        orig = data[i:i+2]
        oval = struct.unpack('<H', orig)[0]

        if skip_null and oval == 0:
            continue

        for j in range(len(interesting_16_Bit)):
            num1 = in_range_16(interesting_16_Bit[j])
            num2 = swap_16(num1)

            if (is_not_bitflip(oval ^ num1) and
                is_not_arithmetic(oval, num1, 2, arith_max=arith_max) and
                is_not_interesting(oval, num1, 2, 0)):
                    struct.pack_into("<H", data, i, num1)
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

            if (num1 != num2 and
                is_not_bitflip(oval ^ num2) and
                is_not_arithmetic(oval, num2, 2, arith_max=arith_max) and
                is_not_interesting(oval, num2, 2, 1)):
                    struct.pack_into(">H", data, i, num1)
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

        data[i:i+2] = orig
    if mutation_part == "header":
        irp_list[index].header = original_data
    elif mutation_part == "body":
        irp_list[index].InBuffer = original_data
    elif mutation_part == "all":
        irp_list[index].header = original_data[:irp_list[index].header_length]
        irp_list[index].InBuffer = original_data[irp_list[index].header_length:]

def mutate_seq_32_bit_interesting(irp_list, index, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False, mutation_part="all"):
    if mutation_part == "header":
        # original_data = irp_list[index].header  # original_data = irp_list[index].InBuffer
        original_data = irp_list[index].header
        data = bytearray(original_data) # 수정 가능한 bytearray로 변환
        InBufferLength = irp_list[index].header_length
    elif mutation_part == "body":
        # original_data = irp_list[index].InBuffer  # original_data = irp_list[index].InBuffer
        original_data = irp_list[index].InBuffer
        data = bytearray(original_data) # 수정 가능한 bytearray로 변환
        InBufferLength = irp_list[index].InBuffer_length
    elif mutation_part == "all":
        original_data = irp_list[index].header + irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length + irp_list[index].InBuffer_length

    if InBufferLength == 0: return


    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_INTERESTING_SIZE:
        end = MAX_INTERESTING_SIZE

    label="afl_int_4"
    for i in range(start, end - 3):
        if effector_map:
            if effector_map[i:i+4] == bytes(4):
                continue

        orig = data[i:i+4]
        oval = struct.unpack('<I', orig)[0]

        if skip_null and oval == 0:
            continue

        for j in range(len(interesting_32_Bit)):

            num1 = in_range_32(interesting_32_Bit[j])
            num2 = swap_32(num1)

            if (is_not_bitflip(oval ^ num1) and
                is_not_arithmetic(oval, num1, 4, arith_max=arith_max) and
                is_not_interesting(oval, num1, 4, 0)):
                    struct.pack_into("<I", data, i, num1)
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

            if (num1 != num2 and is_not_bitflip(oval ^ num2) and
                is_not_arithmetic(oval, num2, 4, arith_max=arith_max) and
                is_not_interesting(oval, num2, 4, 1)):
                    struct.pack_into("<I", data, i, num2)
                    # irp_list[index].InBuffer = bytes(data)  # 수정된 bytearray를 다시 bytes로 변환하여 할당
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

        data[i:i+4] = orig
    if mutation_part == "header":
        irp_list[index].header = original_data
    elif mutation_part == "body":
        irp_list[index].InBuffer = original_data
    elif mutation_part == "all":
        irp_list[index].header = original_data[:irp_list[index].header_length]
        irp_list[index].InBuffer = original_data[irp_list[index].header_length:]

def mutate_seq_64_bit_interesting(irp_list, index, func, skip_null=False, effector_map=None, arith_max=AFL_ARITH_MAX, verbose=False, mutation_part="all"):
    # 32비트 함수에서 .header를 사용한 것을 반영
    if mutation_part == "header":
        original_data = irp_list[index].header
        data = bytearray(original_data) # 수정 가능한 bytearray로 변환
        InBufferLength = irp_list[index].header_length
    elif mutation_part == "body":
        original_data = irp_list[index].InBuffer
        data = bytearray(original_data) # 수정 가능한 bytearray로 변환
        InBufferLength = irp_list[index].InBuffer_length
    elif mutation_part == "all":
        original_data = irp_list[index].header + irp_list[index].InBuffer
        data = bytearray(original_data)
        InBufferLength = irp_list[index].header_length + irp_list[index].InBuffer_length

    if InBufferLength == 0: return

    # limit walking bits up to MAX_WALKING_BITS_SIZE.
    start, end = 0, InBufferLength
    if end > MAX_INTERESTING_SIZE:
        end = MAX_INTERESTING_SIZE

    label="afl_int_8" # 1, 2, 4 다음은 8
    for i in range(start, end - 7): # 8바이트 처리를 위해 끝 경계 조정
        if effector_map:
            # 8바이트 모두 effector가 없는지 확인
            if effector_map[i:i+8] == bytes(8):
                continue

        orig = data[i:i+8] # 8바이트 슬라이스
        oval = struct.unpack('<Q', orig)[0] # '<Q'는 64비트 unsigned long long

        if skip_null and oval == 0:
            continue
            
        # interesting_64_Bit 리스트가 helper에 정의되어 있다고 가정
        for j in range(len(interesting_64_Bit)):

            # 64비트 헬퍼 함수가 있다고 가정
            num1 = in_range_64(interesting_64_Bit[j]) 
            num2 = swap_64(num1) # 64비트 헬퍼 함수가 있다고 가정

            if (is_not_bitflip_64(oval ^ num1) and  # _64 사용
                is_not_arithmetic_64(oval, num1, 8, arith_max=arith_max) and # _64 사용
                is_not_interesting_64(oval, num1, 8, 0)): # _64 사용
                    struct.pack_into("<Q", data, i, num1) 
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

            if (num1 != num2 and is_not_bitflip_64(oval ^ num2) and # _64 사용
                is_not_arithmetic_64(oval, num2, 8, arith_max=arith_max) and # _64 사용
                is_not_interesting_64(oval, num2, 8, 1)): # _64 사용
                    struct.pack_into("<Q", data, i, num2) # num2를 사용해야 함 (num1의 big-endian)
                    if mutation_part == "header":
                        irp_list[index].header = bytes(data)
                    elif mutation_part == "body":
                        irp_list[index].InBuffer = bytes(data)
                    elif mutation_part == "all":
                        irp_list[index].header = bytes(data)[:irp_list[index].header_length]
                        irp_list[index].InBuffer = bytes(data)[irp_list[index].header_length:]
                    func(irp_list, label=label)

        data[i:i+8] = orig # 8바이트 원본 데이터로 복원
        
    if mutation_part == "header":
        irp_list[index].header = original_data
    elif mutation_part == "body":
        irp_list[index].InBuffer = original_data
    elif mutation_part == "all":
        irp_list[index].header = original_data[:irp_list[index].header_length]
        irp_list[index].InBuffer = original_data[irp_list[index].header_length:]