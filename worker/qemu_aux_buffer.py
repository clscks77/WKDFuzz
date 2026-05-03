# Copyright 2020 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2021 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import mmap
import os
import struct

from collections import namedtuple
from enum import IntEnum

from kafl_fuzzer.common import logger


result_tuple = namedtuple('result_tuple', [
    'state',            # 현재 QEMU 상태 코드: unsigned char = B
    'exec_done',        # bool = ?
    'exec_code',        # unsigned char = B
    'reloaded',         # QEMU snapshot이 reload 되었는지 여부: bool = ?

    'pt_overflow',      # Intel PT trace가 overflow 되었는지: bool = ?
    'page_fault',       # bool = ?
    'tmp_snap',         # bool = ?
    'pad3',             # 패딩: bool = ?

    'page_fault_addr',  # unsigned long long = Q
    'dirty_pages',      # 실행 중 dirty된 메모리 페이지 수: unsigned int = I
    'pt_trace_size',    # Intel PT 트레이스 크기: unsigned int = I
    'bb_cov',           # 커버된 basic block 수 (coverage): unsigned int = I
    'runtime_usec',     # unsigned int = I
    'runtime_sec',      # unsigned int = I
    ])

my_magic = 0x54502d554d4551
my_version = 0x3
my_hash = 0x54

HEADER_SIZE = 128
CAP_SIZE = 256
CONFIG_SIZE = 512
STATUS_SIZE = 512
MISC_SIZE = 4096-(HEADER_SIZE+CAP_SIZE+CONFIG_SIZE+STATUS_SIZE)

HEADER_OFFSET = 0
CAP_OFFSET = HEADER_SIZE
CONFIG_OFFSET = CAP_OFFSET + CAP_SIZE
STATUS_OFFSET = CONFIG_OFFSET + CONFIG_SIZE
MISC_OFFSET = STATUS_OFFSET + STATUS_SIZE

class QemuAuxRC(IntEnum):
    SUCCESS = 0
    CRASH = 1
    HPRINTF = 2
    TIMEOUT = 3
    INPUT_BUF_WRITE = 4
    ABORT = 5
    SANITIZER = 6
    STARVED = 7

class QemuAuxBuffer:

    def __init__(self, file):
        self.aux_buffer_fd = os.open(file, os.O_RDWR | os.O_SYNC)
        self.aux_buffer = mmap.mmap(self.aux_buffer_fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ) # fix this later
        self.current_timeout = None

    def validate_header(self):
        qemu_magic = (struct.unpack('L', self.aux_buffer[0:8])[0])
        qemu_version = (struct.unpack('H', self.aux_buffer[8:10])[0])
        qemu_hash = (struct.unpack('H', self.aux_buffer[10:12])[0])

        if qemu_magic != my_magic:
            logger.error("Magic mismatch: %x != %x" % (qemu_magic, my_magic))
            return False

        if qemu_version != my_version:
            logger.error("Version mismatch: %x != %x" % (qemu_version, my_version))
            return False 

        if qemu_hash != my_hash:
            logger.error("Hash mismatch: %x != %x" % (qemu_hash, my_hash))
            return False

        return True

    def get_misc_buf(self):
        mlen = struct.unpack('H', self.aux_buffer[MISC_OFFSET+0:MISC_OFFSET+2])[0]
        return self.aux_buffer[MISC_OFFSET+2:MISC_OFFSET+2+mlen]

    def get_state(self):
        return struct.unpack_from('B', self.aux_buffer, offset=STATUS_OFFSET)[0]

    def get_result(self):
        return result_tuple._make(
                struct.unpack_from('B?B? ???? QIIIII',
                                   self.aux_buffer,
                                   offset=STATUS_OFFSET))

    def set_config_buffer_changed(self):
        self.aux_buffer[CONFIG_OFFSET+0] = 1

    def set_timeout(self, timeout):
        assert(isinstance(timeout, (int, float)))
        self.current_timeout = timeout
        secs = int(timeout)
        usec = int(1000*1000*(timeout - secs))
        struct.pack_into("=BI", self.aux_buffer, CONFIG_OFFSET+1, secs, usec)
        self.set_config_buffer_changed()

    def get_timeout(self):
        return self.current_timeout

    def set_redqueen_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+6] = int(enable)
        self.set_config_buffer_changed()

    def set_trace_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+7] = int(enable)
        self.set_config_buffer_changed()

    def set_reload_mode(self, enable):
        self.aux_buffer[CONFIG_OFFSET+8] = int(enable)
        self.set_config_buffer_changed()

    def dump_page(self, addr):
        struct.pack_into("BQ", self.aux_buffer, CONFIG_OFFSET+10, 1, addr)
        self.set_config_buffer_changed()


class QemuAuxBuffer2:
    def __init__(self, file):
        self.aux_buffer_fd = os.open(file, os.O_RDWR | os.O_SYNC)
        self.aux_buffer = mmap.mmap(self.aux_buffer_fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)

    def validate_header(self):
        magic = struct.unpack('L', self.aux_buffer[0:8])[0]
        version = struct.unpack('H', self.aux_buffer[8:10])[0]
        hashval = struct.unpack('H', self.aux_buffer[10:12])[0]

        if magic != 0x0116011601170117:
            logger.error("QemuAuxBuffer2: Magic mismatch")
            return False
        if version != 0x1:
            logger.error("QemuAuxBuffer2: Version mismatch")
            return False
        if hashval != 0x42:
            logger.error("QemuAuxBuffer2: Hash mismatch")
            return False
        return True

    def get_result(self):    
        # 앞 4바이트는 count, 이후가 state_sequence 데이터
        state_count = struct.unpack('I', self.aux_buffer[12:16])[0]
        # print("[** QemuAuxBuffer2.get_result] state_count: %d" % state_count) # @@ 디버깅용
        next_offset = 16 + state_count * 4
        net_state_sequence = self.aux_buffer[16:16 + state_count * 4]  # unsigned int(uint32_t) = 4byte
        net_state_sequence_list = list(struct.unpack(f'{state_count}I', net_state_sequence))
        
        # 이어서, 앞 4바이트는 count, 이후가 flag_sequence 데이터
        msg_count = struct.unpack('I', self.aux_buffer[next_offset:next_offset + 4])[0]
        # print("[** QemuAuxBuffer2.get_result] msg_count: %d" % msg_count) # @@ 디버깅용
        data_offset = next_offset + 4
        flag_sequence = self.aux_buffer[data_offset:data_offset + msg_count*4]  # uint8_t = 4byte
        flag_sequence_list = list(struct.unpack(f'{msg_count}I', flag_sequence))
        # for(i, flag) in enumerate(flag_sequence_list):
        #     print("[** QemuAuxBuffer2.get_result] flag_sequence[%d]: type(%s)" % (i, type(flag))) # @@ 디버깅용
        #     print("[** QemuAuxBuffer2.get_result] flag_sequence[%d]: %d" % (i, flag)) # @@ 디버깅용
        # print("[** QemuAuxBuffer2.get_result] total data size: %d bytes" % (data_offset + msg_count*4 + 12)) # @@ 디버깅용
        T_IMG_base = struct.unpack('Q', self.aux_buffer[data_offset + msg_count*4 : data_offset + msg_count*4 + 8])[0]
        T_IMG_size = struct.unpack('I', self.aux_buffer[data_offset + msg_count*4 + 8 : data_offset + msg_count*4 + 12])[0]
        # print("[** QemuAuxBuffer2.get_result] imagebase: 0x%016x" % imagebase) # @@ 디버깅용
        # print("[** QemuAuxBuffer2.get_result] imagesize: 0x%08x" % imagesize) # @@ 디버깅용

        # return net_state_sequence_list, flag_sequence_list
        return net_state_sequence_list, flag_sequence_list, T_IMG_base, T_IMG_size