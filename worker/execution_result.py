# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import ctypes
import mmh3

from kafl_fuzzer.native import loader as native_loader

class ExecutionResult:
    bitmap_native_so = None

    @staticmethod
    def bitmap_from_bytearray(bitmap, exitreason, performance, net_state_sequence, flag_list):  # @@
        bitmap_size = len(bitmap)
        c_bitmap = (ctypes.c_uint8 * bitmap_size).from_buffer_copy(bitmap)
        return ExecutionResult(c_bitmap, bitmap_size, exitreason, performance, False, False, net_state_sequence, flag_list)  # @@

    @staticmethod
    def get_null_hash(bitmap_size):
        # corresponds to libxdc_bitmap_get_hash()
        return "%016x" % mmh3.hash64(bytes(bitmap_size), seed=0xaaaaaaaa, x64arch=True, signed=False)[0]

    def __init__(self, cbuffer, bitmap_size, exit_reason, performance, starved=False, trashed=False, net_state_sequence=None, flag_list=None, T_IMG_base=None, T_IMG_size=None, to_rva_counts=None):  # @@ directed
        if not ExecutionResult.bitmap_native_so:
            ExecutionResult.bitmap_native_so = ctypes.CDLL(native_loader.bitmap_path())

        self.bitmap_size = bitmap_size
        self.cbuffer = cbuffer
        self.lut_applied = False  # By default we assume that the bucket lut has not yet been applied
        self.exit_reason = exit_reason
        self.performance = performance
        self.starved = starved
        self.trashed = trashed
        self.net_state_sequence = net_state_sequence # @@
        self.flag_list = flag_list           # @@
        self.T_IMG_base = T_IMG_base
        self.T_IMG_size = T_IMG_size
        self.to_rva_counts = to_rva_counts  # @@ directed

    def invalidate(self):
        self.cbuffer = None
        return self
    
    def set_starved(self, _starved):
        self.starved = _starved

    def is_starved(self):
        return self.starved

    def is_crash(self):
        return self.exit_reason != "regular"

    def is_regular(self):
        return not self.is_crash()

    def is_lut_applied(self):
        return self.lut_applied

    def copy_to_array(self):
        return bytearray(self.cbuffer)

    def hash(self, pre_lut=False):
        # libxdc_bitmap_get_hash() is computed prior to apply_lut()
        # For debug, set pre_lut=True to get a compatible hash or die trying
        if self.lut_applied:
            assert not pre_lut, "Request pre-LUT hash but LUT has been applied already."
        else:
            self.apply_lut()
        return "%016x" % mmh3.hash64(self.cbuffer, seed=0xaaaaaaaa, x64arch=True, signed=False)[0]

    def apply_lut(self):
        if not self.lut_applied:
            ExecutionResult.bitmap_native_so.apply_bucket_lut(self.cbuffer, ctypes.c_uint64(self.bitmap_size))
            self.lut_applied = True
        return self
