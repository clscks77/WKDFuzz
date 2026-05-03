# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Worker Implementation.

Request fuzz input from Manager and process it through various fuzzing stages/mutations.
Each Worker is associated with a single Qemu instance for executing fuzz inputs.
"""

import os
import time
import signal
import sys
import shutil
import tempfile
import logging
import lz4.frame as lz4

#from kafl_fuzzer.common.config import FuzzerConfiguration
from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.common.util import atomic_write, serialize_sangjun, serialize, add_to_message_list # add_to_irp_list
from kafl_fuzzer.manager.bitmap import BitmapStorage, GlobalBitmap
from kafl_fuzzer.manager.communicator import ClientConnection, MSG_IMPORT, MSG_RUN_NODE, MSG_BUSY
from kafl_fuzzer.manager.node import QueueNode
from kafl_fuzzer.manager.statistics import WorkerStatistics
from kafl_fuzzer.worker.state_logic import FuzzingStateLogic
from kafl_fuzzer.worker.qemu import QemuIOException
from kafl_fuzzer.worker.qemu import qemu as Qemu
from kafl_fuzzer.common.logger import WorkerLogAdapter

from kafl_fuzzer.common.color import FLUSH_LINE, FAIL, ENDC
PREFIX = FLUSH_LINE + FAIL
import copy

import hashlib

def worker_loader(pid, config):
    worker = WorkerTask(pid, config)
    worker.start()

class WorkerTask:

    def __init__(self, pid, config):
        self.config = config
        self.pid = pid
        self.logger_no_prefix = logging.getLogger(__name__)
        self.logger = WorkerLogAdapter(self.logger_no_prefix, {'pid': self.pid})

        self.q = Qemu(self.pid, self.config)
        self.conn = ClientConnection(pid, config)
        self.statistics = WorkerStatistics(self.pid, config)
        self.logic = FuzzingStateLogic(self, config)
        self.bitmap_storage = BitmapStorage(self.config, "main")

        self.payload_limit = self.q.get_payload_limit()
        self.t_hard = config.timeout_hard
        self.t_soft = config.timeout_soft
        self.t_check = config.timeout_check
        self.num_funky = 0
        self.play_maker_mode = False

        self.target_state_id = 0

    def play_maker_on(self):
        self.play_maker_mode = True

    def handle_import(self, msg):
        init_seed_id = msg["task"]["init_seed_id"]
        meta_data = {"state": {"name": "import"}, "id": 0, "init_seed_id": init_seed_id} # seed에 메타데이터 부여
        payload = msg["task"]["payload"]
        self.q.set_timeout(self.t_hard)
        print("[** DEBUG] hadle_import")
        # print(''.join(f'\\x{b:02x}' for b in payload))
        try:
            self.logic.process_import(payload, meta_data) # import seed 처리 로직 worker\state_logic.py
        except QemuIOException:
            self.logger.warn("Execution failure on import.")
            self.conn.send_node_abort(None, None) # QEMU 실행에 실패하면 abort 메시지 전송
            raise
        self.conn.send_ready() # 실행 완료되면 Worker에게 ready 메시지 전송

    def handle_busy(self):
        busy_timeout = 4
    
        self.logger.info("No inputs in queue, sleeping %ds..", busy_timeout)
        time.sleep(busy_timeout)
        self.conn.send_ready()

    def handle_node(self, msg):
        meta_data = QueueNode.get_metadata(self.config.workdir, msg["task"]["nid"])
        meta_data["target_state_id"] = msg["task"]["target_state_id"] # @@ 없으면 null
        self.target_state_id = meta_data["target_state_id"] # @@
        # print(f"[** DEBUG] handle_node({msg['task']['nid']}): target_state_id={self.target_state_id}") # @@ 디버깅용
        payload = QueueNode.get_payload(self.config.workdir, meta_data)
        # print(type(payload))
        # payload = b'\x00\x00\x00\xc0\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x01\x00\x00\x00\x00\x00@\x00\x00\x00hLyECAXFIiTCzbFHh\x00\x00\x00\x03\x00\x00\x00\x11\x03\xff\xff\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00NoNDMBRGSMODIqRLqMFirAHWWEhkpaVw\xff\xff\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x01\x00\xff\xff\xff\xff\x03\x00\x0e\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x03\x00\xff\xff\x00\x00\x00\x9a\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00X\x00B\x00\x00\x00\x00\x00\x00\x00\x00\x00`@\x06\x06+\x06\x01\x05\x05\x02\xa0604\xa0\x0e0\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n\xa2"\x04 NTLMSSP\x00\x01\x00\x00\x005\x82\x88\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb5\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00X\x00]\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1[0Y\xa2Wx04UNTLMSSP\x00\x03\x00\x00\x00\x01\x00\x01\x00D\x00\x00\x00\x00\x00\x00\x00E\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x04\x00\x04\x00@\x00\x00\x00\x10\x00\x10\x00E\x00\x00\x005\x82\x88\xe0M\x00E\x00\x00\x99p\xdc\x11\xe1M<\x02\xe8J{=\x1b&\xe0>\x00\x00\x004\xfcSMBD\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff!\xb0\x00\xfeSMB@\x00\x01\x00!\x01\x00\r\x00\x7f\x00\x05\x00\x03\x00\x13\x0b\x00\x02\x84\x0c\x00\x0e\x00\x04\x00\x00\x00\x00\x00\x00\x00D\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00D\xfeSMB@\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00'
        # print(type(payload))
        play_maker = msg["task"]["play_maker"]
        if play_maker and self.play_maker_mode is False:
            self.play_maker_on()

        # fixme: determine globally based on all seen regulars
        t_dyn = self.t_soft + 1.2 * meta_data["info"]["performance"]
        self.q.set_timeout(min(self.t_hard, t_dyn))
        try:
            # print(f"[***** DEBUG handle_node] metadata ({len(meta_data)})={meta_data}") # @@ 디버깅용
            results, new_payload = self.logic.process_node(payload, meta_data) # fuzzing 수행
        except QemuIOException:
            # mark node as crashing and free it before escalating
            self.logger.info("Qemu execution failed for node %d." % meta_data["id"])
            results = self.logic.create_update(meta_data["state"], {"crashing": True}) # 노드 상태 업데이트
            self.conn.send_node_abort(meta_data["id"], results)
            raise

        if new_payload: # 새로운 입력이 생기면 validate_bits 검증
            default_info = {"method": "validate_bits", "parent": meta_data["id"]}
            if self.validate_bits(new_payload, meta_data, default_info):
                self.logger.debug("Stage %s found alternative payload for node %d", meta_data["state"]["name"], meta_data["id"])
            else:
                self.logger.warn("Provided alternative payload found invalid - bug in stage %s?", meta_data["state"]["name"])
        self.conn.send_node_done(meta_data["id"], results, new_payload) # 결과(?)와 함께 MSG_NODE_DONE 전송

    def start(self):

        def sigterm_handler(signal, frame):
            if self.q:
                self.q.async_exit()
            sys.exit(0)

        signal.signal(signal.SIGTERM, sigterm_handler)
        os.setpgrp()
        rand.reseed()

        # pin worker N to the Nth available CPU of this task group
        try:
            cpu_offset = self.config.cpu_offset + self.pid
            cpu = sorted(os.sched_getaffinity(0))[cpu_offset]
            os.sched_setaffinity(0, [cpu])
        except Exception:
            self.logger.error("failed to set CPU affinity to %d out of %d. Aborting..", cpu_offset, len(os.sched_getaffinity(0)))
            return

        # start Qemu and commence main worker loop
        try:
            if self.q.start():
                self.loop()
            else:
                self.logger.error("Failed to launch Qemu.")
                self.conn.send_node_abort(None, None)
        except QemuIOException:
            # Qemu has likely died on us - try to restart?
            pass
        finally:
            if self.q:
                self.q.async_exit()
            self.logger.info("Exit.")

    def loop(self):
        self.logger.info("Entering fuzz loop..")
        self.conn.send_ready()

        while True:
            try:
                msg = self.conn.recv()
            except ConnectionResetError:
                self.logger.error("Lost connection to Manager. Shutting down.")
                return

            if msg["type"] == MSG_RUN_NODE:
                self.handle_node(msg)
            elif msg["type"] == MSG_IMPORT:
                self.handle_import(msg)
            elif msg["type"] == MSG_BUSY:
                self.handle_busy()
            else:
                raise ValueError("Unknown message type {}".format(msg))
    def crash_validate(self,data, old_res, label=None):
        payload_list = []
        add_to_message_list(payload_list, data) # @@ 체크 필요

        
        tmp_list = copy.deepcopy(payload_list)


        retry = 4
        for _ in range(retry):
            payload, is_multi_irp = serialize(tmp_list)
            exec_res = self.__execute(payload, label=label)

            if not exec_res.is_crash():
                return False
            time.sleep(1)
        return True


    def quick_crash_diet(self,data, retry=0, label=None):
        payload_list = []
        add_to_message_list(payload_list, data) # @@ 체크 필요

        if len(payload_list)<5:
            ret_payload, _ = serialize(payload_list)
            return ret_payload, True
        
        if retry>5:
            ret_payload, _ = serialize(payload_list)
            return ret_payload, False

        valid_array = [ True for i in range(len(payload_list))]

        def get_validate_map(payload_list, label=None):
            for i in range(len(payload_list)):

                tmp_list = copy.deepcopy(payload_list)
                tmp_list.pop(i)
                payload, is_multi_irp = serialize(tmp_list)
                exec_res = self.__execute(payload, label=label)
                if exec_res.is_crash():
                    valid_array[i] = False
                else:
                    valid_array[i] = True
                tmp_list.clear()
            return payload_list



        get_validate_map(payload_list, label=label)
        
        refined_list = []
        for i in range(len(payload_list)):
            if valid_array[i]:
                refined_list.append(payload_list[i])
        
        payload, is_multi_irp = serialize(refined_list)
        exec_res = self.__execute(payload, label=label)
        
        if not exec_res.is_crash():
            return self.quick_crash_diet(data, retry=retry+1, label=label)
        else:
            #self.logger.critical(PREFIX+f"[+] DEBUG {valid_array}"+ENDC)
            ret_payload, _ = serialize(refined_list)
            return ret_payload, True
        


    def quick_validate(self, data, old_res, trace=False, label=None):
        # Validate in persistent mode. Faster but problematic for very funky targets
        old_array = old_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(True)
            # give a little extra time in case payload is close to limit
            dyn_timeout = self.q.get_timeout()
            self.q.set_timeout(self.t_hard*2)

        new_res = self.__execute(data, label=label).apply_lut()
        
        ########## @@ Reflect state to new_res too
        # new_res = self.__execute(data)

        # prev_state = 0
        # state_size = 256     #define STATE_SIZE   1 << 8  = 256
        # shift_size = 32768   #define SHIFT_SIZE   1 << 15 = 32768
        
        # net_state_sequence = new_res.net_state_sequence
        # for cur_state in net_state_sequence:
        #     map_ptr_idx = (prev_state * state_size + cur_state) % shift_size
        #     new_res.cbuffer[map_ptr_idx] = (new_res.cbuffer[map_ptr_idx] + 1) % 256  # overflow 방지 # 디버깅 필요
        #     prev_state = cur_state
        # new_res.apply_lut()
        ##########

        new_array = new_res.copy_to_array()

        if trace:
            self.q.set_trace_mode(False)
            self.q.set_timeout(dyn_timeout)
        
        # --- 디버깅 코드 시작 ---
        # diff_count = 0
        # cnt = 0
        # for i in range(len(old_array)):
        #     if old_array[i] != 0:
        #         cnt += 1
        #     if old_array[i] != new_array[i]:
        #         diff_count += 1
        #         print(f"[** DEBUG] Difference at index {i}: old=0x{old_array[i]:02x}, new=0x{new_array[i]:02x}")
                
        # print(f"[** DEBUG] Total differences found: {diff_count}")
        # print(f"[** DEBUG] Total bitmap found: {cnt}/{len(old_array)}")
        # --- 디버깅 코드 끝 ---

        # 다시 실행했을 때 동일한 비트맵을 갖는다면 stable한 input으로 판단
        if new_array == old_array:
            return True, new_res.performance

        return False, new_res.performance

    def funky_validate(self, data, old_res, trace=False):
        # Validate in persistent mode with stochastic prop of funky results

        validations = 8
        confirmations = 0
        runtime_avg = 0
        num = 0
        trace_round=False

        for num in range(validations):
            stable, runtime = self.quick_validate(data, old_res, trace=trace_round)
            if stable:
                confirmations += 1
                runtime_avg += runtime

            if confirmations >= 0.5*validations:
                trace_round=trace

            if confirmations >= 0.75*validations:
                return True, runtime_avg/num

        self.logger.debug("Funky input received %d/%d confirmations. Rejecting..", confirmations, validations)
        if self.config.debug:
            self.store_funky(data)
        return False, runtime_avg/num

    def store_funky(self, data):
        # store funky input for further analysis 
        filename = f"%s/funky/payload_%04x%02x" % (self.config.workdir, self.num_funky, self.pid)
        atomic_write(filename, data)
        self.num_funky += 1



    def validate_bits(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        old_bits.update(old_node["new_bits"])
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def validate_bytes(self, data, old_node, default_info):
        new_bitmap, _ = self.execute(data, default_info)
        # handle non-det inputs
        if new_bitmap is None:
            return False
        old_bits = old_node["new_bytes"].copy()
        return GlobalBitmap.all_new_bits_still_set(old_bits, new_bitmap)

    def execute_redqueen(self, headers, data, irp_list):
        # execute in trace mode, then restore settings
        # setting a timeout seems to interfere with tracing
        self.statistics.event_exec_redqueen()
        self.q.qemu_aux_buffer.set_redqueen_mode(True)
        exec_res = self.execute_naked(headers, data, irp_list, timeout=0)
        self.q.qemu_aux_buffer.set_redqueen_mode(False)
        return exec_res

    def __send_to_manager(self, data, exec_res, info, label=None):
        info["time"] = time.time()
        info["exit_reason"] = exec_res.exit_reason
        info["performance"] = exec_res.performance
        info["hash"]        = exec_res.hash()
        info["starved"]     = exec_res.starved
        info["trashed"]     = exec_res.trashed
        info["payload_len"] = len(data)
        info["payload_sha256"] = hashlib.sha256(data).hexdigest()
        # [디버깅 코드 시작]
        # try:
        #      # 64비트 부호 있는 정수 최대값 (약 9xx경)
        #     LIMIT = 2**63 - 1
        #     for k, v in info.items():
        #         # 리스트나 딕셔너리, 튜플 내부까지 재귀적으로 확인하면 더 좋지만, 
        #         # 일단 의심가는 최상위 필드부터 확인합니다.
        #         if k == "to_rva_counts":
        #              for rva, cnt in v:
        #                  if isinstance(rva, int) and abs(rva) > LIMIT:
        #                      print(f"[DEBUG ERROR] Too large integer in to_rva_counts! RVA: {rva}")
        #                  if isinstance(cnt, int) and abs(cnt) > LIMIT:
        #                      print(f"[DEBUG ERROR] Too large integer in to_rva_counts! Count: {cnt}")
        #         elif isinstance(v, int) and abs(v) > LIMIT:
        #             print(f"[DEBUG ERROR] Too large integer in info['{k}']: {v}")
        #         elif isinstance(v, list):
        #             for i, item in enumerate(v):
        #                 if isinstance(item, int) and abs(item) > LIMIT:
        #                      print(f"[DEBUG ERROR] Too large integer in info['{k}'][{i}]: {item}")
        # except Exception as e:
        #     print(f"[DEBUG] Checking failed: {e}")
        # [디버깅 코드 끝]
        if self.conn is not None:
            self.conn.send_new_input(data, exec_res.copy_to_array(), info, label)
        else:
            print("client connection down")

    def trace_payload(self, data, info):
        # Legacy implementation of -trace (now -trace_cb) using libxdc_edge_callback hook.
        # This is generally slower and produces different bitmaps so we execute it in
        # a different phase as part of calibration stage.
        # Optionally pickup pt_trace_dump* files as well in case both methods are enabled.
        trace_edge_in = self.config.workdir + "/redqueen_workdir_%d/pt_trace_results.txt" % self.pid
        trace_dump_in = self.config.workdir + "/pt_trace_dump_%d" % self.pid
        trace_edge_out = self.config.workdir + "/traces/fuzz_cb_%05d.lst" % info['id']
        trace_dump_out = self.config.workdir + "/traces/fuzz_cb_%05d.bin" % info['id']

        self.logger.info("Tracing payload_%05d..", info['id'])

        if len(data) > self.payload_limit:
            data = data[:self.payload_limit]

        try:
            self.q.set_payload(data)
            old_timeout = self.q.get_timeout()
            self.q.set_timeout(0)
            self.q.set_trace_mode(True)
            exec_res = self.q.send_payload()

            self.q.set_trace_mode(False)
            self.q.set_timeout(old_timeout)

            if os.path.exists(trace_edge_in):
                with open(trace_edge_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_edge_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if os.path.exists(trace_dump_in):
                with open(trace_dump_in, 'rb') as f_in:
                    with lz4.LZ4FrameFile(trace_dump_out + ".lz4", 'wb',
                            compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                        shutil.copyfileobj(f_in, f_out)

            if not exec_res.is_regular():
                self.statistics.event_reload(exec_res.exit_reason)
                self.q.reload()
        except Exception as e:
            self.logger.info("Failed to produce trace %s: %s (skipping..)", trace_edge_out, e)
            return None

        return exec_res
    
    # [for directed] start
    def _get_image_info_from_exec_res(self, exec_res):
        """
        aux2로 들어온 이미지 베이스/사이즈를 exec_res에서 꺼낸다.
        당신이 aux2에 추가한 필드명이 T_IMG_base/T_IMG_size라면 그대로 잡힌다.
        그렇지 않으면 흔한 대체 키들도 시도한다.
        """
        # 1) 가장 먼저 당신이 추가한 이름을 시도
        base = getattr(exec_res, "T_IMG_base", None)
        size = getattr(exec_res, "T_IMG_size", None)
        #print(f"[** DEBUG] _get_image_info_from_exec_res: base={base}, size={size}") # @@ 디버깅용
        if base is not None and size is not None:
            return int(base), int(size)

        # 2) 혹시 다른 이름으로 노출되면 순차 시도
        candidates = [
            ("image_base", "image_size"),
            ("img_base",   "img_size"),
        ]
        for kb, ks in candidates:
            b = getattr(exec_res, kb, None)
            s = getattr(exec_res, ks, None)
            if b is not None and s is not None:
                return int(b), int(s)

        # 3) 일부 구현은 리스트(dict)로 줄 수도 있음
        mods = getattr(exec_res, "image_info", None)
        if mods:
            m = mods[0]
            try:
                return int(m.get("base", 0)), int(m.get("size", 0))
            except Exception:
                pass

        return None, None


    def _read_xdc_to_hits(self):
        """QEMU PID로 /tmp/xdc_to_hits_<pid>.bin 읽어 {to_va,count} 리스트 반환."""
        import struct, os
        pid = self.q.process.pid
        path = f"/tmp/xdc_to_hits_{pid}.bin"
        if not os.path.exists(path):
            return []

        hits = []
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 4:
            return []
        n = struct.unpack_from("<I", data, 0)[0]
        off = 4
        need = 4 + n*(8+4)
        if len(data) < need:
            n = max(0, (len(data)-4)//12)  # 방어적
        for i in range(n):
            to_va, cnt = struct.unpack_from("<Q I", data, off)
            #print(f"[** DEBUG] xdc_to_hits[{i}] to_va=0x{to_va:x}, cnt={cnt}") # @@ 디버깅용
            off += 12
            hits.append((to_va, cnt))
        
        try:
            os.remove(path)  # 또는 os.unlink(path)
        except:
            pass
        return hits
    # [for directed] end

    def execute_naked(self, headers, datas, irp_list, timeout=None):

        if len(datas) > self.payload_limit:
            datas = datas[:self.payload_limit]

        if timeout:
            old_timeout = self.q.get_timeout()
            self.q.set_timeout(timeout)
        payload, is_multi_irp = serialize_sangjun(headers, datas, irp_list)
        exec_res = self.__execute(payload)

        if timeout:
            self.q.set_timeout(old_timeout)

        # restart Qemu on crash
        if exec_res.is_crash():
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res


    def __execute(self, data, retry=0, label=None):

        try:
            # if os.path.exists(f"/tmp/kAFL_crash_call_stack_{self.q.process.pid}"):
            #     os.remove(f"/tmp/kAFL_crash_call_stack_{self.q.process.pid}")
            #     #str(self.q.process.pid)
            #     time.sleep(0.3)
            
            # ---- DEBUGGING ---- start
            # print(f"@@@@____is it import??? {label}")
            # if label != "import":
            #     print("[@@ __Debug Data On @@]")
            #     # data_first = b'\x00\x00\x00\xa4\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x00\x01\x00\x00\x00\x40\x00\x00\x00\x4d\x63\x5a\x5a\x59\x59\x63\x47\x51\x52\x4e\x5a\x77\x47\x76\x51\x68\x00\x00\x00\x02\x00\x00\x00\x11\x03\xff\xff\x01\x00\x26\x00\x00\x00\x00\x00\x01\x00\x20\x00\x01\x00\x6e\x6b\x69\x52\x6e\x79\x54\x71\x6b\x63\x78\x4c\x61\x41\x46\x59\x57\x78\x58\x4d\x44\x50\x68\x74\x54\x73\x6e\x68\x68\x72\x78\x73\xff\xff\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x9a\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x40\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x47\x30\x45\xa2\x43\x04\x41\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x01\x00\x01\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x20\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x00\x86\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x00\x70\x00\x6f\x00\x6f\x00\x6c\x00\x73\x00\x73\x00\x00\x00\x00\x6c\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x24\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00\x64\x00\x00\x00\x00\x88\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\x00\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00\x00\x69\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            #     # data_tree_id = b'\x01\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01\x30\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            #     # data_file_id = b'\x11\x00\x00\x00\x25\x00\x00\x00\x01\x00\x00\x00\x25\x00\x00\x00\x00\x00\x00\x00\x58\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x06\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x25\x00\x00\x00\x05\x00\x00\x00\x25\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x04\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x00\x00\x00\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00'
            #     # data = data_first + data_tree_id + data_file_id
            #     data_first = b'\x00\x00\x00\xa4\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x00\x01\x00\x00\x00\x40\x00\x00\x00\x4b\x78\x66\x4a\x4b\x68\x62\x53\x68\x56\x6f\x68\x70\x77\x61\x50\x68\x00\x00\x00\x02\x00\x00\x00\x11\x03\xff\xff\x01\x00\x26\x00\x00\x00\x00\x00\x01\x00\x20\x00\x01\x00\x47\x6e\x69\x70\x4b\x48\x4f\x73\x4f\x61\x65\x56\x58\x74\x70\x58\x69\x48\x79\x41\x51\x76\x7a\x4f\x46\x64\x6f\x76\x58\x63\x78\x4a\xff\xff\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x9a\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x40\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x47\x30\x45\xa2\x43\x04\x41\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x01\x00\x01\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x20\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x00\x86\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x00\x70\x00\x6f\x00\x6f\x00\x6c\x00\x73\x00\x73\x00\x00\x00\x00\x69\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01'
            #     data_info_level = b'\x30\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x27\x00\x00\x00\x01\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x00\x6c\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x24\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00\x64\x00\x00\x00\x00\x88\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\x00\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00\x00\x69\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01\x30\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x00\x58\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x06\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x04\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00'
            #     data = data_first + data_info_level
            #     print("@@@@not import, data intercept@@@@")
            # ---- DEBUGGING ---- end
            self.q.set_payload(data)
            res = self.q.send_payload() # QEMU 실행 결과를 ExecutionResult 객체로 반환받음

            # ---- DEBUGGING ---- start
            # if label == "import":
            #     print("@@@@@##### import #######@@@@@@")
            #     # info["to_rva_counts"] = sorted(res.to_rva_counts.items())
            #     # is_new_input, is_new_bytes = self.bitmap_storage.should_send_to_manager(res, res.exit_reason)
            #     crash = res.is_crash()
            #     # info["net_state_sequence"] = res.net_state_sequence   # @@
            #     # info["flag_list"] = res.flag_list                     # @@
            #     cbuffer_content = bytes(res.cbuffer)
            #     cbuffer_hash = hashlib.md5(cbuffer_content).hexdigest()
            #     # print(f"@@@@Tree_id: {data[1029:1033]}")
            #     try:
            #         data_label = "Overflow"
            #         with open(f"05_crash_test_{data_label}.txt", "x", encoding="utf-8") as f:
            #             log_line = f"@ type: {data_label},,,exec_res.exit_reason: {res.exit_reason},,,is_crash(): {crash}\nis_new_input, is_new_bytes: , \n\nrva: {res.to_rva_counts}\n{res.net_state_sequence}\ncbuffer_hash: {cbuffer_hash}\n\ndata: {data}\n\n" # exec_res.cbuffer: {cbuffer_content}
            #             f.write(log_line)            
            #             f.flush()
            #     except FileExistsError:
            #         pass
                # if self.conn is not None:
                #     self.conn.send_state_sequence_for_update_fuzzs(exec_res.net_state_sequence)
                # info["net_state_sequence"] = exec_res.net_state_sequence   # @@
                # info["flag_list"] = exec_res.flag_list                     # @@
                # info["generating_net_state_id"] = self.target_state_id     # @@
                # self.__send_to_manager(data, exec_res, info, label)
                # return exec_res, is_new_input
            # ---- DEBUGGING ---- end

            self.statistics.event_exec(bb_cov=self.q.bb_seen, trashed=res.trashed)
            return res
        except (ValueError, BrokenPipeError, ConnectionResetError) as e:
            if retry > 2:
                # TO DO if it reliably kills qemu, perhaps log to Manager for harvesting..
                self.logger.error("Aborting due to repeated SHM/socket error.")
                raise QemuIOException("Qemu SHM/socket failure.") from e

            self.logger.warn("Qemu SHM/socket error (retry %d)", retry)
            self.statistics.event_reload("shm/socket error")
            if not self.q.restart():
                raise QemuIOException("Qemu restart failure.") from e
        return self.__execute(data, retry=retry+1, label=label)


    def execute(self, data, info, hard_timeout=False, is_multi_irp=False, label=None):
        """
        하나의 fuzzing input을 실행하고, 그 결과를 해석하여 Manager에게 보낼지 말지 판단
        """
        if len(data) > self.payload_limit: # SHM에 기록될 수 있는 최대 크기(128KB)를 초과하지 않게 하기 위해 자름
            data = data[:self.payload_limit]
        # exec_res = self.__execute(data)
        # print(f"@@@@is it import??? {label}")
        exec_res = self.__execute(data, label=label)    # exec_res = ExecutionResult 객체

        # ---- DEBUGGING ---- start
        # if label != "import":
        #     print("[@@ Debug Data On @@]")
        #     data_first = b'\x00\x00\x00\xa4\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x00\x01\x00\x00\x00\x40\x00\x00\x00\x4b\x78\x66\x4a\x4b\x68\x62\x53\x68\x56\x6f\x68\x70\x77\x61\x50\x68\x00\x00\x00\x02\x00\x00\x00\x11\x03\xff\xff\x01\x00\x26\x00\x00\x00\x00\x00\x01\x00\x20\x00\x01\x00\x47\x6e\x69\x70\x4b\x48\x4f\x73\x4f\x61\x65\x56\x58\x74\x70\x58\x69\x48\x79\x41\x51\x76\x7a\x4f\x46\x64\x6f\x76\x58\x63\x78\x4a\xff\xff\x02\x00\x04\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x9a\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x40\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x47\x30\x45\xa2\x43\x04\x41\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x01\x00\x01\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x20\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x00\x86\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9f\x01\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x00\x70\x00\x6f\x00\x6f\x00\x6c\x00\x73\x00\x73\x00\x00\x00\x00\x69\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01'
        #     data_info_level = b'\x30\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x27\x00\x00\x00\x01\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x00\x6c\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x24\x00\x5c\x00\x5c\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00\x64\x00\x00\x00\x00\x88\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\x00\x12\x00\x80\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x78\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x00\x65\x00\x73\x00\x74\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00\x00\x69\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01\x30\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x00\x58\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x06\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x05\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x04\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00'
        #     data = data_first + data_info_level
        # ---- DEBUGGING ---- end

        # @@ net_state_sequence에 대해 state_info.fuzzs += 1을 할 수 있도록 소켓통신해줌
        if self.conn is not None:
            self.conn.send_state_sequence_for_update_fuzzs(exec_res.net_state_sequence)
            # print(f"[** DEBUG] send_state_sequence_for_update_fuzzs: {exec_res.net_state_sequence}") # @@ 디버깅용
        ################################ apply_net_state_sequence_to_bitmap ################################
        if self.config.directed:
            info["net_state_sequence"] = exec_res.net_state_sequence   # @@
            info["flag_list"] = exec_res.flag_list                     # @@
        else:
            info["net_state_sequence"] = {}
            info["flag_list"] = {}
        info["generating_net_state_id"] = self.target_state_id     # @@

        # print(f"[** EXECUTE] data after: {data}")
        # print(f"[** EXECUTE] flag_list:{exec_res.flag_list}")
        #print(f"[** DEBUG] generating_net_state_id={self.target_state_id}....is it same???") # @@ 디버깅용

        # net_state_sequence = exec_res.net_state_sequence
        # prev_state = 0
        # state_size = 256     #define STATE_SIZE   1 << 8  = 256
        # shift_size = 32768   #define SHIFT_SIZE   1 << 15 = 32768
        # for cur_state in net_state_sequence:
        #     map_ptr_idx = (prev_state * state_size + cur_state) % shift_size
        #     old_val = exec_res.cbuffer[map_ptr_idx] # @@ 디버깅용
        #     exec_res.cbuffer[map_ptr_idx] = (exec_res.cbuffer[map_ptr_idx] + 1) % 256  # overflow 방지 # 디버깅 필요
        #     new_val = exec_res.cbuffer[map_ptr_idx] # @@ 디버깅용
        #     #print(f"[** DEBUG] map_ptr_idx={map_ptr_idx}, prev={prev_state}, cur={cur_state}, val={old_val}→{new_val}") # @@ 디버깅용
        #     prev_state = cur_state
        ################################ apply_net_state_sequence_to_bitmap ################################
        # [for directed] start
        # to_va_hits = self._read_xdc_to_hits() # [for directed] QEMU가 수집한 to-VA 히트맵 읽기
        # # # === {to_VA,count} -> {to_RVA,count} (aux2에서 받은 imagebase/size 사용) ===
        # to_rva_counts = {}
        # if to_va_hits:
        #     base, size = self._get_image_info_from_exec_res(exec_res)  # <== aux2 경로
        #     #print(f"[** DEBUG] image_base=0x{base:x}, image_size=0x{size:x}") # @@ 디버깅용
        #     if base is not None and size:
        #         end = base + size
        #         for (to_va, c) in to_va_hits:
        #             if base <= to_va < end:
        #                 rva = to_va - base
        #                 to_rva_counts[rva] = to_rva_counts.get(rva, 0) + int(c)
        #                 #print(f"[** DEBUG] to_va 0x{to_va:x} -> to_rva 0x{rva:x}, cnt={c}") # @@ 디버깅용
        #             else:
        #                 #print(f"[** DEBUG] to_va 0x{to_va:x} out of range, ignoring") # @@ 디버깅용
        #                 pass
        # # Manager로 보낼 info에 실어두기
        # if to_rva_counts:
        #     # [(rva, cnt), ...] 형태로 정렬해서 보냄
        #     info["to_rva_counts"] = sorted(to_rva_counts.items())
        #     # (선택) 디버깅용으로 원본도 보고 싶으면 아래 주석 해제
        #     # info["image_base"] = base
        #     # info["image_size"] = size
        # # === end ===
        
        # [for directed] end
        # @@ to_rva_counts는 --directed 여부와 무관하게 항상 전달 (dg_score 계산을 위해)
        info["to_rva_counts"] = list(exec_res.to_rva_counts.items()) # @@ directed
        # info["to_rva_counts"] = sorted(exec_res.to_rva_counts.items()) # @@ directed
        # print(f"[** @@ worker...exec_res.to_rva_counts] {exec_res.to_rva_counts}")

        # check if we have a new bitmap 
        is_new_input, is_new_bytes = self.bitmap_storage.should_send_to_manager(exec_res, exec_res.exit_reason)
        crash = exec_res.is_crash()
        stable = False

        # -trace_cb causes slower execution and different bitmap computation
        # if both -trace and -trace_cb is provided, we must delay tracing to calibration stage
        trace_pt = self.config.trace and not self.config.trace_cb

        if is_multi_irp and is_new_input and exec_res.exit_reason == "regular":
            is_new_input = is_new_bytes
            
        # store crashes and any validated new behavior
        # do not validate timeouts and crashes at this point as they tend to be nondeterministic
        if is_new_input:
            if not crash:
                assert exec_res.is_lut_applied()
                # print(f"[** DEBUG {self.pid} worker.execute] new_input detected")

                # 새로운 input이고 crash가 아니라면, quick_validate() 를 통해 결과의 안정성(stable) 검증
                stable, runtime = self.quick_validate(data, exec_res, trace=trace_pt, label=label)
                exec_res.performance = (exec_res.performance + runtime)/2
                # print(f"[** DEBUG {self.pid} worker.execute] quick_validate: stable={stable}") # @@ 디버깅용

                if trace_pt and stable:
                    trace_in = "%s/pt_trace_dump_%d" % (self.config.workdir, self.pid)
                    if os.path.exists(trace_in):
                        with tempfile.NamedTemporaryFile(delete=False,dir=self.config.workdir + "/traces") as f:
                            shutil.move(trace_in, f.name)
                            info['pt_dump'] = f.name

                if not stable:
                    # TO DO: auto-throttle persistent runs based on funky rate?
                    self.logger.debug("Input validation failed! Target funky?..")
                    self.statistics.event_funky()
            # Timeout일 경우 추가 확인: 느린 input들이 soft timeout 되는 것을 구제하기 위한 로직
            if exec_res.exit_reason == "timeout" and not hard_timeout:
                # re-run payload with max timeout
                # can be quite slow, so we only do this if prior run has some new edges or t_check=True.
                # t_dyn should grow over time and eventually include slower inputs up to max timeout
                maybe_new_regular = self.bitmap_storage.should_send_to_manager(exec_res, "regular")
                if self.t_check or maybe_new_regular:
                    dyn_timeout = self.q.get_timeout()
                    self.q.set_timeout(self.t_hard)
                    # if still new, register the payload as regular or (true) timeout
                    exec_res, is_new = self.execute(data, info, hard_timeout=True)
                    self.q.set_timeout(dyn_timeout)
                    if is_new and exec_res.exit_reason != "timeout":
                        self.logger.debug("Timeout checker found non-timeout with runtime %f >= %f!" % (exec_res.performance, dyn_timeout))
                    else:
                        # uselessly spend time validating a soft-timeout
                        # log it so user may adjust soft-timeout handling
                        self.statistics.event_reload("slow")
                    # sub-call to execute() has submitted the payload if relevant, so we can just return its result here
                    return exec_res, is_new
            # Crash가 발생했다면 로그에 저장
            if crash and self.config.log_crashes:
                self.q.store_crashlogs(exec_res.exit_reason, exec_res.hash())

            if stable: # stable == 다시 실행했을 때 동일한 비트맵을 갖다
                self.__send_to_manager(data, exec_res, info, label) # 바로 Manager에게 NEW_INPUT으로 전송
                #print(f"[** DEBUG worker.execute] send_to_manager: stable input")
            elif crash:
                self.logger.critical(PREFIX+"[+] crash found"+ENDC)
                info['qemu_id'] = str(self.q.process.pid)
                if self.config.use_call_stack:
                    self.__send_to_manager(data, exec_res, info, label)
                    #print(f"[** DEBUG worker.execute] send_to_manager: crash input (use_call_stack)")
                else:
                    if self.crash_validate(data, exec_res) is True:
                        self.logger.critical(PREFIX+"[+] crash validate success"+ENDC)
                        self.store_funky(data)
                        
                        refined_data, diet_error = self.quick_crash_diet(data)

                        if diet_error:
                            self.logger.critical(PREFIX+"[+] diet success"+ENDC)
                            self.__send_to_manager(refined_data, exec_res, info, label)
                            #print(f"[** DEBUG worker.execute] send_to_manager: crash input (diet success)")
                        elif diet_error is False:
                            self.logger.critical(PREFIX+"[-] but there is diet error"+ENDC)
                            #print('there is diet error')
                            self.__send_to_manager(data, exec_res, info, label)
                            #print(f"[** DEBUG worker.execute] send_to_manager: crash input (but diet error)")
                        else:
                            assert(0==1), self.logger.critical(PREFIX+"[-] this code never be executed"+ENDC)
                    else:
                        ## it is not crash ##
                        self.store_funky(data)
                        is_new_input = False
                        exec_res.exit_reason = "regular"
                        self.logger.critical(PREFIX+"[-] crash validate failed"+ENDC)
                        return exec_res, is_new_input
                    # else:
                    #     self.__send_to_manager(data, exec_res, info)
            elif exec_res.exit_reason == "timeout":
                #print(f"[** DEBUG worker.execute] timeout input, but not stable")
                return exec_res, is_new_input
            
            elif exec_res.exit_reason == 'regular':
                #print(f"[** DEBUG worker.execute] regular input, but not stable")
                return exec_res, is_new_input
            else:
                assert(0==1),self.logger.critical("[-] this code region never be executed")

        # restart Qemu on crash
        if crash:
            self.statistics.event_reload(exec_res.exit_reason)
            self.q.reload()

        return exec_res, is_new_input