# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by kAFL-Fuzzer.
"""

import ctypes
import mmap
import os
import socket
import subprocess
import sys
import time
import shutil
import logging
import struct

from kafl_fuzzer.common.util import strdump, print_hprintf
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxBuffer, QemuAuxBuffer2
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxRC as RC
from kafl_fuzzer.common.logger import WorkerLogAdapter
from kafl_fuzzer.common.config.settings import INTEL_PT_MAX_RANGES

class QemuIOException(Exception):
        """Exception raised when Qemu interaction fails"""
        pass

class qemu:
    payload_header_size = 4 # must correspond to set_payload() and nyx_api.h


    def __init__(self, pid, config, debug_mode=False, notifiers=True, resume=False):

        self.debug_mode = debug_mode
        self.ijonmap_size = 0x1000 # quick fix - bitmaps are not processed!
        self.to_buffer_size = 0x400000  # @@ directed 640KB*4
        self.bitmap_size = config.bitmap_size
        self.payload_size = config.payload_size
        self.payload_limit = config.payload_size - qemu.payload_header_size
        self.config = config
        self.pid = pid
        self.alt_bitmap = bytearray(self.bitmap_size)
        self.alt_edges = 0
        self.bb_seen = 0
        self.logger_no_prefix = logging.getLogger(__name__)
        self.logger = WorkerLogAdapter(self.logger_no_prefix, {'pid': self.pid})

        self.process = None
        self.control = None
        self.exiting = False
        self.persistent_runs = 0

        workdir = self.config.workdir

        self.qemu_aux_buffer_filename = workdir + "/aux_buffer_%d" % self.pid
        self.qemu_aux_buffer2_filename = workdir + "/aux_buffer2_%d" % self.pid  # @@ state_sequence용 버퍼

        self.bitmap_filename = workdir + "/bitmap_%d" % self.pid
        self.ijonmap_filename = workdir + "/ijon_%d" % self.pid
        self.to_buffer_filename = workdir + "/to_buffer_%d" % self.pid  # @@ directed
        self.payload_filename = workdir + "/payload_%d" % self.pid
        self.control_filename = workdir + "/interface_%d" % self.pid
        self.qemu_trace_log = workdir + "/qemu_trace_%02d.log" % self.pid
        self.serial_logfile = workdir + "/serial_%02d.log" % self.pid
        self.hprintf_log = self.config.log_hprintf or self.config.log_crashes
        self.hprintf_logfile = workdir + "/hprintf_%02d.log" % self.pid

        self.redqueen_workdir = RedqueenWorkdir(self.pid, config)
        self.redqueen_workdir.init_dir()

        if not resume:
            for page_cache_ext in ["lock", "dump", "addr"]:
                with open(self.config.workdir + "/page_cache." + page_cache_ext, 'w') as f:
                    f.truncate(0)

        # TO DO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd = self.config.qemu_base
        self.cmd += " -chardev socket,server,id=nyx_socket,path=" + self.control_filename + \
                    " -device nyx,chardev=nyx_socket" + \
                    ",workdir=" + workdir + \
                    ",worker_id=%d" % self.pid + \
                    ",bitmap_size=" + str(self.bitmap_size) + \
                    ",input_buffer_size=" + str(self.payload_size)

        if self.config.trace:
            self.cmd += ",dump_pt_trace"

        if self.config.trace_cb:
            self.cmd += ",edge_cb_trace"

        if self.config.sharedir:
            self.cmd += ",sharedir=" + self.config.sharedir

        for i in range(INTEL_PT_MAX_RANGES):
            if self.config[f"ip{i}"]:
                range_a = hex(self.config[f"ip{i}"][0]).replace("L", "")
                range_b = hex(self.config[f"ip{i}"][1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b

        self.cmd = [_f for _f in self.cmd.split(" ") if _f]

        if self.config.qemu_serial:
            # config.qemu_serial should just contain the device(s) to emulate, with id=kafl_serial
            self.cmd.extend(self.config.qemu_serial.split(" "))
            self.cmd.extend(["-chardev", "file,id=kafl_serial,mux=on,path=" + self.serial_logfile])

        self.cmd.extend(["-m", str(config.qemu_memory)])

        if self.config.log:
            self.cmd.extend(["-D", self.qemu_trace_log])
            if self.config.debug:
                self.cmd.extend(["-d", "nyx"])
                #self.cmd.extend(["-d", "kafl,trace:kvm*"])

        if self.config.gdbserver:
            self.cmd.extend(["-s", "-S"])

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.qemu_image:
            self.cmd.extend(["-drive", "file=" + self.config.qemu_image])
        if self.config.qemu_kernel:
            self.cmd.extend(["-kernel", self.config.qemu_kernel])
            if self.config.qemu_initrd:
                self.cmd.extend(["-initrd", self.config.qemu_initrd])
        if self.config.qemu_bios:
            self.cmd.extend(["-bios", self.config.qemu_bios])

        # Qemu -append option
        if self.config.qemu_append:
            self.cmd.extend(["-append", self.config.qemu_append])

        # Qemu extra options
        if self.config.qemu_extra:
            self.cmd.extend(self.config.qemu_extra.split(" "))

        # Fast VM snapshot configuration
        self.cmd.append("-fast_vm_reload")
        snapshot_path = workdir + "/snapshot/"

        if pid == 0 or pid == 1337 and not resume:
            # boot and create snapshot
            if self.config.qemu_snapshot:
                self.cmd.append("path=%s,load=off,pre_path=%s" % (snapshot_path, self.config.qemu_snapshot))
            else:
                self.cmd.append("path=%s,load=off" % snapshot_path)
        else:
            # boot and wait for snapshot creation (or load from existing file)
            self.cmd.append("path=%s,load=on" % (snapshot_path))

    # Asynchronous exit by Worker. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()


    def shutdown(self):
        self.logger.info("Shutting down Qemu after %d execs..", self.persistent_runs)

        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = ""
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        self.logger.debug(f"Qemu exit code: {self.process.returncode}")

        if len(output) > 0:
            header = "\n=================<%s Console Output>==================\n" %self
            footer = "====================</Console Output>======================\n"
            self.logger.info(header + output + footer)

        try:
            self.kafl_shm.close()
        except (BufferError, AttributeError):
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass
        
        try:
            os.close(self.to_buffer_shm_f)  # @@ directed
        except:
            pass

        for tmp_file in [
                self.qemu_aux_buffer_filename,
                self.qemu_aux_buffer2_filename,  # @@
                self.payload_filename,
                self.control_filename,
                self.ijonmap_filename,
                self.to_buffer_filename,  # @@ directed
                self.bitmap_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass

        self.redqueen_workdir.rmtree()
        return self.process.returncode

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0

        # SHM files must exist on Qemu launch (QEMU가 부팅 시 로딩)
        self.ijon_shm_f     = os.open(self.ijonmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT) # IJON용 비트맵
        self.to_buffer_shm_f = os.open(self.to_buffer_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT) # TO_BUFFER용 비트맵  # @@ directed
        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)  # 실행 커버리지 (bitmap)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT) # QEMU에 전달할 입력 데이터 -> qemu.py::set_payload()

        os.ftruncate(self.ijon_shm_f, self.ijonmap_size)
        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, self.payload_size)
        os.ftruncate(self.to_buffer_shm_f, self.to_buffer_size)  # @@ directed

        if self.pid not in [0, 1337]:
            final_cmdline = ""
        else:
            final_cmdline = "\n" + self.config.qemu_path
            for arg in self.cmd:
                if arg[0] == '-':
                    final_cmdline += '\n\t' + arg
                else:
                    final_cmdline += ' ' + arg

        # delayed Qemu startup - some nasty race condition when launching too many at once
        if self.pid not in [0, 1337]:
            time.sleep(4 + 0.1*self.pid)

        self.logger.info("Launching virtual machine...%s", final_cmdline)


        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen([self.config.qemu_path] + self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.DEVNULL)
                #stdin=subprocess.PIPE,
                #stdout=subprocess.PIPE,
                #stderr=subprocess.STDOUT)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError, QemuIOException) as e:
            if not self.exiting:
                self.logger.error("Failed to connect to Qemu: %s", str(e))
                self.async_exit()
            return False

        self.logger.debug("Handshake done.")

        # for -R = {0,1}, set reload_mode here just once
        if self.config['reload'] == 1:
            self.qemu_aux_buffer.set_reload_mode(True)
        else:
            self.qemu_aux_buffer.set_reload_mode(False)
        self.qemu_aux_buffer.set_timeout(self.config.timeout_hard)

        return True

    # release Qemu and wait for it to return
    def run_qemu(self):
        self.control.send(b'x')
        self.control.recv(1)

    def wait_qemu(self):
        self.control.recv(1)

    def __qemu_handshake(self):

        self.wait_qemu()

        self.qemu_aux_buffer = QemuAuxBuffer(self.qemu_aux_buffer_filename)
        self.qemu_aux_buffer2 = QemuAuxBuffer2(self.qemu_aux_buffer2_filename) # @@
        if not self.qemu_aux_buffer.validate_header():
            self.logger.error("Invalid header in qemu_aux_buffer.py. Abort.")
            self.async_exit()
        if not self.qemu_aux_buffer2.validate_header():  # @@
            self.logger.error("Invalid header in qemu_aux_buffer2.py. Abort.")
            self.async_exit()

        while self.qemu_aux_buffer.get_state() != 3:
            self.logger.debug("Waiting for target to enter fuzz mode..")
            result = self.qemu_aux_buffer.get_result()
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
            self.run_qemu()

        # Qemu tends to truncate / resize the files. Not sure why..
        assert(self.payload_size == os.path.getsize(self.payload_filename))
        assert(self.bitmap_size == os.path.getsize(self.bitmap_filename))
        assert(self.ijonmap_size == os.path.getsize(self.ijonmap_filename))
        assert(self.to_buffer_size == os.path.getsize(self.to_buffer_filename))  # @@ directed
        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)
        self.to_buffer_shm = mmap.mmap(self.to_buffer_shm_f, 0)  # @@ directed

    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # Wait for the socket to appear. Fail early if Qemu is done and we get no socket.
        retry_timeout = 20
        retry_interval = 0.2
        for _ in range(int(retry_timeout/retry_interval)):
            try:
                self.control.connect(self.control_filename)
                return True
            except socket.error as e:
                if self.process.poll() is not None:
                    self.logger.error("Aborting due to unexpected Qemu exit.")
                    raise e
            self.logger.debug("Waiting for Qemu connect..")
            time.sleep(retry_interval)

    def store_crashlogs(self, label, stamp):
        # Collect current/accumulated logs
        # We don't have a payload ID yet and in fact manager may refuse to store
        if self.hprintf_log and os.path.exists(self.hprintf_logfile):
            if os.path.getsize(self.hprintf_logfile) > 0:
                shutil.copy(self.hprintf_logfile, "%s/logs/%s_%s.log" % (
                    self.config.workdir, label[:5], stamp[:6]))
                os.truncate(self.hprintf_logfile, 0)

    def flush_crashlogs(self):
        if self.hprintf_log and os.path.exists(self.hprintf_logfile):
            os.truncate(self.hprintf_logfile, 0)

    def handle_hprintf(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')

        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)
        elif not self.config.quiet:
            print_hprintf(msg)

    def handle_habort(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')
        msg = "Guest ABORT: %s" % msg

        self.logger.error(msg)
        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)

        raise QemuIOException(msg)

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):
        # Nyx backend does not tend to die anymore so this is a NOP
        # To enable recovery again, new Qemu instances must respect the snapshot
        # settings and avoid overwriting a possibly existing snapshot
        return True

    # Reset Qemu after crash/timeout - not required anymore
    def reload(self):
        return True

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self):

        self.set_timeout(0)
        #self.send_payload()
        while True:
            self.run_qemu()
            result = self.qemu_aux_buffer.get_result()
            result2 = self.qemu_aux_buffer2.get_result() # @@
            if result.page_fault:
                self.logger.warn("Unhandled page fault in debug mode!")
            if result.pt_overflow:
                self.logger.warn("PT overflow!")
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_done:
                break

        self.logger.info("Result: %s\n", self.exit_reason(result))
        #self.audit(result)
        return result

    def _process_to_buffer(self, T_IMG_base): # @@ directed
        """
        'to_buffer_shm'에서 'to' 주소들을 읽어 T_IMG_base를 기준으로 RVA로 변환하고 각 RVA의 등장 횟수를 카운트
        {to_rva, counts} 딕셔너리를 반환
        버퍼 구조:
        - 0x00 (8 bytes): 카운터 (저장된 주소의 총 개수)
        - 0x08 (8 bytes): to_addr 1
        - 0x10 (8 bytes): to_addr 2
        - ...
        """
        rva_counts = {}
        
        if not hasattr(self, 'to_buffer_shm'):
            self.logger.warning("[-] to_buffer_shm이 mmap되지 않았습니다. RVA 리스트가 비어있습니다.")
            return rva_counts

        try:
            # 1. 버퍼의 첫 8바이트를 읽어 카운터를 가져옵니다.
            self.to_buffer_shm.seek(0)
            count_data = self.to_buffer_shm.read(8)
            count = struct.unpack('<Q', count_data)[0] # '<Q' = little-endian 64-bit unsigned int
            # print(f"[*] count: {count}")
            
            # 버퍼 크기 (0x10000 = 65536 바이트)
            # (65536 / 8) - 1 = 8191. 카운터가 이보다 크면 버퍼 오버플로우입니다.
            max_entries = (self.to_buffer_size // 8) - 1
            if count > max_entries:
                self.logger.warning(f"[-] to_buffer 오버플로우 감지! 카운터: {count}, 최대: {max_entries}")
                count = max_entries # 오버플로우된 데이터는 무시하고, 꽉 찬 버퍼까지만 읽음
            
            # 2. 카운터 개수만큼 주소를 읽어 RVA로 변환하고 카운트합니다.
            for i in range(count):
                # seek()는 필요 없음, read()가 파일 포인터를 이동시킴
                addr_data = self.to_buffer_shm.read(8)
                if len(addr_data) < 8:
                    break # 버퍼가 예기치 않게 끝남
                    
                to_addr = struct.unpack('<Q', addr_data)[0]
                to_rva = to_addr - T_IMG_base
                if to_rva < 0:
                    # print(f"\t[* Warning.. to_addr < T_IMG_base] to_addr: {to_addr}")
                    to_rva = 0
                
                # RVA 카운트
                rva_counts[to_rva] = rva_counts.get(to_rva, 0) + 1

        except Exception as e:
            self.logger.error(f"[-] to_buffer 처리 중 오류 발생: {e}")

        return rva_counts

    def send_payload(self):

        if self.exiting:
            sys.exit(0)

        # for -R > 1, count and toggle reload_mode at runtime
        # note the special syntax for config['reload'] due to dynaconfig internals
        if self.config['reload'] > 1:
            self.persistent_runs += 1
            if self.persistent_runs == 1:
                self.qemu_aux_buffer.set_reload_mode(False)
                self.qemu_aux_buffer2.set_reload_mode(False) # @@ 이게 필요한건지 확인 필요
            if self.persistent_runs >= self.config['reload']:
                self.qemu_aux_buffer.set_reload_mode(True)
                self.qemu_aux_buffer2.set_reload_mode(True) # @@ 이게 필요한건지 확인 필요
                self.persistent_runs = 0

        if self.config.log_crashes and self.persistent_runs == 0:
            # flush crashlogs after VM state reset (persistent_runs=0)
            self.flush_crashlogs()

        result = None
        old_address = 0
        start_time = time.time()

        while True:
            self.run_qemu()

            result = self.qemu_aux_buffer.get_result()
            # net_state_sequence, flag_list = self.qemu_aux_buffer2.get_result() # @@
            net_state_sequence, flag_list, T_IMG_base, T_IMG_size = self.qemu_aux_buffer2.get_result() # @@
            # print(f"[** qemu] state_sequence: {net_state_sequence}, flags: {flag_list}")  # @@

            if result.pt_overflow:
                self.logger.debug("PT overflow!")

            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue

            if result.exec_code == RC.ABORT:
                self.handle_habort()

            if result.exec_done:
                break

            if result.page_fault:
                self.logger.debug("Page fault encountered!")
                if result.page_fault_addr == old_address:
                    self.logger.error("Failed to resolve page after second execution! Qemu status:\n%s", str(result._asdict()))
                    break
                old_address = result.page_fault_addr
                self.qemu_aux_buffer.dump_page(result.page_fault_addr)

        # record highest seen BBs
        self.bb_seen = max(self.bb_seen, result.bb_cov)

        to_rva_counts = self._process_to_buffer(T_IMG_base)  # @@ directed
        # print(f"[** @@@@@ qemu] T_IMG_base: {hex(T_IMG_base)}")  # @@ directed
        # print(f"[** @@@@@ qemu] T_IMG_size: {hex(T_IMG_size)}")  # @@ directed
        # print(f"[** @@@@@ qemu] to_rva_counts: {to_rva_counts}")  # @@ directed
        
        #runtime = result.runtime_sec + result.runtime_usec/1000/1000
        res = ExecutionResult(
                self.c_bitmap,              # SHM으로부터 읽은 coverage bitmap
                self.bitmap_size,
                self.exit_reason(result),   # 종료 사유 (timeout, crash 등)
                time.time() - start_time,   # Qemu에서 측정한 실행 시간
                starved = result.exec_code == RC.STARVED,
                trashed = result.pt_overflow,
                net_state_sequence = net_state_sequence, # @@
                flag_list = flag_list,
                T_IMG_base = T_IMG_base,
                T_IMG_size = T_IMG_size,
                to_rva_counts = to_rva_counts)  # @@ directed

        #self.audit(res.copy_to_array())
        #self.audit(bytearray(self.c_bitmap))
        return res

    def audit(self, bitmap):

        if len(bitmap) != self.bitmap_size:
            self.logger.info("bitmap size: %d" % len(bitmap))

        new_bytes = 0
        new_bits = 0
        for idx in range(self.bitmap_size):
            if bitmap[idx] != 0x00:
                if self.alt_bitmap[idx] == 0x00:
                    self.alt_bitmap[idx] = bitmap[idx]
                    new_bytes += 1
                else:
                    new_bits += 1
        if new_bytes > 0:
            self.alt_edges += new_bytes;
            self.logger.info("New bytes: %03d, bits: %03d, total edges seen: %03d", new_bytes, new_bits, self.alt_edges)


    def exit_reason(self, result):
        if result.exec_code == RC.CRASH:
            return "crash"
        if result.exec_code == RC.TIMEOUT:
            return "timeout"
        elif result.exec_code == RC.SANITIZER:
            return "kasan"
        elif result.exec_code == RC.SUCCESS:
            return "regular"
        elif result.exec_code == RC.STARVED:
            return "regular"
        else:
            raise QemuIOException("Unknown QemuAuxRC code")

    def set_timeout(self, timeout):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_timeout(timeout)

    def get_timeout(self):
        return self.qemu_aux_buffer.get_timeout()

    def set_trace_mode(self, enable):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_trace_mode(enable)

    def get_payload_limit(self):
        return self.payload_limit

    def set_payload(self, payload):
        # Ensure the payload fits into SHM. Caller has to cut off since they also report findings.
        # actual payload is limited to payload_size - sizeof(uint32) - sizeof(uint8)
        assert(len(payload) <= self.payload_limit), "Payload size %d > SHM limit %d. Check size/shm config" % (len(payload),self.payload_limit)
        # self.logger.info("payload length: %d" % len(payload))
        # self.logger.info("payload: %s" % payload)
        #if len(payload) > self.payload_limit:
        #    payload = payload[:self.payload_limit]
        try:
            # TODO len(payload) - 4로 payload의 첫 4byte(NBSS 길이 필드) 변경하기
            # print(f"[** qemu.set_payload] before... NBSS field: {struct.unpack('<I', payload[:4])[0]}")
            # payload = struct.pack("<I", len(payload) - 4) + payload[4:] # 디버깅 필요
            # print(f"[** qemu.set_payload] after...NBSS field: {struct.unpack('<I', payload[:4])[0]}, payload length: {len(payload)}")
            self.fs_shm.seek(0)
            header = struct.pack("<I", len(payload))  # @@ payload 길이 추가
            self.fs_shm.write(header + payload)       # @@ payload 길이 추가
            self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            self.logger.error("Failed to set new payload - Qemu crash?")
            raise
