# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Main logic used by Worker to push nodes through various fuzzing stages/mutators.
"""

import time
import datetime

from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.technique.redqueen.colorize import ColorizerStrategy
from kafl_fuzzer.technique.redqueen.mod import RedqueenInfoGatherer
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.technique import bitflip, arithmetic, interesting_values, havoc

from kafl_fuzzer.common.util import irp_list, add_to_message_list, serialize, parse_header_and_data, serialize_sangjun
from kafl_fuzzer.network.region import extract_m2_region, calculate_redqueen_range
from kafl_fuzzer.manager.node import QueueNode


class FuzzingStateLogic:
    HAVOC_MULTIPLIER = 4
    RADAMSA_DIV = 10
    COLORIZATION_COUNT = 1
    COLORIZATION_STEPS = 1500
    COLORIZATION_TIMEOUT = 5

    def __init__(self, worker, config):
        self.worker = worker
        self.logger = self.worker.logger
        self.config = config
        havoc.init_havoc(config)

        self.stage_info = {}
        self.stage_info_start_time = None
        self.stage_info_execs = None
        self.stage_info_findings = 0
        self.attention_secs_start = None
        self.attention_execs_start = None

    def __str__(self):
        return str(self.worker)

    def create_limiter_map(self, payload):
        limiter_map = bytearray([1 for _ in range(len(payload))])
        if self.config.afl_skip_range:
            for ignores in self.config.afl_skip_range:
                self.logger.debug("AFL ignore-range 0: " + str(ignores[0]) + " " + str(min(ignores[0], len(payload))))
                self.logger.debug("AFL ignore-range 1: " + str(ignores[1]) + " " + str(min(ignores[1], len(payload))))
                for i in range(min(ignores[0], len(payload)), min(ignores[1], len(payload))):
                    limiter_map[i] = 0

        return limiter_map

    def stage_timeout_reached(self, limit=20):
        if time.time() - self.stage_info_start_time > limit:
            return True
        else:
            return False

    # 현재 단계의 실행 시간, 실행 횟수, 성능, 상태 정보 등을 dictionary로 묶어 반환 
    def create_update(self, new_state, additional_data):
        ret = {}
        ret["state"] = new_state
        ret["attention_execs"] = self.stage_info_execs
        ret["attention_secs"] = time.time() - self.stage_info_start_time
        ret["state_time_initial"] = self.initial_time
        ret["state_time_havoc"] = self.havoc_time
        ret["state_time_splice"] = self.splice_time
        ret["state_time_radamsa"] = self.radamsa_time
        ret["state_time_grimoire"] = self.grimoire_time
        ret["state_time_grimoire_inference"] = self.grimoire_inference_time
        ret["state_time_redqueen"] = self.redqueen_time
        ret["performance"] = self.performance

        if additional_data:
            ret.update(additional_data)

        return ret          # Manager에게 전송할 데이터 구조 생성

    # import seed 처리 로직 (node 만들기 전)
    def process_import(self, payload, metadata):
        self.init_stage_info(metadata)
        add_to_message_list(irp_list, payload) # add_to_irp_list(irp_list, payload)
        #target = irp_list[0]
        #print(f"payload is {target.Command} {hex(target.IoControlCode)} {hex(target.InBuffer_length)}")
        #import time
        #time.sleep(1)
        self.handle_import(metadata)

    def process_kickstart(self, kick_len):
        return

    # Manager에게 받은 하나의 node를 다양한 단계의 fuzzing 스테이지를 통해 처리하고, 어떤 스테이지에서 어떤 결과(신규 입력, 성능 등)가 나왔는지 업데이트 정보 생성
    def process_node(self, payload, metadata):
        self.init_stage_info(metadata)
        tmp = self.stage_info["stage"]
        # print(f"[** DEBUG] {tmp}")

        # payload를 add_to_irp_list()로 전역 irp_list에 저장 → 각 단계에서 여기에 직접 mutation
        # node = QueueNode(self.config, payload, bitmap=None, node_struct=metadata, write=False) # @@
        add_to_message_list(irp_list, payload) # add_to_irp_list(irp_list, payload, node)
        print(f"[*** Worker process_node] {datetime.datetime.now()}.. node {metadata['id']}, {metadata['state']['name']}") # @@
        # metadata["state"]["name"] 값에 따라 처리 로직이 다름
        if metadata["state"]["name"] == "initial":      # calibrate 단계: 입력을 랜덤하게 여러 번 실행해서 평균 실행 시간(성능)을 추정
            # print("[** DEBUG] goto initial")
            new_payload = self.handle_initial(metadata) # trace_cb가 설정되어 있으면 trace_payload, havoc.mutate_seq_havoc_array()로 빠른 변화 주고 성능 측정
            return self.create_update({"name": "redq/grim"}, None), new_payload # state를 "redq/grim"으로 전환
            # return self.create_update({"name": "deterministic"}, None), new_payload # redq보다 deterministic 먼저 @@
        elif metadata["state"]["name"] == "redq/grim":
            # print("[** DEBUG] goto redq/grim")
            grimoire_info = self.handle_grimoire_inference(payload, metadata)
            self.handle_redqueen(metadata)              # RedQueen 기법 수행 → 타겟이 어떤 조건 분기를 사용하는지 알아내고 추론/우회
            return self.create_update({"name": "deterministic"}, {"grimoire": grimoire_info}), None # 실행 후 "deterministic" 단계로 이동
            # return self.create_update({"name": "havoc"}, {"grimoire": grimoire_info}), None # @@
        elif metadata["state"]["name"] == "deterministic":              # AFL의 기본 mutation 기법들 수행: 비트 플립, 산술 연산, 관심 값 대입 등
            # print("[** DEBUG] goto inter")
            resume, afl_det_info = self.handle_deterministic(metadata)  # 내부에서 단계별로 bitflip, arithmetic, interesting_values 호출
            if resume:
                return self.create_update({"name": "deterministic"}, {"afl_det_info": afl_det_info}), None # afl_det_info를 통해 진행 상태 기억 → resume 기능 가능
            return self.create_update({"name": "havoc"}, {"afl_det_info": afl_det_info}), None
            # return self.create_update({"name": "redq/grim"}, {"afl_det_info": afl_det_info}), None # @@ deterministic 다음 redq/grim
        elif metadata["state"]["name"] == "havoc":  # 비정형 무작위 입력을 대량으로 생성하여 fuzzing
            # print("[** DEBUG] goto havoc")
            self.handle_havoc(metadata)             # 다양한 mutation 기법을 조합: havoc, splicing, dependency, argv mutation 등
            return self.create_update({"name": "final"}, None), None
        elif metadata["state"]["name"] == "final":  # final == havoc 반복, 이후 다시 queue에 넣을지 말지는 Manager가 결정
            # print("[** DEBUG] goto final")
            self.handle_havoc(metadata)
            return self.create_update({"name": "final"}, None), None
        else:
            raise ValueError("Unknown task stage %s" % metadata["state"]["name"])

    def init_stage_info(self, metadata, verbose=False):
        stage = metadata["state"]["name"]
        nid = metadata["id"]
        
        if metadata.get("init_seed_id") is not None:
            init_seed_id = metadata["init_seed_id"]
        else:
            init_seed_id = metadata["info"]["init_seed_id"]

        self.stage_info["init_seed_id"] = init_seed_id # @@
        self.stage_info["stage"] = stage
        self.stage_info["parent"] = nid
        self.stage_info["method"] = "fixme"

        self.stage_info_start_time = time.time()
        self.stage_info_execs = 0
        self.attention_secs_start = metadata.get("attention_secs", 0)
        self.attention_execs_start = metadata.get("attention_execs", 0)
        self.performance = metadata.get("performance", 0)

        self.initial_time = 0
        self.havoc_time = 0
        self.splice_time = 0
        self.radamsa_time = 0
        self.grimoire_time = 0
        self.grimoire_inference_time = 0
        self.redqueen_time = 0

        self.worker.statistics.event_stage(stage, nid)

    def stage_update_label(self, method):
        self.stage_info["method"] = method
        self.worker.statistics.event_method(method)

    def get_parent_info(self, extra_info=None):
        info = self.stage_info.copy()
        info["parent_execs"] = self.attention_execs_start + self.stage_info_execs
        info["parent_secs"]  = self.attention_secs_start  + time.time() - self.stage_info_start_time

        if extra_info:
            info.update(extra_info)
        return info

    def handle_import(self, metadata):
        # for funky targets, retry seed a couple times to avoid false negatives
        retries = 1
        if self.config.funky:
            retries = 8

        for _ in range(retries):
            _, is_new = self.execute(irp_list, label="import")
            if is_new: break

        # Inform user if seed yields no new coverage. This may happen if -ip0 is
        # wrong or the harness is buggy.
        if not is_new:
            self.logger.debug("Imported payload produced no new coverage, skipping..")

    # def handle_kickstart(self, kick_len, metadata):
    #     # random injection loop to kickstart corpus with no seeds, or to scan/test a target
    #     busy_timeout = 5
    #     start_time = time.time()
    #     while (time.time() - start_time) < busy_timeout:
    #         payload = rand.bytes(kick_len)
    #         self.execute(payload, label="kickstart")

    def handle_initial(self, metadata):
        if self.config.trace_cb: # trace_cb가 설정되어 있으면 트레이싱 수행 (trace_payload)
            self.stage_update_label("trace")
            payload, is_multi_irp = serialize(irp_list)
            self.worker.trace_payload(payload, metadata)
            
        self.stage_update_label("calibrate")
        # Update input performance using multiple randomized executions
        # Scheduler will de-prioritize execution of very slow nodes..
        num_execs = 10
        timer_start = time.time()

        target_state_id = metadata["target_state_id"]  # @@
        # for index in range(len(irp_list)):
        # print(f"[** DEBUG] node_id: {metadata['id']}") # @@ 디버깅용
        m2_region_id, m2_count, target_state_id = extract_m2_region(metadata, self.config, target_state_id) # @@
        if target_state_id:
            metadata["target_state_id"] = target_state_id
        for index in range(m2_region_id, m2_region_id + m2_count):   # @@ M2_region에 대해 havoc mutation 후 전체 리스트에 대해 execute
            havoc.mutate_seq_havoc_array(irp_list, index, self.execute, num_execs, mutation_part=self.config.mutation_part)
        timer_end = time.time()
        self.performance = (timer_end-timer_start) / num_execs

        # Trimming only for stable + non-crashing inputs
        if metadata["info"]["exit_reason"] != "regular": #  or metadata["info"]["stable"]:
            self.logger.debug("Validate: Skip trimming..")
            return None

        # if metadata['info']['starved']:
        #     return trim.perform_extend(payload, metadata, self.execute, self.worker.payload_limit)

        return None
        #new_payload = trim.perform_trim(payload, metadata, self.execute)

        # center_trim = True
        # if center_trim:
        #     new_payload = trim.perform_center_trim(new_payload, metadata, self.execute)

        # self.initial_time += time.time() - time_initial_start
        # if new_payload == payload:
        #     return None
        # #self.logger.debug("before trim:\t\t{}".format(repr(payload)), self)
        # #self.logger.debug("after trim:\t\t{}".format(repr(new_payload)), self)
        # return new_payload

    def handle_grimoire_inference(self, payload, metadata):
        grimoire_info = {}
        return grimoire_info
        


    def handle_redqueen(self, metadata):
        redqueen_start_time = time.time()
        if self.config.redqueen:
            self.__perform_redqueen(metadata)
        self.redqueen_time += time.time() - redqueen_start_time
        return
    
    def handle_havoc(self, metadata):
        havoc_afl = True
        havoc_splice = True
        havoc_dependency = True
        havoc_argv_mutate = False

        havoc_redqueen = self.config.redqueen

        for i in range(1):
            
            if havoc_redqueen:
                # self.__perform_rq_dict(metadata)
                # self.__perform_rq_dict_header(metadata)
                # self.__perform_rq_dict_header_v2(metadata)
                self.__perform_rq_dict_all_version(metadata)

            if self.worker.play_maker_mode:

                target_state_id = metadata["target_state_id"] # @@
                # for index in range(len(irp_list)):
                m2_region_id, m2_count, target_state_id = extract_m2_region(metadata, self.config, target_state_id) # @@
                if target_state_id:
                    metadata["target_state_id"] = target_state_id
                for index in range(m2_region_id, m2_region_id + m2_count):   # @@ M2_region에 대해 havoc mutation 후 전체 리스트에 대해 execute
                    if havoc_dependency:
                        self.__perform_havoc(irp_list, index, metadata, dependency_stage=True)
            else:
                target_state_id = metadata["target_state_id"] # @@
                # for index in range(len(irp_list)):
                m2_region_id, m2_count, target_state_id = extract_m2_region(metadata, self.config, target_state_id) # @@
                if target_state_id:
                    metadata["target_state_id"] = target_state_id
                for index in range(m2_region_id, m2_region_id + m2_count):   # @@ M2_region에 대해 havoc mutation 후 전체 리스트에 대해 execute
                    if havoc_afl:
                        havoc_start_time = time.time()
                        self.__perform_havoc(irp_list, index, metadata, use_splicing=False)
                        self.havoc_time += time.time() - havoc_start_time

                    if havoc_splice:
                        splice_start_time = time.time()
                        self.__perform_havoc(irp_list, index, metadata, use_splicing=True)
                        self.splice_time += time.time() - splice_start_time

                    if havoc_argv_mutate and self.config.interface:
                        self.__perform_havoc(irp_list, index, metadata, use_argv_mutate=False)
                

        self.logger.debug("HAVOC times: afl: %.1f, splice: %.1f, grim: %.1f, rdmsa: %.1f", self.havoc_time, self.splice_time, self.grimoire_time, self.radamsa_time)


    def validate_bytes(self, payload, metadata, extra_info=None):
        self.stage_info_execs += 1
        # FIXME: can we lift this function from worker to this class and avoid this wrapper?
        parent_info = self.get_parent_info(extra_info)
        return self.worker.validate_bytes(payload, metadata, parent_info)


    def execute(self, irp_list, label=None, extra_info=None):
        

        '''
        serailize all irps set before set payload and execute
        '''
        self.stage_info_execs += 1
        if label and label != self.stage_info["method"]:
            self.stage_update_label(label)

        parent_info = self.get_parent_info(extra_info)
        payload, is_multi_irp = serialize(irp_list)
        #print(f"HELLO : {payload}")
        if label == "import":
            bitmap, is_new = self.worker.execute(payload, parent_info, is_multi_irp=is_multi_irp, label=label)
        else:
            bitmap, is_new = self.worker.execute(payload, parent_info, is_multi_irp=is_multi_irp)
        if is_new:
            self.stage_info_findings += 1
        return bitmap, is_new

    # def execute_sangjun(self, headers, datas, label=None, extra_info=None): # mutate header version
    #     global irp_list

    #     '''
    #     serailize all irps set before set payload and execute
    #     '''
    #     self.stage_info_execs += 1
    #     if label and label != self.stage_info["method"]:
    #         self.stage_update_label(label)

    #     parent_info = self.get_parent_info(extra_info)
    #     payload, is_multi_irp = serialize_sangjun(headers, datas, irp_list)
    #     # print(f"############################### worker {self.worker.pid}...stage_info = {self.stage_info['method']}") # @@
    #     # if self.stage_info["method"] == "redq_color_coloring":  # redq_color, redq_color_coloring, redq_color_check_colorization, redq_color_coloring_bitmap_hash
    #     #     print(f"HELLO : [{len(payload)}] {payload}")
    #     bitmap, is_new = self.worker.execute(payload, parent_info, is_multi_irp=is_multi_irp)
    #     if is_new:
    #         self.stage_info_findings += 1
    #     return bitmap, is_new

    def execute_sangjun(self, static_part, mutated_part, label=None, extra_info=None): # all version
        global irp_list

        '''
        (static_part, mutated_part)를 (headers, datas)로 재조립하여 실행
        '''
        self.stage_info_execs += 1
        if label and label != self.stage_info["method"]:
            self.stage_update_label(label)

        parent_info = self.get_parent_info(extra_info)

        # --- (static, mutated) -> (header, data) 재조립 로직 ---
        mutation_part = self.config.mutation_part
        
        if mutation_part == "header":
            headers = mutated_part
            datas = static_part
        elif mutation_part == "body":
            headers = static_part
            datas = mutated_part
        elif mutation_part == "all":
            total_header_len = 0
            try:
                for irp in irp_list:
                    total_header_len += len(irp.header) 
            
            except Exception as e:
                # irp_list가 비어있거나, 객체가 손상된 경우
                print(f"[ERROR] Redqueen 'all' mode failed: irp_list empty or invalid: {e}")
                # 분리 불가능. 이 실행은 실패해야 함.
                headers = b""
                datas = b""

            if total_header_len > 0:
                # 총 헤더 길이를 기준으로 mutated_part를 분리합니다.
                headers = mutated_part[:total_header_len]
                datas = mutated_part[total_header_len:]
            
            elif len(mutated_part) == 0 and total_header_len == 0:
                # 정상적인 케이스 (빈 입력)
                headers = b""
                datas = b""
            else:
                # irp_list는 비어있는데(total_header_len=0),
                # mutated_part는 내용이 있는 경우 (로직 오류)
                print(f"[WARNING] Redqueen 'all' mode: No irp_list, but mutated_part exists. Executing empty payload.")
                headers = b""
                datas = b""
        # -----------------------------------------------------
        payload, is_multi_irp = serialize_sangjun(headers, datas, irp_list)
        # print(f"############################### worker {self.worker.pid}...stage_info = {self.stage_info['method']}") # @@
        bitmap, is_new = self.worker.execute(payload, parent_info, is_multi_irp=is_multi_irp)
        if is_new:
            self.stage_info_findings += 1
        return bitmap, is_new


    # def execute_redqueen(self, headers, datas):
    #     global irp_list
    #     # one regular execution to ensure all pages cached
    #     # also colored payload may yield new findings(?)
    #     self.execute_sangjun(headers, datas)
    #     return self.worker.execute_redqueen(headers, datas, irp_list)

    def execute_redqueen(self, static_part, mutated_part):
        global irp_list
        # one regular execution to ensure all pages cached
        # also colored payload may yield new findings(?)
        self.execute_sangjun(static_part, mutated_part)

        # --- (static, mutated) -> (header, data) 재조립 로직 ---
        mutation_part = self.config.mutation_part
        
        headers = b""
        datas = b""

        if mutation_part == "header":
            headers = mutated_part
            datas = static_part
        elif mutation_part == "body":
            headers = static_part
            datas = mutated_part
        elif mutation_part == "all":
            total_header_len = 0
            try:
                for irp in irp_list:
                    total_header_len += len(irp.header) 
            
            except Exception as e:
                print(f"[ERROR] Redqueen 'all' mode failed: irp_list empty or invalid: {e}")
                # headers, datas는 이미 b""로 초기화됨

            if total_header_len > 0:
                # 총 헤더 길이를 기준으로 mutated_part를 분리합니다.
                headers = mutated_part[:total_header_len]
                datas = mutated_part[total_header_len:]
            
            elif len(mutated_part) == 0 and total_header_len == 0:
                # 정상적인 케이스 (빈 입력)
                headers = b""
                datas = b""
            else:
                # irp_list는 비어있는데(total_header_len=0),
                # mutated_part는 내용이 있는 경우 (로직 오류)
                print(f"[WARNING] Redqueen 'all' mode: No irp_list, but mutated_part exists. Executing empty payload.")
                headers = b""
                datas = b""
        # -----------------------------------------------------
        return self.worker.execute_redqueen(headers, datas, irp_list)

    # def __get_bitmap_hash(self,  headers, datas):
    #     # bitmap, _ = self.execute_sangjun( headers, datas)      # original version
    #     bitmap, _ = self.execute_sangjun_swapped(headers, datas) # mutate header version
    #     if bitmap is None:
    #         return None
    #     return bitmap.hash()
    
    def __get_bitmap_hash(self, static_part, mutated_part):
        # execute_sangjun이 알아서 재조립하므로, 그대로 전달
        bitmap, _ = self.execute_sangjun(static_part, mutated_part)
        if bitmap is None:
            return None
        return bitmap.hash()


    def __get_bitmap_hash_robust(self, headers, datas):
        # all version: (headers = static_part, datas = mutated_part)
        hashes = {self.__get_bitmap_hash( headers, datas) for _ in range(3)}
        if len(hashes) == 1:
            return hashes.pop()
        # self.logger.warn("Hash doesn't seem stable")
        return None

    # def execute_sangjun_swapped(self, headers_from_rq, datas_from_rq, label=None, extra_info=None): # @@@@@@
    #     """
    #     Redqueen이 (static_part, mutated_payload)를 호출하면
    #     (mutated_payload, static_part) 순서로 execute_sangjun을 호출합니다.
        
    #     - headers_from_rq: static_part (원본 data)
    #     - datas_from_rq: payload_array (변이된 header)
    #     """
    #     # execute_sangjun의 (headers, datas) 시그니처에 맞게
    #     # (변이된 header, 원본 data) 순서로 전달합니다.
    #     return self.execute_sangjun(datas_from_rq, headers_from_rq, label=None, extra_info=None)

    # def execute_redqueen_swapped(self, datas, headers): # @@@@@@
    #     """
    #     execute_redqueen의 인자 순서를 바꿔서 호출합니다.
        
    #     - datas: static_part (원본 data)
    #     - headers: payload_array (변이된 header)
    #     """
    #     # (변이된 header, 원본 data) 순서로 전달
    #     return self.execute_redqueen(headers, datas)

    # def __get_bitmap_hash_robust_swapped(self, datas, headers): # @@@@@@
    #     """
    #     __get_bitmap_hash_robust의 인자 순서를 바꿔서 호출합니다.
    #     """
    #     # (변이된 header, 원본 data) 순서로 전달
    #     return self.__get_bitmap_hash_robust(headers, datas)

    # def __perform_coloring_swapped(self, datas, headers, orig_hash): # @@@@@@
    #     """
    #     __perform_coloring의 인자 순서를 바꿔서 호출합니다.
    #     """
    #     # (변이된 header, 원본 data) 순서로 전달
    #     return self.__perform_coloring(headers, datas, orig_hash)

    def __perform_redqueen(self, metadata):
        # print(f"@@@init... worker-{self.worker.pid}..node-{metadata['id']}.. stage_info[method]: {self.stage_info['method']}")
        self.stage_update_label("redq_color")
        global irp_list

        # headers, datas = parse_header_and_data(irp_list)
        # --- mutation_part에 따라 static/mutated 부분 결정 ---
        headers_orig, datas_orig = parse_header_and_data(irp_list) # @@@@@@
        # headers = datas_orig # @@@@@@
        # datas = headers_orig # @@@@@@ 헤더를 변이 대상으로 설정
        mutation_part = self.config.mutation_part
        if mutation_part == "header":
            static_part = bytes(datas_orig)   # 고정 = 바디
            mutated_part = headers_orig       # 변이 = 헤더
        elif mutation_part == "body":
            static_part = bytes(headers_orig) # 고정 = 헤더
            mutated_part = datas_orig         # 변이 = 바디
        elif mutation_part == "all":
            static_part = b""                 # 고정 = 없음
            mutated_part = headers_orig + datas_orig # 변이 = 전체
            # 'all'일 때 static_part를 어떻게 처리할지는 정책에 따라 다름.
            # 여기서는 'all'일 때 static_part가 없다고 가정함.
            # 만약 'all' 모드에서 원본 헤더 길이를 알아야 한다면,
            # execute_sangjun 등에서 irp_list[0].header_length 또는 len(irp_list[0].header)를 참조해야 함.

        # orig_hash = self.__get_bitmap_hash_robust(headers, datas)
        # --- extension 로직은 데이터 길이가 바뀌니까 삭제 -----
        # extension = bytes([207, 117, 130, 107, 183, 200, 143, 154])
        # # appended_hash = self.__get_bitmap_hash_robust(headers, datas + extension)
        # appended_hash = self.__get_bitmap_hash_robust_swapped(headers, datas + extension)

        # if orig_hash and orig_hash == appended_hash:
        #     self.logger.debug("Redqueen: Input can be extended")
        #     payload_array = bytearray(datas + extension)
        # else:
        #     payload_array = bytearray(datas)
        # --- extension 로직은 데이터 길이가 바뀌니까 삭제 -----
        # payload_array = bytearray(datas) # @@@@@@
        payload_array = bytearray(mutated_part)

        orig_hash = self.__get_bitmap_hash_robust(static_part, payload_array)
        if orig_hash is None:
            self.logger.debug("Redqueen: Input is not stable, skipping..")
            return
        
        # allowed_ranges = calculate_redqueen_range(metadata) # @@ M2 region 기반으로 RedQueen이 수정할 수 있는 바이트 범위 계산
        allowed_ranges = calculate_redqueen_range(metadata, self.config) # "all" -> None
        # allowed_ranges = None # 범위 한정 안함
        # print(f"@@@ coloring_done.. worker-{self.worker.pid}..node-{metadata['id']}.. stage_info[method]: {self.stage_info['method']}")
        # ================= [디버깅 코드 시작] =================
        print(f"\n[DEBUG] Node ID: {metadata.get('id', 'Unknown')}, target = {metadata.get('target_state_id', 'Unknown')}")
        
        # 1. 계산된 범위 확인
        if allowed_ranges:
            d_start, d_end = allowed_ranges
            print(f"[DEBUG] allowed_ranges: Start={d_start}, End={d_end}, Length={d_end - d_start}")
            
            # 2. 전체 페이로드 길이와 비교 (범위 초과 여부 확인)
            print(f"[DEBUG] payload_array length: {len(payload_array)}")
            
            # 3. 실제 데이터 확인 (중요!)
            # 계산된 범위의 앞부분 16바이트를 Hex로 찍어서, 
            # 이것이 내가 타겟팅하려는 SMB 메시지 헤더/바디가 맞는지 눈으로 확인합니다.
            if d_start < len(payload_array):
                safe_end = min(d_end, d_start + 16, len(payload_array))
                preview_data = payload_array[d_start:safe_end]
                print(f"[DEBUG] Range Content (Hex): {preview_data.hex()}")
            else:
                print(f"[DEBUG] !! ERROR !! Start offset {d_start} is out of bounds!")
        else:
            print("[DEBUG] allowed_ranges is None (Targeting WHOLE payload)")
            
        # 4. (선택사항) Metadata의 Region 정보와 대조
        # 현재 Metadata가 인식하는 Region 구조를 출력해 비교해봅니다.
        # regions = metadata.get("regions", [])
        # for idx, r in enumerate(regions):
        #     print(f"[DEBUG] Region[{idx}]: {r}")
        
        print("===================================================\n")
        # ================= [디버깅 코드 끝] =================
        
        # colored_alternatives = self.__perform_coloring(headers, payload_array) # original version
        # colored_alternatives = self.__perform_coloring(headers, payload_array, orig_hash) # @@@@@@ mutate header version
        colored_alternatives = self.__perform_coloring(static_part, payload_array, allowed_ranges, orig_hash) # all version
        if colored_alternatives:
            payload_array = colored_alternatives[0]
            assert isinstance(colored_alternatives[0], bytearray), print(
                    "!! ColoredAlternatives:", repr(colored_alternatives[0]), type(colored_alternatives[0]))
        else:
            self.logger.debug("Redqueen: Input is not stable, skipping..")
            return

        self.stage_update_label("redq_trace")
        rq_info = RedqueenInfoGatherer(allowed_ranges) # @@ M2 region 기반으로 RedQueen이 수정할 수 있는 바이트 범위 전달
        rq_info.make_paths(RedqueenWorkdir(self.worker.pid, self.config))
        rq_info.verbose = False
        for pld in colored_alternatives:
            # if self.execute_redqueen(headers, pld):
            # if self.execute_redqueen_swapped(headers, pld):
            if self.execute_redqueen(static_part, pld): # all version 
                rq_info.get_info(pld)

        rq_info.get_proposals()
        # print(f"@@@ redq_trace_done.. worker-{self.worker.pid}..node-{metadata['id']}.. stage_info[method]: {self.stage_info['method']}")
        self.stage_update_label("redq_mutate")
        # rq_info.run_mutate_redqueen(headers, payload_array, self.execute_sangjun) # original version
        # print(f"@@@ mutate_start.. worker-{self.worker.pid}..node-{metadata['id']}.. stage_info[method]: {self.stage_info['method']}")
        # rq_info.run_mutate_redqueen(headers, payload_array, self.execute_sangjun_swapped, self.worker.pid) # @@@@@@ mutate header version
        rq_info.run_mutate_redqueen(static_part, payload_array, self.execute_sangjun, self.worker.pid) # all version
        # print(f"@@@ mutate_done..! worker-{self.worker.pid}..node-{metadata['id']}.. stage_info[method]: {self.stage_info['method']}")

        #if self.mode_fix_checksum:
        #    for addr in rq_info.get_hash_candidates():
        #        self.redqueen_state.add_candidate_hash_addr(addr)

        # for addr in rq_info.get_boring_cmps():
        #    self.redqueen_state.blacklist_cmp_addr(addr)
        # self.redqueen_state.update_redqueen_blacklist(RedqueenWorkdir(0))


    def dilate_effector_map(self, effector_map, limiter_map):
        ignore_limit = 2
        effector_map[0] = 1
        effector_map[-1] = 1
        for i in range(len(effector_map) // ignore_limit):
            base = i * ignore_limit
            effector_slice = effector_map[base:base + ignore_limit]
            limiter_slice = limiter_map[base:base + ignore_limit]
            if any(effector_slice) and any(limiter_slice):
                for j in range(len(effector_slice)):
                    effector_map[i + j] = 1

    def handle_deterministic(self, metadata):
        # if self.config.afl_dumb_mode:
        #     return False, {}

        # skip_zero = self.config.afl_skip_zero
        # arith_max = self.config.afl_arith_max
        # use_effector_map = not self.config.afl_no_effector and len(payload) > 128
        # limiter_map = self.create_limiter_map(payload)
        # effector_map = None

        # Mutable payload allows faster bitwise manipulations
        #payload_array = bytearray(payload)


        def __handle_deterministic(irps_list, index, metadata):
            default_info = {"stage": "flip_1"}
            # default_info = {"stage": "arith"} # @@ mutation order
            det_info = metadata.get("afl_det_info", default_info)
            # Walking bitflips
            if det_info["stage"] == "flip_1":
                bitflip.mutate_seq_walking_bits(irps_list, index,      self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=limiter_map)
                bitflip.mutate_seq_two_walking_bits(irps_list, index,  self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=limiter_map)
                bitflip.mutate_seq_four_walking_bits(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=limiter_map)

                det_info["stage"] = "flip_8"
                # if self.stage_timeout_reached():
                #     return True, det_info

            # Walking byte sets..
            if det_info["stage"] == "flip_8":
                # # Generate AFL-style effector map based on walking_bytes()
                # if use_effector_map:
                #     self.logger.debug("Preparing effector map..")
                #     effector_map = bytearray(limiter_map)

                bitflip.mutate_seq_walking_byte(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, limiter_map=limiter_map, effector_map=effector_map)

                # if use_effector_map:
                #     self.dilate_effector_map(effector_map, limiter_map)
                # else:
                #     effector_map = limiter_map

                bitflip.mutate_seq_two_walking_bytes(irps_list, index,  self.execute, self.config.mutation_part)#, effector_map=effector_map)
                bitflip.mutate_seq_four_walking_bytes(irps_list, index, self.execute, self.config.mutation_part)#, effector_map=effector_map)

                det_info["stage"] = "arith" # @@ mutation order
                # det_info["stage"] = "done" # @@ mutation order
                # if effector_map:
                #     det_info["eff_map"] = bytearray(effector_map)
                # if self.stage_timeout_reached():
                #     return True, det_info

            # Arithmetic mutations..
            if det_info["stage"] == "arith":
                arithmetic.mutate_seq_8_bit_arithmetic(irps_list, index,  self.execute, self.config.mutation_part)##, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
                arithmetic.mutate_seq_16_bit_arithmetic(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
                arithmetic.mutate_seq_32_bit_arithmetic(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

                det_info["stage"] = "intr"
                # if self.stage_timeout_reached():
                #     return True, det_info

            # Interesting value mutations..
            if det_info["stage"] == "intr":
                interesting_values.mutate_seq_8_bit_interesting(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=effector_map)
                interesting_values.mutate_seq_16_bit_interesting(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
                interesting_values.mutate_seq_32_bit_interesting(irps_list, index, self.execute, self.config.mutation_part)#, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)
                # interesting_values.mutate_seq_64_bit_interesting(irps_list, index, self.execute)#, skip_null=skip_zero, effector_map=effector_map, arith_max=arith_max)

                det_info["stage"] = "done"  # @@ mutation order
                # det_info["stage"] = "flip_1"  # @@ mutation order

            return False, det_info
        target_state_id = metadata["target_state_id"] # @@
        # for index in range(len(irp_list)):
        m2_region_id, m2_count, target_state_id = extract_m2_region(metadata, self.config, target_state_id) # @@
        if target_state_id:
            metadata["target_state_id"] = target_state_id
        for index in range(m2_region_id, m2_region_id + m2_count):   # @@ M2_region에 대해 deterministic mutation 후 전체 리스트에 대해 execute
            _, det_info = __handle_deterministic(irp_list, index, metadata)

        
        return False, det_info

    def __perform_rq_dict(self, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()

        headers, datas = parse_header_and_data(irp_list)
        datas = bytearray(datas)
        if len(datas) < 256:
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
       
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        for i in range(len(datas)-len(repl)):
                            counter += 1
                            mutated = apply_dict(datas, repl, i)
                            self.execute_sangjun(headers, mutated, label="redq_dict")
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)

    def __perform_rq_dict_all_version(self, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()

        headers_orig, datas_orig = parse_header_and_data(irp_list)
        
        mutation_part = self.config.mutation_part
        if mutation_part == "header":
            static_part = bytes(datas_orig)    # 고정 = 바디
            mutated_part = headers_orig        # 변이 = 헤더
        elif mutation_part == "body":
            static_part = bytes(headers_orig)  # 고정 = 헤더
            mutated_part = datas_orig          # 변이 = 바디
        elif mutation_part == "all":
            # 'all' 모드: 전체를 변이 대상으로 설정
            # (static_part는 비워두고, mutated_part에 전체를 넣음)
            # 주의: execute_sangjun이 'all' 모드일 때 재조립을 올바르게 수행해야 함
            static_part = b""
            mutated_part = headers_orig + datas_orig
        
        mutated_part = bytearray(mutated_part)
        # Redqueen 사전(Dictionary) 적용 루프
        if len(mutated_part) < 256: # 너무 긴 입력은 스킵 (성능 문제)
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
       
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        # mutated_part(변이 대상)에 대해 dict을 적용
                        for i in range(len(mutated_part) - len(repl)):
                            counter += 1
                            mutated_current = apply_dict(mutated_part, repl, i) # 변이 수행 (mutated_part 복사본 사용)
                            self.execute_sangjun(static_part, mutated_current, label="redq_dict")
                            
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)

    def __perform_rq_dict_header(self, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()

        headers, datas = parse_header_and_data(irp_list)
        
        # [수정] 변이 대상을 headers로, 고정 부분을 datas로
        static_part = bytes(datas)
        payload_array = bytearray(headers) # 'datas' -> 'headers'

        # [수정] 헤더 길이를 기준으로 로직 수행
        if len(payload_array) < 256: # 'datas' -> 'payload_array'
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
       
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        
                        # [수정] 'datas' -> 'payload_array'
                        for i in range(len(payload_array)-len(repl)):
                            counter += 1
                            
                            # [수정] 'datas' -> 'payload_array'
                            mutated_header = apply_dict(payload_array, repl, i)
                            
                            # [수정] execute_sangjun -> execute_sangjun_swapped
                            # (고정된 data, 변이된 header) 순서로 전달
                            self.execute_sangjun_swapped(static_part, mutated_header, label="redq_dict")
                            
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)

    def __perform_rq_dict_header_v2(self, metadata):
        rq_dict = havoc.get_redqueen_dict()
        counter = 0
        seen_addr_to_value = havoc.get_redqueen_seen_addr_to_value()

        headers_orig, datas_orig = parse_header_and_data(irp_list)
        headers = datas_orig
        datas = headers_orig

        datas = bytearray(datas)
        if len(datas) < 256:
            for addr in rq_dict:
                for repl in rq_dict[addr]:
                    if addr in seen_addr_to_value and (
                            len(seen_addr_to_value[addr]) > 32 or repl in seen_addr_to_value[addr]):
                        continue
                    if not addr in seen_addr_to_value:
                        seen_addr_to_value[addr] = set()
       
                    seen_addr_to_value[addr].add(repl)
                    self.logger.debug("RQ-Dict: attempting %s ", repr(repl))
                    for apply_dict in [havoc.dict_insert_sequence, havoc.dict_replace_sequence]:
                        for i in range(len(datas)-len(repl)):
                            counter += 1
                            mutated = apply_dict(datas, repl, i)
                            self.execute_sangjun_swapped(headers, mutated, label="redq_dict")
        self.logger.debug("RedQ-Dict: Have performed %d iters", counter)

    def __perform_havoc(self, irp_list, index, metadata, use_splicing=False, dependency_stage=False, use_argv_mutate=False):
        perf = metadata["performance"]
        havoc_amount = havoc.havoc_range(self.HAVOC_MULTIPLIER / perf)

        if use_splicing:
            self.stage_update_label("afl_splice")
            havoc.mutate_seq_splice_array(irp_list, index, self.execute, havoc_amount, mutation_part=self.config.mutation_part)
        elif dependency_stage:
            self.stage_update_label("dependency")
            havoc.mutate_random_sequence(irp_list, index, self.execute)
        elif use_argv_mutate:
            self.stage_update_label("argv_mutate")
            havoc.mutate_length(irp_list, index, self.execute)
        else:
            self.stage_update_label("afl_havoc")
            havoc.mutate_seq_havoc_array(irp_list, index, self.execute, havoc_amount, mutation_part=self.config.mutation_part)


    def __check_colorization(self, orig_hash, headers, payload_array, min, max):
        # self.stage_update_label("redq_color_check_colorization")
        # @ all version: (headers = static_part, payload_array = mutated_part)
        backup = payload_array[min:max]
        for i in range(min, max):
            payload_array[i] = rand.int(255)
        new_hash = self.__get_bitmap_hash(headers, payload_array)
        if new_hash is not None and new_hash == orig_hash:
            return True
        else:
            payload_array[min:max] = backup
            return False

    # def __colorize_payload(self, orig_hash, headers, payload_array):
    #     # @ all version: (headers = static_part, payload_array = mutated_part)
    #     def checker(min_i, max_i):
    #         self.__check_colorization(orig_hash, headers, payload_array, min_i, max_i)

    #     c = ColorizerStrategy(len(payload_array), checker)
    #     t = time.time()
    #     i = 0
    #     while True:
    #         if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TO DO add to config
    #             break
    #         if len(c.unknown_ranges) == 0:
    #             break
    #         c.colorize_step()
    #         i += 1

    def __colorize_payload(self, orig_hash, headers, payload_array, allowed_ranges=None):
        # @ all version: (headers = static_part, payload_array = mutated_part)
        def checker(min_i, max_i):
            self.__check_colorization(orig_hash, headers, payload_array, min_i, max_i)

        # c = ColorizerStrategy(len(payload_array), checker)
        if allowed_ranges:
            real_start, real_end = allowed_ranges
            length = real_end - real_start
            
            def adjusted_checker(min_i, max_i):
                # 0 based index -> real offset
                return checker(real_start + min_i, real_start + max_i)
                
            c = ColorizerStrategy(length, adjusted_checker)
        else:
            c = ColorizerStrategy(len(payload_array), checker)
        
        t = time.time()
        i = 0
        while True:
            if i >= FuzzingStateLogic.COLORIZATION_STEPS and time.time() - t > FuzzingStateLogic.COLORIZATION_TIMEOUT:  # TO DO add to config
                break
            if len(c.unknown_ranges) == 0:
                break
            c.colorize_step()
            i += 1


    def __perform_coloring(self, headers, payload_array, allowed_ranges=None, orig_hash=None):
        # @ all version: (headers = static_part, payload_array = mutated_part)
        self.logger.debug("Redqueen: Initial colorize...")
        # self.stage_update_label("redq_color_coloring")
        if orig_hash is None:
            orig_hash = self.__get_bitmap_hash_robust(headers, payload_array)
            if orig_hash is None:
                return None

        colored_arrays = []
        for i in range(FuzzingStateLogic.COLORIZATION_COUNT):
            if len(colored_arrays) >= FuzzingStateLogic.COLORIZATION_COUNT:
                assert False  # TO DO remove me
            tmpdata = bytearray(payload_array)
            self.__colorize_payload(orig_hash, headers, tmpdata, allowed_ranges)
            # self.stage_update_label("redq_color_coloring_bitmap_hash")
            new_hash = self.__get_bitmap_hash(headers, tmpdata)
            if new_hash is not None and new_hash == orig_hash:
                colored_arrays.append(tmpdata)
            else:
                return None

        colored_arrays.append(payload_array)
        return colored_arrays