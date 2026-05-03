# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
kAFL Manager Implementation.

Manage overall fuzz inputs/findings and schedule work for Worker instances.
"""

import glob
import os
import time
import random

import datetime

import logging
import mmh3
import shutil
from typing import List, Optional
import lz4.frame as lz4

from kafl_fuzzer.common.config import dump_config
from kafl_fuzzer.common.util import read_binary_file
from kafl_fuzzer.manager.communicator import ServerConnection
from kafl_fuzzer.manager.communicator import MSG_NODE_DONE, MSG_NEW_INPUT, MSG_READY, MSG_NODE_ABORT
from kafl_fuzzer.manager.queue import InputQueue
from kafl_fuzzer.manager.statistics import ManagerStatistics
from kafl_fuzzer.manager.bitmap import BitmapStorage
from kafl_fuzzer.manager.node import QueueNode
from kafl_fuzzer.technique.redqueen.cmp import redqueen_global_config
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.manager.playMaker import PlayMaker

from kafl_fuzzer.technique.helper import helper_init

from kafl_fuzzer.network.state_machine import IPSM # @@

import json 
import math  #for json parsing
import sys
import hashlib

SKIP_TO_NEW_PROB = 99
SKIP_NFAV_NEW_PROB = 75
SKIP_NFAV_OLD_PROB = 95

CHOOSE_NEXT_NODE = "01_priority_and_distance.txt" # 다음 노드 선택할 때, state별 노드 풀에 대해... @ manager.choose_seed()
NEXT_NODE_INFO = "02_distance_info.txt" # 선택된 노드에 대한 정보 @ manager.send_next_task
STATE_PERCENTAGE_INFO = "02_2_state_percentage_info.txt" # 선택된 노드에 대한 정보 (거리 점수 백분율) @ manager.send_next_task
M2_REGION_INFO = "03_extract_m2_region.txt" # mutaton할 때. 선택된 영역 정보 @ state_logic.py
NEW_NODE_INFO = "04_state_and_distance.txt" # 새로운 노드 추가할 때, 노드 정보 @ manager.maybe_insert_node()
DEFAULT_DISTANCE_LOG = "05_default_distance.txt" # 실행된 노드의 타겟까지의 최소 거리 @ manager.maybe_insert_node() ## @@ 05.txt
SSR_TEST_LOG = "06_ssr_test.txt" # Session Survival Rate @ manager.maybe_insert_node() ## @@ 06.ssr


logger = logging.getLogger(__name__)
distance_json_path = "/home/udw/kAFL/iso/CVE-2020-0796 (SMBGhost)/srv2_1c0017e60_directed_dist.json" #json abs path - 0796
# distance_json_path = "/home/udw/kAFL/iso/CVE-2022-32230/srv2_1c005bb7c_directed_dist.json" #json abs path - 32230
# distance_json_path = "/home/udw/kAFL/iso/CVE-2024-43642/srv2_1c005fd10_directed_dist.json" #json abs path - 43642

class ManagerTask:

    def __init__(self, config):
        self.config = config
        self.comm = ServerConnection(self.config) # Worker들과 통신할 서버 인터페이스 초기화

        self.busy_events = 0                      # Worker들이 할 일이 없을 때 카운터 증가 (커버리지가 멈췄는지 판단에 사용)
        self.empty_hash = mmh3.hash(("\x00" * config.bitmap_size), signed=False)

        self.statistics = ManagerStatistics(config)
        self.queue = InputQueue(self.config, self.statistics)   # 입력 큐 생성 (interesting input을 저장하고 꺼내는 큐)
        self.bitmap_storage = BitmapStorage(config, "main", read_only=False)
        self.play_maker = PlayMaker(self.config.play_maker)

        self.state_machine = IPSM() # @@
        self.top_rated = [None] * config.bitmap_size  # @@
        self.score_changed = False   # @@
        self.init_regions = {}  # @@ seed의region 정보
        self.init_state_sequence = {}
        self.seed_num = -1  # @@
        self.min_dist = int(sys.maxsize)  # @@
        self.ssr_total = 0     # @@ 06.ssr: maybe_insert_node() 호출 횟수 (new coverage input)
        self.ssr_survived = 0  # @@ 06.ssr: exit_reason == "regular" 횟수
        self.ssr_reach3 = 0    # @@ 06.ssr: net_state_sequence에 state 3이 포함된 횟수

        helper_init()                           # fuzzing 기법들에 필요한 헬퍼 함수 초기화

        redqueen_global_config(                 # RedQueen 관련 fuzzing 전략 설정 적용
                redq_hammering = self.config.redqueen_hammer,
                redq_do_simple = self.config.redqueen_simple,
                afl_arith_max  = self.config.afl_arith_max,
                )

        path = self.path_validate(distance_json_path)
        self.dg_dist = self._load_distance_map(path)       # << 로드
        print(f"dg_dist: {self.dg_dist}")

        logger.debug("Starting (pid: %d)" % os.getpid())
        dump_config()                           # 현재 설정을 로그로 출력
        print(f"[**] mutation_part : {self.config.mutation_part}")

        self._init_log_files()
    
    def _init_log_files(self):
        """디버깅 과정에서 생성된 로그파일들 초기화"""
        try:
            if os.path.exists(CHOOSE_NEXT_NODE):
                os.remove(CHOOSE_NEXT_NODE)
            if os.path.exists(NEXT_NODE_INFO):
                os.remove(NEXT_NODE_INFO)
            if os.path.exists(STATE_PERCENTAGE_INFO):
                os.remove(STATE_PERCENTAGE_INFO)
            if os.path.exists(M2_REGION_INFO):
                os.remove(M2_REGION_INFO)
            if os.path.exists(NEW_NODE_INFO):
                os.remove(NEW_NODE_INFO)
            if os.path.exists(DEFAULT_DISTANCE_LOG): # @@ 05.txt
                os.remove(DEFAULT_DISTANCE_LOG)      # @@ 05.txt
            if os.path.exists(SSR_TEST_LOG): # @@ 06.ssr
                os.remove(SSR_TEST_LOG)      # @@ 06.ssr
            if os.path.exists("05_crash_test_Normal.txt"):
                os.remove("05_crash_test_Normal.txt")
            if os.path.exists("05_crash_test_Overflow.txt"):
                os.remove("05_crash_test_Overflow.txt")
            if os.path.exists("05_crash_test_Overflow, CompAlg ABCD.txt"):
                os.remove("05_crash_test_Overflow, CompAlg ABCD.txt")

        except FileNotFoundError:
            pass

    def log_zero_distance_seed_counts(self, target_state_id):
        """
        각 상태에 할당된 시드 중에서 dg_score가 0인 시드의 개수를 출력 (for DEBUG)
        """
        # print("\n--- [@@ Zero Distance Seed Counts per State @@] ---")
        if not self.config.logging_file:
            return
        if not self.state_machine.state_info:
            print("  No states found in state_machine.")
            # print("-----------------------------------------------")
            return

        # # state_id를 기준으로 정렬하여 출력 순서를 일관되게 만듭니다.
        # for state_id in sorted(self.state_info.keys()):
        #     state = self.state_info[state_id]
            
        #     if not state.seeds or state.seeds_count == 0:
        #         # 이 상태에 할당된 시드가 없는 경우
        #         print(f"  State {state_id:<4}: 0 seeds total (0 with dist=0, 0.0%)")
        #         continue

        #     # state.seeds 리스트를 순회하며 dg_score가 0인 시드의 개수를 계산합니다.
        #     zero_dist_cnt = sum(1 for s in state.seeds if s.get_dg_score() == 0)
            
        #     # 0-dist 시드의 비율(%)을 계산합니다.
        #     percentage2 = self.get_zero_distance_percentage(state_id)

        #     # 총 시드 수, 0-dist 시드 수, 그리고 비율(%)을 함께 출력합니다.
        #     print(f"  State {state_id:<4}: {zero_dist_cnt} seeds with dist=0 (out of {state.seeds_count} total, {percentage2:.1f}%")
            
        with open(STATE_PERCENTAGE_INFO, "a", encoding="utf-8") as f:
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"\n--- [@@ Zero Distance Seed Counts per State @@{current_time}] ---\n")
            for state_id in sorted(self.state_machine.state_info.keys()):
                state = self.state_machine.state_info[state_id]

                if not state.seeds or state.seeds_count == 0:
                    f.write(f"  State {state_id:<4}: 0 seeds total (0 with dist=0, 0.0%)\n")
                    continue

                zero_dist_cnt = sum(1 for s in state.seeds if s.get_dg_score() == 0)
                percentage2 = self.state_machine.get_zero_distance_percentage(state_id)

                f.write(f"  State {state_id:<4}: {zero_dist_cnt} seeds with dist=0 (out of {state.seeds_count} total, {percentage2:.1f}%)\n")
            f.write(f"--> target_state_id: {target_state_id}\n")

        # top_seed_state_sequence_0 = sorted(self.state_info[0].seeds, key=lambda s: s.get_final_priority(), reverse=True)[0].get_net_state_sequence()
        # top_seed_state_sequence_3 = sorted(self.state_info[3].seeds, key=lambda s: s.get_final_priority(), reverse=True)[0].get_net_state_sequence()
        # top_seed_state_sequence_255 = sorted(self.state_info[255].seeds, key=lambda s: s.get_final_priority(), reverse=True)[0].get_net_state_sequence()
        # print(f"  [0]: {top_seed_state_sequence_0}")
        # print(f"  [3]: {top_seed_state_sequence_3}")
        # print(f"  [255]: {top_seed_state_sequence_255}")
        # print("-----------------------------------------------\n")

    @staticmethod
    def path_validate(path: str) -> str:
        import os
        if not isinstance(path, str) or not path:
            raise RuntimeError("[DG] distance_json_path must be a non-empty string.")
        if not os.path.isabs(path):
            raise ValueError(f"[DG] distance_json_path must be absolute, got: {path!r}")
        if not os.path.exists(path):
            raise FileNotFoundError(f"[DG] distance JSON not found at: {path!r}")
        return path

    def _load_distance_map(self, path):
        with open(path, "r", encoding="utf-8") as f:
            j = json.load(f)

        meta = j.get("meta", {})
        entries = j.get("entries", [])

        dist_map = {int(e["rva"]): int(e["dist"]) for e in entries}
        
        return {
            "module": meta.get("module"),
            "base_hint": int(meta.get("image_base_hint", "0"), 0) if meta.get("image_base_hint") else 0,
            "dist": dist_map
        }

    def _score_distance(self, to_rva_counts, debug=False):
        max_score = sys.maxsize

        # 거리맵이 없거나 입력이 없으면 교집합 불가 → max_score
        if not getattr(self, "dg_dist", None) or not to_rva_counts:
            return int(max_score)

        dist_map = self.dg_dist["dist"]
        min_dist = None
        if debug:
            print(f"  [** @@@@@@@@ start debugging RVA]")
        for rva, cnt in to_rva_counts:
            d = dist_map.get(int(rva))
            if d is None:
                continue
            d = int(d)
            if debug:
                print(f"  [** @@@@@@@@] rva: 0x{rva:x}, cnt: {cnt}, dist: {d}")
            if (min_dist is None) or (d < min_dist):
                min_dist = d
        if min_dist is None:
            return int(max_score)

        score = int(min_dist)
        return score


    def should_use_ipsm_schedule(self):
        """
        Hybrid mode에서 HIT_TARGET(IPSM_SCHEDULE)을 유지할지 확률적으로 결정.
        새로운 input이 발견된 시간 간격이 커질수록 DEFAULT 스케줄링(NET_STATE 고려x)을 사용할 확률이 높아짐.
        """
        if self.queue.find_new_input_time == 0:
            return False  # 아직 새로운 input이 발견되지 않았음
        
        if self.state_machine.state_cycles < 3:
            return True
        
        base_probability = 50  # HIT_TARGET(IPSM_SCHEDULE)로 선택될 최소 기본 확률
        time_gap = 600
        cur_time = int(time.time() * 1000)
        elapsed = cur_time - self.queue.find_new_input_time 

        return random.randint(0, 99) < base_probability + (elapsed // time_gap)
    
    def cull_queue(self, state_aware_mode, target_state_id=None):
        if not self.score_changed: # update_bitmap_score()에서 각 비트의 대표 시드를 업데이트 했을 때 cull_queue() 수행
            return

        self.score_changed = False  # 처리 완료 표시

        bitmap_size = self.config.bitmap_size
        temp_v = bytearray([0xFF] * (bitmap_size >> 3))  # 모든 비트를 아직 커버되지 않은 것으로 가정

        self.queue.queued_favored = 0
        self.queue.pending_favored = 0

        # Step 1: 모든 초기 시드를 제외한 노드의 favored 초기화
        for node in self.queue.id_to_node.values():
            if not node.is_initial_seed():
                node.set_favored(False, write=False)

        # Step 2: top_rated를 순회하며 각 coverage 비트를 대표하는 노드 선택
        for i in range(bitmap_size):
            node = self.top_rated[i]
            if node is None:
                continue

            if temp_v[i >> 3] & (1 << (i & 7)):  # 아직 다루지 않은 커버리지
                trace = node.get_trace_mini()
                if trace is not None:
                    for j in range(len(trace)):
                        if trace[j]:
                            temp_v[j] &= ~trace[j]  # 해당 비트 제거

                node.set_favored(True, write=False)
                self.queue.queued_favored += 1

                if state_aware_mode:
                    # 상태 기반 우선순위 선택
                    state_id = node.get_generating_net_state_id()
                    # 현재 상태가 target_state_id와 일치하거나 초기 시드인 경우, 그리고 퍼징되지 않은 경우
                    if (state_id == target_state_id or node.is_initial_seed()) and \
                    self.state_machine.was_fuzzed_map[target_state_id][node.get_id()] == 0:
                        self.queue.pending_favored += 1
                else:
                    # 일반적인 fuzzing 상황
                    if not node.get_was_fuzzed():
                        self.queue.pending_favored += 1 # 현황 파악용

        # Step 3: favored가 아닌 입력은 redundant로 간주
        for node in self.queue.id_to_node.values():
            node.set_fs_redundant(not node.get_favored())

    def choose_seed(self, target_state_id, mode="favor"):
        #print(f"[** DEBUG] choose_seed: target_state_id={target_state_id}, mode={mode}")  # @@ 디버깅용
        if target_state_id not in self.state_machine.state_info:
            # raise RuntimeError(f"AFLNet - the state_machine has no entries for state {target_state_id}")
            return None

        state = self.state_machine.get_state_info(target_state_id)
        if state.seeds_count == 0:
            return None

        result = None
        passed_cycles = 0

        if mode == "random":
            state.selected_seed_index = random.randrange(state.seeds_count)
            result = state.seeds[state.selected_seed_index]

        elif mode == "round_robin":
            result = state.seeds[state.selected_seed_index]
            state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count

        elif mode == "priority":
            # priority 기준으로 시드를 내림차순 정렬
            sorted_seeds = sorted(state.seeds, key=lambda s: s.get_final_priority(), reverse=True)
            state.selected_seed_index = 0
            
            # 모든 시드의 priority가 1 미만인지 확인 (가장 높은 priority를 가진 첫 번째 요소만 확인)
            all_less_than_one = sorted_seeds[0].get_final_priority() < 1
            
            # 현재 인덱스로 시드 선택 (라운드 로빈)
            result = sorted_seeds[state.selected_seed_index]

            if all_less_than_one:
                # 모든 priority가 1 미만이면, 단순 라운드 로빈 수행
                state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
            else:
                # priority가 1 이상인 시드가 하나라도 있는 경우:
                # 선택된 시드의 priority가 1 미만이면 인덱스를 0으로 리셋
                if result.get_final_priority() < 1:
                    state.selected_seed_index = 0
                    result = sorted_seeds[state.selected_seed_index]
                    state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
                else:
                    # priority가 1 이상이면, 다음 인덱스로 이동 (라운드 로빈)
                    state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count

        elif mode == "favor":
            sorted_seeds = sorted(state.seeds, key=lambda s: s.get_final_priority(), reverse=True) # @@@@ priority 기준으로 정렬
            self.log_zero_distance_seed_counts(target_state_id)
            state.selected_seed_index = 0

            if state.seeds_count > 5:
                passed_cycles = 0
                while passed_cycles < 5: # 5번의 사이클을 반복하여 좋은 시드 찾기 (못 찾으면 라운드 로빈으로 선택됨)
                    result = sorted_seeds[state.selected_seed_index] # result = state.seeds[state.selected_seed_index] # 일단 라운드 로빈으로 선택 (이후 skip 조건에 따라 필터링)
                    state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
                    if state.selected_seed_index == 0:
                        passed_cycles += 1

                    if result.is_busy(): # 이미 worker가 작업 중인 경우, skip
                        continue

                    if result.get_final_priority() < 1: # 무한대 거리는 제외
                        continue
                    # Skip condition 1: unrelated and not initial
                    if result.get_generating_net_state_id() != target_state_id and not result.is_initial_seed():
                    # if not result.is_initial_seed(): # 저 조건 없앴더니 choose_target_state에서 2가 선택되는 상황이 생김
                        if random.randint(0, 99) < 90:
                            continue  # Skip 90% of unrelated & non-initial seeds

                    seed_id = result.get_id()
                    if self.queue.pending_favored: # 아직 퍼징되지 않은 favored 노드가 있음
                        if (self.state_machine.was_fuzzed_map[target_state_id][seed_id] == 1) or not result.get_favored():
                            # Skip condition 2: already fuzzed or not favored
                            # 근데 지금 선택된 시드는 이미 퍼징되었거나 favored가 아님 -> 99% 확률로 skip
                            if random.randint(0, 99) < SKIP_TO_NEW_PROB:
                                continue
                        break  # Accept this seed (조건에 맞거나, 확률을 통과함)
                    else: # 아직 퍼징 안된 favored 노드가 없음
                        if not result.get_favored() and self.queue.queued_paths > 10:
                            if self.queue.num_cycles > 1:
                                was_fuzzed = self.state_machine.was_fuzzed_map[target_state_id][seed_id]
                                # Skip condition 3: 퍼징되지 않은 노드는 75%, 퍼징된 노드는 95% 확률로 skip
                                skip_prob = SKIP_NFAV_NEW_PROB if was_fuzzed == 0 else SKIP_NFAV_OLD_PROB
                                if random.randint(0, 99) < skip_prob:
                                    continue
                            break  # Accept this seed (확률을 통과함)
                        else: # Favored=True이거나, 노드 풀에 노드가 10개 이하임
                            break  # Accept this seed
            else: # 시드가 10개 이하인 경우, 라운드 로빈
                # result = sorted_seeds[state.selected_seed_index]  # result = state.seeds[state.selected_seed_index]
                # state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
                all_less_than_one = sorted_seeds[0].get_final_priority() < 1
                result = sorted_seeds[state.selected_seed_index]
                if all_less_than_one:  # 모든 priority가 1 미만이면, 단순 라운드 로빈 수행
                    state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
                else:  # priority가 1 이상인 시드가 하나라도 있는 경우:
                    if result.get_final_priority() < 1:
                        state.selected_seed_index = 0
                        result = sorted_seeds[state.selected_seed_index]
                        state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
                    else:  # priority가 1 이상이면, 다음 인덱스로 이동 (라운드 로빈)
                        state.selected_seed_index = (state.selected_seed_index + 1) % state.seeds_count
        
        # --- [Logging] save all sorted seeds info for this state ---
        if self.config.logging_file:
            try:
                current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                zero_dist_cnt = sum(1 for s in sorted_seeds if s.get_dg_score() == 0)
                with open(CHOOSE_NEXT_NODE, "a", encoding="utf-8") as f:
                    # Log a header for this choose_seed call
                    header_line = f"{current_time},,,CHOOSE_{mode:<10}, target_state_id: {target_state_id:<4}, seed_cnt: {len(sorted_seeds):<4}, zero_dist_cnt: {zero_dist_cnt}, passed_cycles: {passed_cycles}, state.selected_seed_index: {state.selected_seed_index}\n"
                    f.write(header_line)
                    
                    # Log details for each seed in sorted_seeds
                    for node in sorted_seeds[:10]:
                        node_id = f"node: {node.get_id()}"
                        dist_str = f"dist: {node.get_dg_score()}"
                        priority = f"priority: {node.get_final_priority():.6f}"
                        
                        log_line = f"{current_time},,,    {node_id:<10}, {dist_str:<30}, {priority:<35}\n"
                        f.write(log_line)
                    
                    f.flush()
                    
            except Exception as e:
                logger.error(f"[** ERROR manager] Failed to write to priority_and_distance.txt in choose_seed: {e}")
        # --- [Logging Done] ---

        if result.get_state() != "final":
            result.set_busy()
        self.statistics.event_choose_state_seed()  # 선택된 시드에 대한 통계 기록
        return result

    def log_distance_info(self, node, mode, target_state_id=None):
        if node is not None and self.config.logging_file:
            # --- [Logging] save distance_info at log file --- 
            try:
                current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                node_id = f"node: {node.get_id()}"
                dist_str = f"dist: {node.get_dg_score()}"
                priority = f"priority: {node.get_final_priority():.6f}"
                log_line = f"{current_time},,,{node_id:<10}, {dist_str:<30}, {priority:<35},,, schedule_mode: {mode}\n"
                if target_state_id is not None:
                    log_line = log_line.strip() + f", target_state_id: {target_state_id}\n"
                with open(NEXT_NODE_INFO, "a", encoding="utf-8") as f:
                    f.write(log_line)
                    f.flush()
                    
            except Exception as e:
                print(f"[** ERROR manager] Failed to write to distance_info.txt: {e}")
            # --- [Logging Done] ---

    def send_next_task(self, conn, play_maker=False):
        # Inputs placed to imports/ folder have priority.
        # This can also be used to inject additional seeds at runtime.
        imports = glob.glob(self.config.workdir + "/imports/*")
        # imports 시드 처리하면서 perform_dry_run() 역할 수행
        if imports: # imports/에 새로운 seed 파일이 있으면 그것을 우선 전송
            path = imports.pop()
            logger.debug("Importing payload from %s" % path)
            seed = read_binary_file(path)
            os.remove(path)
            
            from kafl_fuzzer.network.region import extract_requests_smb # @@
            # self.init_regions.append(extract_requests_smb(seed)) # @@
            self.seed_num += 1  # @@
            # self.init_regions[self.seed_num] = extract_requests_smb(seed)

            return self.comm.send_import(conn, {"type": "import", "payload": seed, "init_seed_id": self.seed_num})
        ########################## SCHEDULING ##########################
        if self.config.directed:
            state_aware_mode = True
            if self.config.target_state_id != 0:
                target_state_id = self.config.target_state_id
            else:
                target_state_id = self.state_machine.choose_target_state(self.config.state_selection_algo, self.min_dist)
                # target_state_id = 17
            hit_target_state_mode = self.should_use_ipsm_schedule() # HIT_TARGET을 유지할지 확률적으로 결정
            hit_target_state_mode = True # ###### @@@1208
            if hit_target_state_mode:
                # 1) HIT_TARGET 모드
                self.cull_queue(state_aware_mode, target_state_id) # favored 노드 체크
                node = self.choose_seed(target_state_id, self.config.seed_selection_algo)
                # node = self.choose_seed(target_state_id) # "priority"
                if node:
                    self.log_distance_info(node, "HIT_TARGET", target_state_id)
                else:
                    print(f"[** HIT_TARGET @@@@@ send_next_task] No seeds for state {target_state_id}!!!!")  # @@ 디버깅용
                #print(f"[** DEBUG send_next_task] HIT_TARGET: target_state_id={target_state_id}, chosen seed id={node.get_id() if node else None}")  # @@ 디버깅용
            else:
                # 2) BEFORE_TARGET 모드: target_state_id의 이전 state으로 설정
                orig_target_state_id = target_state_id
                try:
                    state = self.state_machine.get_state_info(orig_target_state_id)
                    sorted_seeds = sorted(state.seeds, key=lambda s: s.get_final_priority(), reverse=True)
                    top_seed_state_sequence = sorted_seeds[0].get_net_state_sequence()
                    idx = top_seed_state_sequence.index(orig_target_state_id)
                    if idx > 0: # 이게 첫 번째 상태이면 그대로, 아니면 이전 idx 선택
                        target_state_id = top_seed_state_sequence[idx - 1]
                    self.cull_queue(state_aware_mode, target_state_id) # favored 노드 체크
                    node = self.choose_seed(target_state_id, self.config.seed_selection_algo)
                    # node = self.choose_seed(target_state_id) # "priority"
                    target_state_id = orig_target_state_id  # mutation 대상은 원래 target_state_id -> 없으면? TODO (현재 아마 random하게 선택됨)
                    self.log_distance_info(node, "BEFORE_TARGET", target_state_id)
                except:
                    # 3) DEFAULT_SCHEDULE 모드: 전체 노드풀에서 다음 노드 선택
                    # print(f"@@@ No seeds for state {orig_target_state_id} -> DEFAULT_SCHEDULE on")  # @@ 디버깅용
                    state_aware_mode = False
                    self.cull_queue(state_aware_mode)
                    node = self.queue.get_next()
                    self.log_distance_info(node, "DEFAULT_SCHEDULE", target_state_id)
        else:
            node = self.queue.get_next()
            target_state_id = 0
        ########################## SCHEDULING ##########################
        if node:
            return self.comm.send_node(conn, {"type": "node", "nid": node.get_id(),"play_maker":play_maker, "target_state_id": target_state_id}) # → MSG_RUN_NODE

        # No work in queue. Tell Worker to wait a little or attempt blind fuzzing.
        # If all Workers are waiting, check if we are getting any coverage..
        self.comm.send_busy(conn) # 할당할 입력이 없음 → MSG_BUSY
        self.busy_events +=1
        if self.busy_events >= self.config.processes:
            self.busy_events = 0
            main_bitmap = self.bitmap_storage.get_bitmap_for_node_type("regular").c_bitmap
            if mmh3.hash(main_bitmap) == self.empty_hash:
                logger.warn("Coverage bitmap is empty?! Check -ip0 or try better seeds.")

    # Manager의 메인 루프: worker들과 계속 통신하면서 입력을 보내고 결과를 수집하며 큐를 갱신
    def loop(self):
        workers_ready = set()
        workers_aborted = set()

        while True:
            for conn, msg in self.comm.wait(self.statistics.plot_thres): # Worker로부터 메시지를 기다림 @@@@@
                # 메시지 타입에 따라 처리
                if msg["type"] == MSG_NODE_DONE:
                    # print(f"[** Manager loop] MSG_NODE_DONE {datetime.datetime.now()}")
                    # Worker 실행 완료 → 결과를 큐에 반영 + 다음 입력 전송 (send_next_task)
                    # Worker execution done, update queue item + send new task
                    if msg["node_id"]:
                        self.queue.update_node_results(msg["node_id"], msg["results"], msg["new_payload"], self.state_machine)

                    if self.play_maker.use:
                        if self.play_maker.toggle is False and time.time() - self.play_maker.last_find_time >= self.play_maker.time_limit:
                            self.play_maker.on()

                        if self.play_maker.toggle is True:
                            self.send_next_task(conn, play_maker=True)
                        else:
                            self.send_next_task(conn)
                    else:
                        self.send_next_task(conn)

                elif msg["type"] == MSG_NODE_ABORT:
                    print(f"[** Manager loop] MSG_NODE_ABORT {datetime.datetime.now()}")
                    # Worker가 중단됨 → 큐 결과 갱신 (입력 재사용 X)
                    # Worker execution aborted, update queue item + DONT send new task
                    logger.warn(f"Worker {msg['worker_id']} sent ABORT..")
                    workers_aborted.add(msg["worker_id"])
                    if msg["node_id"]:
                        self.queue.update_node_results(msg["node_id"], msg["results"], None, self.state_machine)

                elif msg["type"] == MSG_NEW_INPUT:
                    # print(f"[** Manager loop] MSG_NEW_INPUT {datetime.datetime.now()}")
                    # 새로운 흥미로운 입력 도착 → 큐에 삽입 (maybe_insert_node)
                    # Worker reports new interesting input 
                    # logger.debug("Received new input (exit=%s): %s" % (
                    #    msg["input"]["info"]["exit_reason"],
                    #    repr(msg["input"]["payload"][:24])))
                    self.maybe_insert_node(msg["input"]["payload"], msg["input"]["bitmap"], msg["input"]["info"], msg["input"]["label"])

                elif msg["type"] == MSG_READY:  # Worker는 start() 함수에서 Qemu를 실행하고 루프를 시작한 후, Manager에게 MSG_READY 메시지를 전송함
                    # print(f"[** Manager loop] MSG_READY {datetime.datetime.now()}")
                    # Worker가 준비 완료 → 즉시 다음 입력 전송 (send_next_task)
                    # Worker is ready for new input (initial hello or import done)  
                    logger.debug(f"Worker {msg['worker_id']} sent READY..")
                    workers_ready.add(msg["worker_id"])
                    self.send_next_task(conn)
                elif msg["type"] == "UPDATE_FUZZS":
                    # Worker가 state_machine.update_fuzzs()를 하기 위해 Manager에게 전송함
                    self.state_machine.update_fuzzs(msg["state_sequence"])
                else:
                    raise ValueError("unknown message type {}".format(msg))

            # start printing status when first instance is ready - or exit when they died
            if workers_ready:
                if (len(workers_ready - workers_aborted)) == 0: # 모든 워커가 aborted -> 프로그램 종료 (SystemExit)
                    raise SystemExit("All Workers have died, or aborted before they became ready. :-/")
                self.statistics.maybe_write_stats(self.state_machine)     # 통계 출력 @@@
            elif workers_aborted:  # 준비된 워커 없음 + abort 있음 -> 프로그램 종료 (SystemExit)
                raise SystemExit("Workers aborted before becoming ready. Likely broken VM or agent setup.")

            self.check_abort_condition() # 종료 조건 확인: 실행 시간 초과 또는 최대 실행 횟수 초과 시 종료


    def check_abort_condition(self):
        t_limit = self.config.abort_time
        n_limit = self.config.abort_exec

        if t_limit:
            # t_limit is minutes count
            if t_limit*60 < time.time() - self.statistics.data['start_time']:
                raise SystemExit("Exit on timeout.")
        if n_limit:
            if n_limit < self.statistics.data['total_execs']:
                raise SystemExit("Exit on max execs.")

    def store_trace(self, nid, tmp_trace):
        if tmp_trace and os.path.exists(tmp_trace):
            trace_dump_out = "%s/traces/fuzz_%05d.bin" % (self.config.workdir, nid)
            with open(tmp_trace, 'rb') as f_in:
                with lz4.LZ4FrameFile(trace_dump_out + ".lz4", 'wb',
                        compression_level=lz4.COMPRESSIONLEVEL_MINHC) as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(tmp_trace)

    def update_region_annotations(self, regions, net_state_sequence, flag_list):  # @@ 디버깅 필요
        """
        각 region의 state_sequence 및 state_count 업데이트 (state_sequence는 누적)
        flag_list는 각 region의 응답 코드 개수로, region의 개수와 동일해야 함
        """
        if len(regions) != len(flag_list):
            print(f"[** DEBUG] regions = {len(regions)}")  # @@ 디버깅용
            print(f"[** DEBUG] net_state_sequence = {net_state_sequence}")  # @@ 디버깅용
            print(f"[** DEBUG] flag_list = {flag_list}")  # @@ 디버깅용
            raise ValueError(f"Region count ({len(regions)}) does not match flag_list length ({len(flag_list)})")
    
        idx = 0  # net_state_sequence에서 현재 위치
        for i, region in enumerate(regions):
            response_count = flag_list[i]
            if response_count == 0:
                region.state_sequence = []
                region.state_count = 0
            else:
                region.state_sequence = net_state_sequence[:idx + response_count + 1] # +1은 초기 상태(0) 때문
                region.state_count = len(region.state_sequence)
            idx += response_count

    def minimize_bits(self, trace_bits: List[int]) -> bytearray:  # @@ 디버깅 필요
        """
        비트 리스트를 8비트 단위로 압축하여 bytearray 반환
        """
        mini = bytearray(self.config.bitmap_size >> 3)
        for i, bit in enumerate(trace_bits):
            if bit:
                mini[i >> 3] |= 1 << (i & 7)
        return mini

    def update_bitmap_score(self, node: QueueNode, trace_bits: List[int]): # @@ AFLNet 반영
        """
        현재 노드의 trace_bits를 기반으로 각 비트의 대표 시드(top_rated)를 업데이트
        - {실행시간 * 입력 길이}에 따라 top_rated 설정
        """
        fav_factor = node.get_performance() * node.get_payload_len()

        for i, bit in enumerate(trace_bits):
            if not bit:
                continue

            current_top = self.top_rated[i]

            if current_top:
                current_factor = current_top.get_performance() * current_top.get_payload_len()
                if fav_factor > current_factor:
                    continue  # 현재 시드가 더 느리거나 큼 → 건너뜀

                # 대표 변경 -> 기존 대표 시드의 참조 수 감소
                if current_top.dec_tc_ref() == 0:
                    current_top.set_trace_mini(None)  # 메모리 해제

            # 현재 시드가 새 대표가 됨
            self.top_rated[i] = node
            node.inc_tc_ref()

            # trace_mini 생성 (없을 경우에만)
            if not node.has_trace_mini():
                node.set_trace_mini(self.minimize_bits(trace_bits))

            self.score_changed = True

    def find_smb_version_by_state_id(self, regions_list, target_state_id):
        """
        List[Region]을 순회하여,
        state_sequence의 마지막 state_id가 target_state_id와 일치하는
        Region을 찾아 해당 Region의 smb_version을 반환합니다.
        """
        for region in regions_list:
            last_state_id = region.state_sequence[-1]
            # print(f"last_state_id: {last_state_id}")
            if last_state_id == target_state_id:
                return region.smb_version  # 일치하면 smb_version 반환

        return None

    def maybe_insert_node(self, payload, bitmap_array, info, label=None):  # @@ 수정: AFLNet 필드 반영
        assert len(payload) == info["payload_len"], "len mismatch"
        assert hashlib.sha256(payload).hexdigest() == info["payload_sha256"], "sha256 mismatch"

        bitmap = ExecutionResult.bitmap_from_bytearray(bitmap_array,
                                                       info["exit_reason"], info["performance"],
                                                       info["net_state_sequence"], info["flag_list"])  # @@
        bitmap.lut_applied = True  # since we received the bitmap from Worker, the lut was already applied
        if self.config.debug:
            backup_data = bitmap.copy_to_array()

        tmp_trace_file = info.get("pt_dump", None)
        # print(f'aaaaaaaaaaaaaaaaaaaaaaa {info.get("qemu_id",None)}')
        should_store, new_bytes, new_bits = self.bitmap_storage.should_store_in_queue(bitmap)

        from kafl_fuzzer.network.region import extract_requests_smb
        if self.config.directed and label == "import":
            my_init_regions = extract_requests_smb(payload)
            self.init_regions[info["init_seed_id"]] = my_init_regions
            self.update_region_annotations(my_init_regions, info["net_state_sequence"], info["flag_list"])
            self.init_state_sequence[info["init_seed_id"]] = info["net_state_sequence"]
            unique_state_count = len(set(info["net_state_sequence"]))
            if unique_state_count > self.state_machine.get_init_seed_state_count():
                    self.state_machine.set_init_seed_state_count(unique_state_count)
            # print(f"@@ my_init_regions: {my_init_regions}") # @@ 잘 저장 됐는지?
            print(f"@@@ init_seed_id {info['init_seed_id']} -> {info['net_state_sequence']}")
        else:
            if info["generating_net_state_id"] != 0:
                init_seed_regions = self.init_regions.get(info["init_seed_id"])
                # print(f"info['generating_net_state_id']: {info['generating_net_state_id']}")
                # print(f"info['generating_net_state_id']: {info['generating_net_state_id']}, init_seed_regions: {init_seed_regions}")
                target_version = self.find_smb_version_by_state_id(init_seed_regions, info["generating_net_state_id"])
                regions = extract_requests_smb(payload)
                # print(f"[** @@@@@@ ] target={target_version}, generating_net_state_id={info['generating_net_state_id']}\nregions={regions}")
                # print(f"[** @@@@@@ ] target={target_version}, generating_net_state_id={info['generating_net_state_id']}")
                found_version = False
                for region in regions:
                    if region.smb_version == target_version:
                        found_version = True
                        break
                if not found_version:
                    should_store = False # generating_net_state_id에 해당하는 SMB 버전이 안잡히면 signature부터 잘못된거라 저장하지 않음
                    # print(f"[** @@@@@@ ] SMB version mismatch: target={target_version}\nregions={regions}")
                    print(f"[** @@@@@@ ] SMB version mismatch: target={target_version}")
        
        # ------------------ @@거리가 안나오면 제외 O ------------------ start
        to_rva_counts = info.get("to_rva_counts", [])
        if to_rva_counts:
            # print(f"@@@ init_seed_id: {info['init_seed_id']}")  # @@ non-directed에서도 실행되므로 주석 처리
            dg_score = self._score_distance(to_rva_counts, debug=self.config.directed)
            self.min_dist = min(self.min_dist, dg_score)
            # dg_score = self._score_distance(to_rva_counts, debug=True)  # @@ 디버깅용
            # if dg_score is not int(sys.maxsize):
            #     self._score_distance(to_rva_counts, debug=True)  # @@ 디버깅용
            # else:
            #     print("@@@ dg_score == inf")
            if self.config.directed and dg_score is int(sys.maxsize):  # @@ init_state_sequence는 directed 모드에서만 채워짐
                if info["net_state_sequence"] != self.init_state_sequence[info["init_seed_id"]]:
                    init_set = set(self.init_state_sequence[info["init_seed_id"]])
                    if all(item in init_set for item in info["net_state_sequence"]):
                        self.state_machine.update_inf_dist_info(info["net_state_sequence"])
                # print("@@@ dg_score == inf")
                # print(f"@@@ state_sequence: {info['net_state_sequence']}")
        else:
            # print("@@@ to_rva_counts == None")
            pass
        
        # --- [Logging] 06_ssr_test.txt --- ## @@ 06.ssr
        try:
            self.ssr_total += 1
            exit_reason = info.get("exit_reason", "unknown")
            survived = (exit_reason == "regular")
            if survived:
                self.ssr_survived += 1
            state_seq = info.get("net_state_sequence", [])
            if 3 in state_seq:
                self.ssr_reach3 += 1
            ssr_pct    = (self.ssr_survived / self.ssr_total * 100.0)
            reach3_pct = (self.ssr_reach3   / self.ssr_total * 100.0)
            seq_len    = len(state_seq) if state_seq else 0
            dist_val   = dg_score if to_rva_counts else sys.maxsize
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            with open(SSR_TEST_LOG, "a", encoding="utf-8") as f:
                f.write(f"{current_time}, exit: {exit_reason:<8}, survived: {int(survived)}, "
                        f"total: {self.ssr_total:<6}, ssr: {ssr_pct:6.2f}%, "
                        f"reach3: {int(3 in state_seq)}, reach3_pct: {reach3_pct:6.2f}%, "
                        f"dist: {dist_val:<12}, seq_len: {seq_len:<4}, seq: {list(state_seq)}\n")
                f.flush()
        except Exception as e:
            logger.error(f"[** ERROR manager] Failed to write to 06_ssr_test.txt: {e}")
        # --- [Logging Done] --- ## @@ 06.ssr
        
        if self.config.directed:
            empty_state_ids = len(self.state_machine.state_ids) == 0
            if (should_store and empty_state_ids) or (should_store and to_rva_counts and dg_score is not int(sys.maxsize)):
            # ------------------ @@거리가 안나오면 제외 O ------------------ end

            # if should_store: # @@거리가 안나오면 제외 X ------------------ one lineS
                # print("@@@@@@@@@@@@@ should_store !")
                node_struct = {"info": info, "state": {"name": "initial"}}
                node = QueueNode(self.config, payload, bitmap_array, node_struct, write=False)
                node.set_new_bytes(new_bytes, write=False)
                node.set_new_bits(new_bits, write=False)

                node.set_performance(node.get_initial_performance(), write=False)
                node.set_generating_net_state_id(info["generating_net_state_id"], write=True)
                # [for directed] start
                # ------------------ @@거리가 안나오면 제외 X ------------------ start
                # to_rva_counts = info.get("to_rva_counts", [])
                # if to_rva_counts:
                #     dg_score = self._score_distance(to_rva_counts, debug=False)
                #     self.min_dist = min(self.min_dist, dg_score)
                #     #print(f"[** DEBUG] [maybe_insert_node] Directed distance score: {dg_score:.6f}, dbg={dg_dbg}")  # @@ 디버깅용
                #     # return 0
                #     # 스케줄러와 느슨히 결합: info에 저장해두고(로그/후처리/시각화 용), 필요하면 node.score에 반영
                #     node.set_dg_score(dg_score, write=True)
                # else:
                #     node.set_dg_score(sys.maxsize, write=True) 
                # ------------------ @@거리가 안나오면 제외 X ------------------ end
                node.set_dg_score(dg_score, write=True) # @@거리가 안나오면 제외 O ------------------ one line
                # [for directed] end
                self.update_bitmap_score(node, bitmap_array) # @@ {실행시간 * 입력 길이}에 따라 top_rated seed 업데이트

                ########################## update_state_aware_variables ########################## 디버깅 필요
                net_state_sequence = info["net_state_sequence"]
                dry_run = label == "import"
                #print(f"[** DEBUG] [maybe_insert_node] net_state_sequence={net_state_sequence}, label={label}, dry_run={dry_run}")
                # @@ state_sequence가 흥미로운 경우에만 state_machine에 추가
                if self.state_machine.is_state_sequence_interesting(net_state_sequence):
                    # 현재 메시지 시퀀스를 파일로 저장  (fname = 일단 nid로)
                    self.state_machine.save_replayable_path(net_state_sequence, payload, self.config.workdir, dry_run, node.get_id())
                    # 상태 전이 그래프 구성하기
                    self.state_machine.register_state_transition_sequence(net_state_sequence, self.init_state_sequence[info["init_seed_id"]], dry_run)
                    self.state_machine.write_dot_file(self.config.workdir) # @@ 디버깅 필요
                    
                # @@ 상태 시퀀스가 흥미롭지 않으면, region 생성만
                # region 생성해서 node_struct에 넣고 update_region_annotations
                from kafl_fuzzer.network.region import extract_requests_smb
                regions = extract_requests_smb(payload)
                self.update_region_annotations(regions, net_state_sequence, info["flag_list"])
                node.set_regions(regions, write=True)
                #print(f"[** DEBUG manager] set_regions.... {node.get_id()} with {len(regions)} regions")

                # StateInfo->seeds 추가, was_fuzzed_map 업데이트
                self.state_machine.update_seed_reachability(node, self.init_state_sequence[info["init_seed_id"]])  # @@ update_region_annotations() 이후에 호출해야 함

                # StateInfo 등록 및 업데이트
                # self.state_machine.register_seed_to_state(info["generating_net_state_id"], node)  # @@
                self.state_machine.state_info[info["generating_net_state_id"]].paths_discovered += 1  # @@ None이면 여기가 문제임
                self.state_machine.update_paths(net_state_sequence)  # @@
                self.state_machine.update_zero_dist_percentage()     # @@
                ##################################################################################
                    
                self.queue.insert_input(node, bitmap)

                # --- [Logging] 05_default_distance.txt ---
                try:
                    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    with open(DEFAULT_DISTANCE_LOG, "a", encoding="utf-8") as f:
                        f.write(f"{current_time}, node: {node.get_id()}, dist: {dg_score}, min_dist: {self.min_dist}\n")
                        f.flush()
                except Exception as e:
                    logger.error(f"[** ERROR manager] Failed to write to 05_default_distance.txt: {e}")
                # --- [Logging Done] --- ## @@ 05.txt

                # --- [Logging] save state_and_distance at log file ---
                if self.config.logging_file:
                    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    node_id = f"node: {node.get_id()}"
                    exit_reason = f"exit_reason: {node.get_exit_reason()}"
                    dist_str = f"dist: {node.get_dg_score()}"
                    state_id = f"set_generating_net_state_id: {node.get_generating_net_state_id()}"
                    state_seq = f"state_sequence: {info['net_state_sequence']}"
                    flag_list = f"flag_list: {info['flag_list']}"
                    parent_id = f"parent: {info['parent']}"
                    fav_bit = f"fav_bit: {len(node.get_fav_bits())}"
                    # log_line = f"{current_time},,,{node_id:<10}, {exit_reason:<25}, {dist_str:<20}, {state_id:<35}, {state_seq:<40}, {flag_list:<55}, {parent_id:<15}, {fav_bit}\n"
                    log_line = f"{current_time},,,{node_id:<10}, {exit_reason:<25}, {dist_str:<20}, {state_id:<35}, {state_seq:<40}, {parent_id:<15}, {fav_bit}\n"
                    with open(NEW_NODE_INFO, "a", encoding="utf-8") as f:
                        f.write(log_line)
                        f.flush()
                # --- [Logging Done] ---

                # print(tmp_trace_file)
                self.store_trace(node.get_id(), tmp_trace_file)

                crash_log_qemu_id = info.get("qemu_id",None)

                if crash_log_qemu_id and node.get_exit_reason()=="crash" and self.config.use_call_stack:
                    time.sleep(2)
                    #from kafl_fuzzer.common.color import FLUSH_LINE, FAIL, OKBLUE, ENDC

                    #PREFIX = FLUSH_LINE + FAIL
                    #logger.critical(PREFIX+f"crash log moving /tmp/kAFL_crash_call_stack_{crash_log_qemu_id} -> {self.config.workdir}/corpus/crash/{node.get_id()}_crash_log"+ENDC)
                    #logger.info(color.FAIL+ + color.ENDC)
                    #__get_payload_filename
                    #return "%s/corpus/%s/payload_%05d" % (workdir, exit_reason, node_id)
                    src = f"/tmp/kAFL_crash_call_stack_{crash_log_qemu_id}"
                    dst = self.config.workdir + "/corpus/crash/payload_%05d_crash_log"%(node.get_id())

                    if os.path.exists(src):
                        shutil.move(src, dst)
                    else:
                        pass

                    
                ## trace last finding time to play maker
                if self.play_maker.use and self.play_maker.toggle is False:
                    self.play_maker.last_find_time = time.time()
                
                return
            if tmp_trace_file and os.path.exists(tmp_trace_file):
                os.remove(tmp_trace_file)

            if self.config.debug:
                logger.debug("Received duplicate payload with exit=%s, discarding." % info["exit_reason"])
                new_data = bitmap.copy_to_array()
                for i in range(len(bitmap_array)):
                    if backup_data[i] != new_data[i]:
                        assert(False), "Bitmap mangled at {} {} {}".format(i, repr(backup_data[i]), repr(new_data[i]))
        else:
            if should_store:
                node_struct = {"info": info, "state": {"name": "initial"}}
                node = QueueNode(self.config, payload, bitmap_array, node_struct, write=False)
                node.set_new_bytes(new_bytes, write=False)
                node.set_new_bits(new_bits, write=False)
                
                from kafl_fuzzer.network.region import extract_requests_smb
                regions = extract_requests_smb(payload)
                node.set_regions(regions, write=True)
                
                self.queue.insert_input(node, bitmap)

                # --- [Logging] 05_default_distance.txt ---
                try:
                    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                    dist_val = dg_score if to_rva_counts else sys.maxsize
                    with open(DEFAULT_DISTANCE_LOG, "a", encoding="utf-8") as f:
                        f.write(f"{current_time}, node: {node.get_id()}, dist: {dist_val}, min_dist: {self.min_dist}\n")
                        f.flush()
                except Exception as e:
                    logger.error(f"[** ERROR manager] Failed to write to 05_default_distance.txt: {e}")
                # --- [Logging Done] --- ## @@ 05.txt

                self.store_trace(node.get_id(), tmp_trace_file)

                crash_log_qemu_id = info.get("qemu_id",None)

                if crash_log_qemu_id and node.get_exit_reason()=="crash" and self.config.use_call_stack:
                    time.sleep(2)
                    src = f"/tmp/kAFL_crash_call_stack_{crash_log_qemu_id}"
                    dst = self.config.workdir + "/corpus/crash/payload_%05d_crash_log"%(node.get_id())

                    if os.path.exists(src):
                        shutil.move(src, dst)
                    else:
                        pass

                if self.play_maker.use and self.play_maker.toggle is False:
                    self.play_maker.last_find_time = time.time()
                
                return

            if tmp_trace_file and os.path.exists(tmp_trace_file):
                os.remove(tmp_trace_file)

            if self.config.debug:
                logger.debug("Received duplicate payload with exit=%s, discarding." % info["exit_reason"])
                new_data = bitmap.copy_to_array()
                for i in range(len(bitmap_array)):
                    if backup_data[i] != new_data[i]:
                        assert(False), "Bitmap mangled at {} {} {}".format(i, repr(backup_data[i]), repr(new_data[i]))
