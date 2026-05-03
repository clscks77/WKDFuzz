# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Queue of fuzz inputs (nodes). Interface with scheduler to determine next input to be fuzzed.
"""
import logging
import time
from kafl_fuzzer.manager.scheduler import Scheduler

logger = logging.getLogger(__name__)

class InputQueue:
    def __init__(self, config, statistics):
        self.config = config
        self.num_workers = config.processes
        self.scheduler = Scheduler()
        self.id_to_node = {}     # 전체 노드 풀 (insert_input에서 추가됨)
        self.current_cycle = []  # 현재 fuzzing 사이클에 사용될 노드 리스트
        self.bitmap_index_to_fav_node = {}  # 각 bitmap 인덱스에 대한 best node
        self.num_cycles = 0      # = queue_cycle
        self.statistics = statistics

        self.find_new_input_time = 0           # @@ 마지막으로 새로운 입력을 찾은 시간 (ms 단위)
        self.queued_paths: int = 0             # @@ 큐에 있는 전체 시드 수 = len(self.id_to_node)
        self.queued_favored: int = 0           # @@ (cull_queue에서 계산됨)
        self.pending_favored: int = 0          # @@ favor된 시드 수 (cull_queue에서 계산됨)
    
    def get_next(self, retry=False):
        if len(self.id_to_node) == 0:
            print("[** get_next] Queue is empty!!!")
            return None

        while self.current_cycle:
            #print(f"[** get_next] current_cycle: {[n.get_id() for n in self.current_cycle]}")
            node = self.current_cycle.pop()
            if not node.is_busy():   # 노드가 busy하다 = worker가 작업 중이다
                if node.get_state() != "final":
                    node.set_busy() # final 상태가 아니면 busy로 설정
                return node
        # 현재 사이클에 사용 가능한 노드가 없다면(all busy), 전체 노드를 정렬하여 새로운 사이클을 만듦
        self.update_current_cycle()

        if retry:
            # print("[** get_next] retry but still no available node")
            return None # 한번 더 해도 없으면 None 반환
        else:
            return self.get_next(retry=True) # 그리고 한번 다시 시도

    def update_current_cycle(self):   # 다음 노드를 꺼낸 이후
        # Fun experimental fuzzing scheduler.
        #
        # Idea is to perform a frequent overall sorting of the queue and
        # just fuzz the top-most N entries. This seems effective especially
        # for slow targets since we don't have good queue culling and early
        # Redqueen/Grimoire stages seem to be the most efficient.
        #
        # Issues
        # - Sorting the queue is relatively expensive, can turn the Manager into a bottleneck
        # - If we have very few items, we will end up sorting all the time
        #
        # Alternatives?
        # - keep a sorted queue
        # - let scheduler pick randomly, with weighted distribution

        fav_items = self.statistics.data['favs_total']
        cycle_size = int(min(1.5*fav_items, 4*self.num_workers)) # fav_items 수를 기준으로 하되, 시스템 자원에 맞게 제한

        # score를 기반으로 top-N 노드를 선택하기 위해 sort
        full_queue = sorted(self.id_to_node.values(),
                            key=lambda n: self.scheduler.score_priority_favs(n, self.config))

        self.num_cycles += 1
        self.current_cycle = full_queue[-cycle_size:] # score가 높은 순서로 cycle_size만큼만 가져옴
        self.statistics.event_queue_cycle(self)

        # -------- START --------

        # print(f"[** DEBUG] @@@@@@ Full Sorted Queue (Total: {len(full_queue)}):")
        # # full_queue는 self.id_to_node.values()를 스케줄러 점수로 정렬한 리스트입니다.
        # for node in full_queue:
        #     print(f"  [Full] ID: {node.get_id()}, DG_Score: {node.get_dg_score()}, Scheduler_Score: {node.get_final_priority()}")
            
        # print(f"[** DEBUG] @@@@@@ Selected Current Cycle (Top {len(self.current_cycle)}):")
        # # self.current_cycle은 full_queue에서 스케줄러 점수가 가장 높은 N개입니다.
        # for node in self.current_cycle:
        #     print(f"  [Cycle] ID: {node.get_id()}, DG_Score: {node.get_dg_score()}, Scheduler_Score: {node.get_final_priority()}")        
        # -------- END --------

        #for i in self.current_cycle:
        #    busy = "*" if i.is_busy() else " "
        #    score = i.get_score()
        #    if i.get_state() == "final":
        #        score = score/i.node_struct.get("state_time_havoc")
        #    print("node %02d%s, prio=%2.1f, score=%.2f, perf=%d, stage=%s" %(
        #        i.get_id(),
        #        busy,
        #        i.get_score(),
        #        score,
        #        i.get_fav_factor(),
        #        i.get_state(),
        #        ))

    def maybe_pushback_to_cycle(self, node, state_machine=None):
        # put nodes in early stages directly at head of queue, to reduce global sorting
        if node.get_exit_reason() == "regular" and node.is_initial_seed():
            if len(node.get_fav_bits()) > 20:
                self.current_cycle.append(node)
        if node.get_state() in ["final"]:  # @@ 디버깅 필요
            node.set_was_fuzzed(True)      # @@ final 상태로 들어오면 fuzzing이 완료된 것으로 간주
            state_machine.was_fuzzed_map[node.get_generating_net_state_id()][node.get_id()] = 1  # @@

    def update_node_results(self, nid, results, new_payload, state_machine=None):   # MSG_NODE_DONE, MSG_NODE_ABORT 결과에 대해
        node = self.id_to_node[nid]
        self.statistics.event_node_update(node, results)
        if new_payload:
            node.set_payload(new_payload)
            node.node_struct["info"]["trimmed"] = True # payload가 set_payload()로 수정되었음을 기록
            node.set_score(self.scheduler.score_speed(node))
        if results.get("performance"):
            oldperf = node.get_initial_performance()
            newperf = results["performance"]
            logger.debug("perf updated for node %d: %.2f => %.2f" % (node.get_id(), oldperf*1000,newperf*1000))
            node.set_score(self.scheduler.score_speed(node))

        node.set_fav_factor(self.scheduler.score_impact(node), write=False)
        node.update_metadata(results)
        node.set_free()
        self.maybe_pushback_to_cycle(node, state_machine)

    def insert_input(self, node, bitmap):  # 새로운 노드를 추가할 때  # @@ 수정: AFLNet 필드 반영
        """
        id_to_node에 새로운 노드를 추가하고, regular의 경우는 현재 사이클에 포함시킴(maybe_pushback_to_cycle)
        """
        parent = node.get_parent_id()
        node.set_level(self.id_to_node[parent].get_level() + 1 if parent else 0, write=False)
        node.set_performance(node.get_initial_performance(), write=False)
        node.clear_fav_bits(write=False)
        node.set_score(self.scheduler.score_speed(node))

        # @@ AFLNet 필드 설정
        # node.set_handicap(self.num_cycles)          # @@ 간단하게 현재 사이클로 설정

        self.id_to_node[node.get_id()] = node
        self.queued_paths += 1  # @@ 큐에 있는 전체 시드 수 증가
        self.find_new_input_time = int(time.time() * 1000) # @@ 현재 시간 (ms 단위)

        # only regular nodes with new bytes can become favorites
        if node.get_exit_reason() == "regular":
            if len(node.get_new_bytes()) > 0:
                self.update_best_input_for_bitmap_entry(node, bitmap)  # TO DO improve performance!
                self.maybe_pushback_to_cycle(node)
                node.set_has_new_cov(True)          # @@ 새로운 커버리지 있음
                node.set_bitmap_size(len([b for b in bitmap.cbuffer if b != 0]))  # @@ 비트맵 비트 수 # 디버그 필요(뭐가 맞니)
                #print(f"[** DEBUG] 22 set_bitmap_size.... {node.get_id()} with {node.get_bitmap_size()} fav bits")
            else:
                node.set_has_new_cov(False) # @@ 
                node.set_bitmap_size(0)     # @@ 

        node.set_fav_factor(self.scheduler.score_impact(node), write=True)
        #node.update_file()
        if self.config.directed:
            self.scheduler.score_priority_favs(node, self.config)  # @@ priority 계산
        self.statistics.event_node_new(node)

    def should_overwrite_old_entry(self, index, val, node): # 새로운 노드를 추가할 때 
        entry = self.bitmap_index_to_fav_node.get(index)
        if not entry:
            return True, None
        old_node, old_val = entry
        better_bits = val > old_val and node.get_score() <= old_node.get_score()
        better_score = val == old_val and node.get_score() < old_node.get_score()
        if better_bits or better_score:
            return True, old_node
        return False, None

    def update_best_input_for_bitmap_entry(self, new_node, bitmap):  # 새로운 노드를 추가할 때  # @@ 수정
        """
        퍼징 대상에서 발견된 새로운 커버리지 정보를 기반으로, 어떤 입력 노드가 
        특정 비트맵 인덱스의 "best input"인지를 판단하고 이를 갱신하는 기능
        """
        changed_nodes = set()
        fav_bit_count = 0       # @@ count favored bits
        for (index, val) in enumerate(bitmap.cbuffer):
            if val == 0x0:
                continue
            overwrite, old_node = self.should_overwrite_old_entry(index, val, new_node)
            if overwrite:
                self.bitmap_index_to_fav_node[index] = (new_node, val)
                new_node.add_fav_bit(index, write=False)
                fav_bit_count += 1    # @@ 
                #changed_nodes.add(new_node)
                if old_node:
                    old_node.remove_fav_bit(index, write=False)
                    changed_nodes.add(old_node)
                    self.statistics.event_node_remove_fav_bit(old_node)
        for node in changed_nodes:
            node.set_fav_factor(self.scheduler.score_impact(node), write=False)
            node.update_file()
        
        new_node.set_bitmap_size(fav_bit_count)      # @@ # 디버그 필요(뭐가 맞니)
        new_node.set_has_new_cov(fav_bit_count > 0)  # @@ 
        #print(f"[** DEBUG] 11 set_bitmap_size.... {new_node.get_id()} with {fav_bit_count} fav bits")