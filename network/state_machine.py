# network/state_machine.py
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple
from collections import defaultdict
import random
import math
import sys
import datetime
import os, shutil
import networkx as nx
from networkx.drawing.nx_pydot import write_dot

from kafl_fuzzer.manager.node import QueueNode

@dataclass
class StateInfo:
    id: int
    is_covered: bool = True
    paths: int = 0                # add_to_queue할 때, 해당 노드의 state_squence들의 id에 대해 ++
    paths_discovered: int = 0     # add_to_queue할 때, 해당 노드의 target_state_id에 대해 ++
    selected_times: int = 0       # choose_target_state()로 선택된 target_state_id에 대해 ++
    fuzzs: int = 0                # 퍼징 결과를 받았을 때, 응답받은 state_id에 대해 ++
    score: float = 1.0            # 현재 상태의 점수 = paths_discovered(↑), selected_times(↓), fuzzs(↓)로 계산
    selected_seed_index: int = 0  # 현재 상태에서 선택된 시드의 인덱스
    seeds: List["QueueNode"] = field(default_factory=list)
    seeds_count: int = 0
    zero_dist_percentage_to_target: float = 0.0  # 이 상태에 할당된 시드 중에서 dg_score가 0인 시드의 비율(%)
    inf_dist_count: int = 0
    inf_dist_percentage_to_target: float = 0.0

class IPSM:
    def __init__(self):
        self.state_ids: List[int] = []         # 맵핑된 state_id를 가지고 있는, 중복 없는 리스트 e.g. C0000001, 00000008 ->  [1, 2] 
        self.state_count: int = 0
        self.state_info: Dict[int, StateInfo] = {}
        self.paths_seen: Set[int] = set()      # 방문한 경로의 해시값을 저장하는 집합
        self.was_fuzzed_map: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(lambda: -1))
            # was_fuzzed_map[state_id][seed_index] = 0 -> 이 seed_index는 이 state_id에 도달 가능하지만 아직 fuzzed되진 않음
        self.selected_state_index: int = 0     # choose_target_state에 의해 정해진 현재의 target state 인덱스
        self.state_cycles: int = 0             # choose_target_state()에서 사용되는 사이클 카운트
        self.graph: nx.DiGraph = nx.DiGraph()  # 상태 머신 그래프
        self.init_seed_state_count: int = 0   # 초기 시드가 도달한 상태의 개수

    # def reset(self):
    #     self.state_ids.clear()
    #     self.state_info.clear()
    #     self.paths_seen.clear()
    #     self.was_fuzzed_map.clear()
    #     self.selected_state_index = 0
    #     self.state_cycles = 0
    #     self.graph.clear()
    
    def set_init_seed_state_count(self, count: int):
        print(f"------- self.init_seed_state_count: {count}\n")
        self.init_seed_state_count = count

    def get_init_seed_state_count(self) -> int:
        return self.init_seed_state_count

    def get_zero_distance_percentage(self, state_id: int) -> float:
        return self.state_info[state_id].zero_dist_percentage_to_target

    def get_state_info(self, state_id: int) -> StateInfo:
        return self.state_info[state_id]
        # ex. state_info = state_machine.get_state_info(42)
        #     state_info.paths_discovered += 1

    def add_state_if_new(self, state_id: int):
        """
        새로운 state_id가 발견되면 StateInfo를 생성하고 state_ids에 추가
        """
        if state_id not in self.state_info:
            self.state_info[state_id] = StateInfo(id=state_id)
            self.state_ids.append(state_id)
            self.state_count += 1

    def register_seed_to_state(self, state_id: int, seed: QueueNode):
        """
        지정된 상태에 도달 가능한 시드를 StateInfo.seeds에 등록
        """
        self.add_state_if_new(state_id)
        
        state = self.state_info[state_id]
        # 중복 시드 방지
        if seed not in state.seeds:
            state.seeds.append(seed)
            state.seeds_count += 1
            # current_seed_ids = [s.get_id() for s in state.seeds]
            # print(f"@@@@@@@@@@@@@@ node_{seed.get_id()} registered to state_id={state_id}, state.seed_ids = {current_seed_ids}")  # @@ 디버깅용

    def update_inf_dist_info(self, state_sequence):
        """
        state_sequence = inf dist
        """
        print(f"@@@ inf_dist__... {state_sequence}")
        for state_id in set(state_sequence):
            state = self.state_info.get(state_id)
            if not state:
                continue

            inf_dist_count = state.inf_dist_count + 1
            state.inf_dist_count = inf_dist_count
            if state.seeds_count == 0:
                state.inf_dist_percentage_to_target = 100.0
                continue
            state.inf_dist_percentage_to_target = (inf_dist_count / (state.seeds_count + inf_dist_count)) * 100.0
        print(f"@@@@@ {[s for s in self.state_ids]}")
        print(f"[** @@ inf_count : {[self.state_info[s].inf_dist_count for s in self.state_ids]}")
        print(f"[** @@ inf_percentage : {[self.state_info[s].inf_dist_percentage_to_target for s in self.state_ids]}\n")
    
    def update_zero_dist_percentage(self):
        """
        각 상태에 할당된 시드 중에서 dg_score가 0인 시드의 비율(%)을 계산하여 StateInfo.zero_dist_percentage_to_target에 저장
        """
        for state_id, state in self.state_info.items():
            if state.seeds_count == 0:
                state.zero_dist_percentage_to_target = 0.0
                continue

            zero_dist_count = sum(1 for seed in state.seeds if seed.get_dg_score() == 0)
            state.zero_dist_percentage_to_target = (zero_dist_count / state.seeds_count) * 100.0
    
    def update_seed_reachability(self, seed: QueueNode, init_state_sequence):
        """
        이 seed가 도달한 모든 state에 대해:
        - 해당 StateInfo에 seed 등록
        - was_fuzzed_map[state_id][seed.get_id()] = 0 (reachable but not fuzzed)
        """
        seed_id = seed.get_id()

        # 초기 상태인 state 0에 대해
        self.register_seed_to_state(0, seed)  # StateInfo.seeds에 등록
        self.was_fuzzed_map[0][seed_id] = 0   # was_fuzzed_map에 등록

        last_region = seed.get_regions()[-1]
        if last_region.state_count > 0:
            # 마지막 region의 state_sequence에 있는 *모든* state ID에 대해 반복
            for reachable_state_id in last_region.state_sequence:
                # print(f"[** @@@@@@@@@ ]register_seed_to_state: node_{seed_id}, registered_state_id={reachable_state_id}")  # @@ 디버깅용
                # state에 해당 시드 등록
                if reachable_state_id in init_state_sequence:
                    # print(f"@@@@@@ reachable_state_id: {reachable_state_id}")
                    self.register_seed_to_state(reachable_state_id, seed)
                    self.was_fuzzed_map[reachable_state_id][seed_id] = 0

    def register_state_transition_sequence(self, state_sequence: List[int], init_state, dry_run: bool = False): # 디버깅 필요
        """
        상태 시퀀스를 기반으로 상태 간 전이(edge)를 그래프에 등록하고,
        발견되지 않은 상태는 자동으로 state_info에 추가함.
        """
        if len(state_sequence) < 2:
            return

        for i in range(1, len(state_sequence)):
            prev_state = state_sequence[i - 1]
            cur_state = state_sequence[i]

            # 상태 정보 등록
            if cur_state in init_state and prev_state in init_state:
                self.add_state_if_new(prev_state)
                self.add_state_if_new(cur_state)

                # 노드 등록 (색상 속성은 dry_run 여부에 따라 지정)
                if prev_state not in self.graph:
                    self.graph.add_node(prev_state, color="blue" if dry_run else "red")
                if cur_state not in self.graph:
                    self.graph.add_node(cur_state, color="blue" if dry_run else "red")

                # 엣지 등록 (이미 존재하지 않으면)
                if not self.graph.has_edge(prev_state, cur_state):
                    self.graph.add_edge(prev_state, cur_state, color="blue" if dry_run else "red")

    def get_node_edge_count(self) -> Tuple[int, int]: # maybe_update_plot_file()
        """
        plot_data 출력 시 상태 머신 변화량 감지
        """
        return len(self.graph.nodes), len(self.graph.edges)
    
    def write_dot_file(self, out_dir: str):
        dot_path = f"{out_dir}/ipsm.dot"
        write_dot(self.graph, dot_path)

    # def reset_output_files(workdir: str):
    #     dot_path = os.path.join(workdir, "ipsm.dot")
    #     replay_dir = os.path.join(workdir, "replayable-new-ipsm-paths")

    #     try:
    #         if os.path.exists(dot_path):
    #             os.remove(dot_path)
    #         shutil.rmtree(replay_dir, ignore_errors=True)
    #     except Exception as e:
    #         print(f"[ERROR] Failed to cleanup IPSM files: {e}")

    def save_replayable_path(self,
                             state_sequence: List[int],
                             message_list: List[bytes],
                             out_dir: str,
                             dry_run: bool = False,
                             seed_file_path: str = None) -> str:
        """
        상태 시퀀스에 해당하는 메시지 시퀀스를 파일로 저장합니다.
        저장 경로: {out_dir}/replayable-new-ipsm-paths/id:{state_seq}:{basename or 'new'}
        """
        if not state_sequence or not message_list:
            return ""

        # 상태 시퀀스를 문자열로 변환: 1,2,3 → "01.02.03"
        state_str = ".".join(f"{s:02d}" for s in state_sequence)

        # 파일 이름 결정
        base = os.path.basename(str(seed_file_path)) if dry_run and seed_file_path else "new"
        replay_dir = os.path.join(out_dir, "replayable-new-ipsm-paths")
        os.makedirs(replay_dir, exist_ok=True)

        fname = os.path.join(replay_dir, f"id:{state_str}:{base}")

        # 메시지 시퀀스 저장
        with open(fname, "wb") as f:
            for msg in message_list:
                if isinstance(msg, bytes):
                    f.write(msg)
                elif isinstance(msg, int):
                    # For integers, call to_bytes() with length and byteorder.
                    # This calculates the minimum bytes needed to represent the int.
                    # 'big' is a common byte order for network protocols.
                    length = (msg.bit_length() + 7) // 8 if msg > 0 else 1
                    f.write(msg.to_bytes(length, byteorder='big'))
                else:
                    # Fallback for other potential types, though it might be better
                    # to raise an error if an unexpected type is found.
                    f.write(msg.to_bytes())  # 확장 가능성 고려
        #print(f"[** DEBUG] Saved replayable path to {fname}")  # 디버깅용 (payload가 byte 상태인지 확인)

    def is_state_sequence_interesting(self, state_sequence: List[int]) -> bool: # 디버깅 필요
        """
        상태 시퀀스가 이전에 본 적 없는 경로라면 True를 반환하고, paths_seen에 등록
        """
        trimmed = []
        for i in range(len(state_sequence)):
            if i >= 2 and state_sequence[i] == state_sequence[i - 1] == state_sequence[i - 2]:
                continue
            trimmed.append(state_sequence[i])

        # 해시 계산 (tuple로 고유화)
        hash_key = hash(tuple(trimmed))

        if hash_key in self.paths_seen:
            return False
        else:
            self.paths_seen.add(hash_key)
            return True

    def update_paths(self, state_sequence: List[int]):
        """
        방문한 state_sequence에 대해 state_info.paths++
        """
        if not state_sequence:
            return
        
        visited_states: Set[int] = set()
        for state_id in state_sequence:
            if state_id in visited_states:
                continue
            visited_states.add(state_id)

            state = self.state_info.get(state_id)
            if state:
                state.paths += 1
        

    def update_fuzzs(self, state_sequence: List[int]):
        """
        방문한 state_sequence를 기준으로 각 상태의 fuzzs 값을 1씩 증가
        동일 시드 내 중복 state_id는 무시
        """
        visited_states: Set[int] = set()

        for state_id in state_sequence:
            if state_id in visited_states:
                continue
            visited_states.add(state_id)

            state_info = self.state_info.get(state_id)
            if state_info:   # 없으면 무시
                state_info.fuzzs += 1
                #print(f"[** DEBUG] update_fuzzs: state_id={state_id}, fuzzs={state_info.fuzzs}")  # @@ 디버깅용
    
    def update_scores_and_select_next_state(self, state_selection_algo = "FAVOR_DIRECTED") -> int:
        """
        choose_target_state()에서 FAVOR 알고리즘을 사용하여 다음 상태를 선택할 때의 로직
        - state_info.fuzzs, state_info.selected_times, state_info.paths_discovered를 기반으로 점수를 계산하고,
        - 누적 점수 배열을 사용하여 확률적으로 선택된 상태를 반환함
        """
        if not self.state_ids:
            return 0

        cumulative_scores = []
        total_score = 0.0
        PERCENTAGE_WEIGHT = 10.0

        for _, state_id in enumerate(self.state_ids):
            state_info = self.state_info[state_id]

            if state_selection_algo == "FAVOR": # other cases are reserved
                # 원래 식:
                # state->score = ceil(1000 * pow(2, -log10(log10(state->fuzzs + 1) * state->selected_times + 1)) * pow(2, log(state->paths_discovered + 1)));
                fuzz_term = math.log10(math.log10(state_info.fuzzs + 1) * state_info.selected_times + 1) if state_info.selected_times > 0 or state_info.fuzzs > 0 else 0
                # fuzzs = 이 state가 퍼징된 횟수에 대해 2의 거듭제곱으로 -score 반영
                # selected_times = 이 state가 타겟으로 선택된 횟수에 대해 2의 거듭제곱으로 -score 반영
                discover_term = math.log(state_info.paths_discovered + 1) if state_info.paths_discovered > 0 else 0
                # paths_discovered = 새롭게 발견된 경로에 대해 2의 거듭제곱으로 +score 반영
                state_info.score = math.ceil(
                    1000 * pow(2, -fuzz_term) * pow(2, discover_term)
                )
            elif state_selection_algo == "FAVOR_DIRECTED":
                # FAVOR_DIRECTED 알고리즘:
                # zero_dist_percentage_to_target가 높을수록 score 증가
                fuzz_term = math.log10(math.log10(state_info.fuzzs + 1) * state_info.selected_times + 1) if state_info.selected_times > 0 or state_info.fuzzs > 0 else 0
                discover_term = math.log(state_info.paths_discovered + 1) if state_info.paths_discovered > 0 else 0

                zero_dist_percentage_term = PERCENTAGE_WEIGHT * state_info.zero_dist_percentage_to_target

                state_info.score = math.ceil(
                    1000 * pow(2, -fuzz_term) * pow(2, discover_term + zero_dist_percentage_term)
                )

            total_score += state_info.score
            cumulative_scores.append(total_score)

        if total_score == 0:
            return random.choice(self.state_ids)  # fallback

        rand_val = random.uniform(0, total_score) # 확률적으로 선택
        
        # 이진 탐색으로 누적 점수 배열에서 인덱스 찾기
        selected_index = self._binary_search(cumulative_scores, rand_val)
        selected_state_id = self.state_ids[selected_index]

        self.selected_state_index = selected_index
        return selected_state_id

    def _binary_search(self, cumulative_scores: List[float], target: float) -> int:
        left, right = 0, len(cumulative_scores) - 1
        while left < right:
            mid = (left + right) // 2
            if cumulative_scores[mid] > target:
                right = mid
            else:
                left = mid + 1
        return left

    def choose_target_by_path_convergence(self, min_dist, mode) -> int:
        """
        새로운 지향성 상태 선택 로직 (수렴 경로 휴리스틱):
        
        1. 'zero_dist_percentage_to_target' < 1.0 이고 시드가 존재하는 상태 중 Top 2를 선택.
        2. (기본) Top 2 상태의 Top 우선순위 시드 시퀀스에 두 상태 ID가 모두 포함되는지 확인.
        3. (2)가 참이면: 시퀀스에서 더 *먼저* 나오는 상태 ID를 선택.
        4. (2)가 거짓이면: (대체) Top 2 상태에 대해서만 'FAVOR_DIRECTED' 점수를 계산하여 더 높은 쪽을 선택.
        """
        
        eligible_states_info = []
        for state_id in self.state_ids[1:]:
            info = self.state_info.get(state_id)
            # print(f"[** DEBUG] State ID: {state_id}, Seeds Count: {info.seeds_count}, Zero Dist %: {info.zero_dist_percentage_to_target:.2f}")  # @@ 디버깅용

            if info and info.zero_dist_percentage_to_target < 100 and info.seeds: # 타겟 도달률 100%은 제외
                eligible_states_info.append(info)

        # 적격한 상태가 아예 없는 경우 (e.g. 모두 100%이거나 시드가 없음): 'FAVOR_DIRECTED' 점수 계산으로 대체
        if not eligible_states_info:
            print("[** WARNING] No eligible states found for path convergence; falling back to FAVOR_DIRECTED scoring.")
            return self.update_scores_and_select_next_state("FAVOR_DIRECTED")
        
        # 적격한 상태가 1개인 경우: 그냥 그 1개를 선택
        if len(eligible_states_info) == 1:
            target_state_id = eligible_states_info[0].id
            self.state_info[target_state_id].selected_times += 1
            # print(f"@@@@@ 1) Only one: {target_state_id}")
            return target_state_id

        # Top state 선택
        # 적격한 상태가 2개 이상인 경우: 도달률(percentage) 기준으로 내림차순 정렬
        eligible_states_info.sort(key=lambda s: s.zero_dist_percentage_to_target, reverse=True)
        # top2_states = [eligible_states_info[0], eligible_states_info[1]]
        # top2_state_ids = {s.id for s in top2_states} # e.g., {state_A_id, state_B_id}
        top_states = [eligible_states_info[0]]
        second_place_percentage = eligible_states_info[1].zero_dist_percentage_to_target
        for i in range(1, len(eligible_states_info)):
            current_state_info = eligible_states_info[i]
            if current_state_info.zero_dist_percentage_to_target == second_place_percentage:
                top_states.append(current_state_info)
            else:
                break 

        top_state_ids = {s.id for s in top_states} # e.g., {state_A, state_B, state_C}
        # print(f"[** DEBUG] Top eligible states : {top_state_ids}")

        # Top state 필터링 : inf_dist_percentage_to_target 기준 필터링
        sorted_states = sorted(top_states, key=lambda s: s.inf_dist_percentage_to_target)
        min_delta = float('inf') 
        prev_val = 0.0
        top_states = [] # 이 리스트가 새로운 top_states가 됨
        if mode == "gap":  # 0을 제외한 최소 변화량(min_delta)을 기준으로 비교
            for state in sorted_states:
                current_delta = state.inf_dist_percentage_to_target - prev_val
                if current_delta > min_delta:
                    print(f"[** DEBUG] Stopping state selection. current_delta ({current_delta:.2f}) > min_delta ({min_delta:.2f})") # 디버깅용
                    break
                top_states.append(state)
                # 0이 아닌 delta가 발생했을 때만 min_delta 업데이트
                if current_delta > 0 and current_delta < min_delta:
                    min_delta = current_delta
                
                prev_val = state.inf_dist_percentage_to_target
        elif mode == "min":  # 최솟값 사용
            min_val = sorted_states[0].inf_dist_percentage_to_target
            for state in sorted_states:
                if state.inf_dist_percentage_to_target == min_val:
                    top_states.append(state)
                else:  # 정렬된 리스트이므로, 최솟값보다 큰 값이 나오면 더 이상 볼 필요 없이 중단
                    break

        top_state_ids = {s.id for s in top_states}
        print(f"[** @@@@@@@] Top eligible states (after inf_dist filtering): {top_state_ids}")

        # (tmp) Round Robin
        target_state_id = None            
        num_top_states = len(top_states)
        if self.selected_state_index >= num_top_states:
            self.selected_state_index = 0
        target_state = top_states[self.selected_state_index]
        target_state_id = target_state.id
        self.selected_state_index = (self.selected_state_index + 1) % num_top_states
        
        # Top 중 선택
        # target_state_id = None
        # for state_info in top_states: 
        #     sorted_seeds = sorted(state_info.seeds, key=lambda s: s.get_final_priority(), reverse=True)
        #     top_seed_state_sequence = sorted_seeds[0].get_net_state_sequence() 
        #     # 검사: Top 2 상태 ID가 *모두* 이 시퀀스에 포함되는가?
        #     sequence_set = set(top_seed_state_sequence) # 빠른 조회를 위해 Set 사용
        #     if all(s_id in sequence_set for s_id in top_state_ids):
        #         # 성공: 이 시퀀스에서 Top 2 ID 중 가장 먼저 나오는 ID를 선택
        #         for s_id_in_seq in top_seed_state_sequence:
        #             if s_id_in_seq in top_state_ids:
        #                 target_state_id = s_id_in_seq
        #                 # print(f"@@@@@ 2) Top 2: {target_state_id}")
        #                 break # 루프 탈출 (가장 먼저 나온 ID 찾음)
        #         if target_state_id:
        #             break # state_B를 확인할 필요 없이 바깥 루프 탈출
        
        # 검사에서 둘다 통과 못하면, Top2에 대해 FAVOR_DIRECTED 스코어링
        # if target_state_id is None:
        if target_state_id:
            PERCENTAGE_WEIGHT = 10.0 # 'FAVOR_DIRECTED' 가중치
            scores = []
            for state_info in top_states:
                fuzz_term = math.log10(math.log10(state_info.fuzzs + 1) * state_info.selected_times + 1) if state_info.selected_times > 0 or state_info.fuzzs > 0 else 0
                discover_term = math.log(state_info.paths_discovered + 1) if state_info.paths_discovered > 0 else 0
                percentage_term = PERCENTAGE_WEIGHT * state_info.zero_dist_percentage_to_target
                
                score = math.ceil(
                    1000 * pow(2, -fuzz_term) * pow(2, discover_term)
                )
                # score = math.ceil(
                #     1000 * pow(2, -fuzz_term) * pow(2, discover_term + percentage_term)
                # )
                # score = discover_term
                # score = math.ceil(
                #     1000 * pow(2, fuzz_term) * pow(2, -discover_term)
                # )
                scores.append((state_info.id, score))
            
            # 더 높은 점수를 받은 상태를 선택
            scores.sort(key=lambda x: x[1], reverse=True)
            if min_dist == 0:
                scores.sort(key=lambda x: x[1], reverse=False)
            else:
                scores.sort(key=lambda x: x[1], reverse=True)
            print(f"[** @@ scores's id, min_dist={min_dist}] : {[s[0] for s in scores]}")  # @@ 디버깅용
            print(f"[** @@ scores's id, score] : {[s[1] for s in scores]}")  # @@ 디버깅용
            print(f"[** @@ scores's id, paths_discovered] : {[self.state_info[s[0]].paths_discovered for s in scores]}")  # @@ 디버깅용

            # target_state_id = scores[0][0]
            
            # --- [Logging] save all sorted seeds info for this state ---
            # current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # # zero_dist_cnt = sum(1 for s in sorted_seeds if s.get_dg_score() == 0)
            # scores2 = []
            # for state_info in top_states:
            #     discover_term = math.log(state_info.paths_discovered + 1) if state_info.paths_discovered > 0 else 0
            #     percentage_term = PERCENTAGE_WEIGHT * state_info.zero_dist_percentage_to_target
            #     score2 = discover_term * percentage_term
            #     scores2.append((state_info.id, score2))
            # scores2.sort(key=lambda x: x[1], reverse=True)
            # with open("00_Choose_Targaet_State", "a", encoding="utf-8") as f:
            #     header_line = f"\n@{current_time}...min_dist={min_dist}]\nsort_score: {[s[0] for s in scores]}\n"
            #     header_line += f"discover_term : {[s[1] for s in scores]}\n"
            #     header_line += f"percentage : {[self.state_info[s[0]].zero_dist_percentage_to_target for s in scores]}\n"
            #     header_line += f"discover * percentage : {[s for s in scores2]}\n"
            #     header_line += f"inf_dist_count : {[self.state_info[s].inf_dist_count for s in self.state_ids]}\n"
            #     header_line += f"inf_dist_percentage : {[self.state_info[s].inf_dist_percentage_to_target for s in self.state_ids]}\n"
            #     f.write(header_line)
            #     f.flush()
            # --- [Logging Done] ---
        # target_state_id = 255
        return target_state_id

    def choose_target_state(self, state_selection_algo="favor_directed", min_dist=sys.maxsize):
        """
        Choose a target state for the next fuzzing input based on the specified algorithm.
        """
        #print(f"[** DEBUG] choose_target_state: state_selection_algo={state_selection_algo}") # @@ 디버깅용
        if state_selection_algo == "random":
            selected_state_index = random.randint(0, len(self.state_ids) - 1)
            target_state_id = self.state_ids[selected_state_index]

        elif state_selection_algo == "round_robin":
            # print(len(self.state_ids)) #!!tmp
            target_state_id = self.state_ids[self.selected_state_index] # 처음에는 0
            self.selected_state_index += 1
            if self.selected_state_index >= len(self.state_ids):
                self.selected_state_index = 0

        elif state_selection_algo == "favor":
            if self.state_cycles < 5:
                # 처음 5 사이클 동안은 라운드 로빈 방식으로 순환
                # print(len(self.state_ids)) #!!tmp
                target_state_id = self.state_ids[self.selected_state_index] # 처음에는 0
                self.selected_state_index += 1
                if self.selected_state_index >= len(self.state_ids):
                    self.selected_state_index = 0
                    self.state_cycles += 1
            else:
                target_state_id = self.update_scores_and_select_next_state("FAVOR")
        
        elif state_selection_algo == "favor_directed":
            # if self.state_cycles < self.init_seed_state_count * 2:
            if self.state_cycles < 3:
                # 처음 N 사이클 동안은 라운드 로빈 방식으로 순환
                # print(len(self.state_ids)) #!!tmp
                # print(f"[** DEBUG] choose_target_state: self.selected_state_index = {self.selected_state_index}") # @@ 디버깅용
                # print(f"[** DEBUG] len(self.state_ids) = {len(self.state_ids)}") # @@ 디버깅용
                target_state_id = self.state_ids[self.selected_state_index] # 처음에는 0
                self.selected_state_index += 1
                if self.selected_state_index >= len(self.state_ids):
                    self.selected_state_index = 0
                    self.state_cycles += 1
            else:
                target_state_id = self.choose_target_by_path_convergence(min_dist, "gap")
        else:
            raise ValueError("Unknown state selection algorithm: %s" % state_selection_algo)
        
        self.state_info[target_state_id].selected_times += 1
        return target_state_id