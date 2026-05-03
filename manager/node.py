# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Fuzz inputs are managed as nodes in a queue. Any persistent metadata is stored here as node attributes.
"""

import zlib  # @@ for checksum 계산
import lz4.frame
import msgpack
import os
from kafl_fuzzer.common.util import read_binary_file, atomic_write, parse_all


class QueueNode:
    NextID = 1

    def __init__(self, config, payload, bitmap, node_struct, write=True):
        self.node_struct = node_struct
        self.busy = False
        self.workdir = config.workdir
        self.config = config
        self.dependency_dir = self.workdir+"/dependency"
        self.set_id(QueueNode.NextID, write=False)
        QueueNode.NextID += 1

        self.set_payload(payload, write=write)
        # store individual bitmaps only in debug mode
        if bitmap and config.debug:
            self.write_bitmap(bitmap)

        self.node_struct["attention_execs"] = 0
        self.node_struct["attention_secs"] = 0
        self.set_state("initial", write=False)
        
        # @@ AFLNet queue_entry 필드 확장
        self.node_struct["was_fuzzed"] = False           # 제일 마지막에 fuzzing 완료 표시 (final 상태가 되면 True인걸로 함) 
        self.node_struct["favored"] = False              # 각 coverage 비트를 대표하는 노드는 favored (at cull_queue)
        self.node_struct["fs_redundant"] = False         # 파일 시스템상 중복 입력으로 간주되었는가 (at cull_queue)
        self.node_struct["trace_mini"] = None            # 실행 trace 요약 정보
        self.node_struct["tc_ref"] = 0                   # trace_mini 참조 횟수
        self.node_struct["bitmap_size"] = 0              # 비트맵 상 1로 설정된 비트 수
        self.node_struct["has_new_cov"] = False          # 새로운 커버리지를 유발했는가
        self.node_struct["regions"] = []                 # 메시지 단위로 분할
        self.node_struct["region_count"] = 0             # regions 개수
        self.node_struct["generating_net_state_id"] = 0  # 해당 노드가 생성될 때의 target_state_id
        # self.node_struct["var_behavior"] = False         # 실행 결과가 비결정적이었는가 -> WorkerTask.execute()의 stable 변수
        # self.node_struct["passed_det"] = False           # deterministic stage를 통과했는가 -> node.get_state() in ["havoc", "final"]로 대체
        # self.node_struct["queue_index"] = 0              # 전체 큐에서의 index -> seed.get_id()로 대체 # update_seed_reachability에서만 사용함
        # self.node_struct["is_initial_seed"] = False      # 초기 입력(seed)인지 여부 -> node.get_state() in ["initial"]로 대체
        # self.node_struct["cal_failed"] = False           # 캘리브레이션 실패 여부 -> 미사용
        # self.node_struct["unique_net_state_count"] = 0   # 이 입력이 탐색한 유니크 상태 수 -> 미사용
        # self.node_struct["trim_done"] = False            # AFLNet의 trimming 단계 완료 여부 -> 미사용
        # self.node_struct["handicap"] = 0                 # fuzzing 큐에서 뒤처진 정도 (@ calculate_score) -> 일단 안 씀
        # self.node_struct["exec_cksum"] = 0               # 실행 trace 체크섬
        # self.node_struct["fname"] = ""                   # 입력 파일 이름 (경로)

    @staticmethod
    def get_metadata(workdir, node_id):
        return msgpack.unpackb(read_binary_file(QueueNode.__get_metadata_filename(workdir, node_id)), strict_map_key=False)

    @staticmethod
    def get_payload(workdir, node_struct):
        return read_binary_file(QueueNode.__get_payload_filename(workdir, node_struct['info']['exit_reason'], node_struct['id']))

    @staticmethod
    def __get_payload_filename(workdir, exit_reason, node_id):
        return "%s/corpus/%s/payload_%05d" % (workdir, exit_reason, node_id)

    @staticmethod
    def __get_depend_payload_filename(target_dir, exit_reason, node_id):
        return "%s/payload_%05d" % (target_dir, node_id)
    

    @staticmethod
    def __get_metadata_filename(workdir, node_id):
        return "%s/metadata/node_%05d" % (workdir, node_id)

    def update_file(self, write=True):
        if write:
            node_path = QueueNode.__get_metadata_filename(self.workdir, self.get_id())
            atomic_write(node_path, msgpack.packb(self.node_struct))

    def write_bitmap(self, bitmap):
        bitmap_path = "%s/bitmaps/payload_%05d.lz4" % (self.workdir, self.get_id())
        atomic_write(bitmap_path, lz4.frame.compress(bitmap))

    # will be used both for the final update and the intermediate update in the statelogic. Needs to work in both occasions!
    # That means it needs to be able to apply an update to another update as well as the final meta data
    # This function must leave new_data unchanged, but may change old_data
    @staticmethod
    def apply_metadata_update(old_data, new_data):
        new_data = new_data.copy()  # if we remove keys deeper than attention_execs and attention_secs, we need a deep copy

        for key in [
                "attention_execs",
                "attention_secs",
                "state_time_initial",
                "state_time_redqueen",
                "state_time_grimoire",
                "state_time_grimoire_inference",
                "state_time_havoc",
                "state_time_splice",
                "state_time_radamsa"
                ]:

            old_data[key] = old_data.get(key, 0) + new_data[key]
            del new_data[key]

        old_data.update(new_data)
        return old_data

    def update_metadata(self, delta, write=True):
        self.node_struct = QueueNode.apply_metadata_update(self.node_struct, delta)
        self.update_file(write=write)

    def set_payload(self, payload, write=True):   # @@ 수정: AFLNet 필드 반영
        self.set_payload_len(len(payload), write=False)
        atomic_write(QueueNode.__get_payload_filename(self.workdir, self.get_exit_reason(), self.get_id()), payload)
        # @@ AFLNet 확장 필드 갱신
        self.set_has_new_cov(False, write=False)  # 기본값은 False
        self.set_bitmap_size(0, write=False)      # 아직 분석 안됐음
        # self.set_exec_cksum(zlib.adler32(payload), write=False)  # payload 체크섬 저장
        #(f"new payload is {payload}")
        if self.config.play_maker: # play_maker 옵션: 의존성 폴더 복사
            irp_list = parse_all(payload)

            # iterator irp_list and if there is an dependency folders, push the payload to there
            for irp in irp_list:
                ioctl_code = irp.IoControlCode
                if os.path.exists(self.dependency_dir+"/"+hex(ioctl_code)) and self.get_exit_reason()=="regular":
                     atomic_write(QueueNode.__get_depend_payload_filename(self.dependency_dir+"/"+hex(ioctl_code), self.get_exit_reason(), self.get_id()), payload)
                else:
                    pass


            #atomic_write(QueueNode.__get_payload_filename(self.workdir, self.get_exit_reason(), self.get_id()), payload)
        # TO DO Add new payload files to dependency folders when play makers on
        # settings.play_maker -> can know this options is ON
        # Need to Exists check first
        
    def get_payload_len(self):
        return self.node_struct["payload_len"]

    def set_payload_len(self, val, write=True):
        self.node_struct["payload_len"] = val
        self.update_file(write)

    def get_id(self):
        return self.node_struct["id"]

    def set_id(self, val, write=True):
        self.node_struct["id"] = val
        self.update_file(write)

    def get_new_bytes(self):
        return self.node_struct["new_bytes"]

    def set_new_bytes(self, val, write=True):
        self.node_struct["new_bytes"] = val
        self.update_file(write)

    def get_new_bits(self):
        return self.node_struct["new_bits"]

    def clear_fav_bits(self, write=True):
        self.node_struct["fav_bits"] = {}
        self.update_file(write)

    def get_fav_bits(self):
        return self.node_struct["fav_bits"]

    def add_fav_bit(self, index, write=True):
        self.node_struct["fav_bits"][index] = 0
        self.update_file(write)

    def remove_fav_bit(self, index, write=True):
        assert index in self.node_struct["fav_bits"]
        self.node_struct["fav_bits"].pop(index)
        self.update_file(write)

    def set_new_bits(self, val, write=True):
        self.node_struct["new_bits"] = val
        self.update_file(write)

    def get_level(self):
        return self.node_struct["level"]

    def set_level(self, val, write=True):
        self.node_struct["level"] = val
        self.update_file(write)

    def is_favorite(self):
        return len(self.node_struct["fav_bits"]) > 0

    def get_parent_id(self):
        return self.node_struct["info"]["parent"]

    def get_timestamp(self):
        return self.node_struct["info"]["time"]

    def get_method(self):
        return self.node_struct["info"]["method"]

    def get_initial_performance(self):
        return self.node_struct["info"]["performance"]

    def get_performance(self):
        return self.node_struct["performance"]

    def set_performance(self, val, write=True):
        self.node_struct["performance"] = val
        self.update_file(write)

    def get_state(self):
        return self.node_struct["state"]["name"]

    def set_state(self, val, write=True):
        self.node_struct["state"]["name"] = val
        self.update_file(write)

    def get_exit_reason(self):
        return self.node_struct["info"]["exit_reason"]

    def set_exit_reason(self, val, write=True):
        self.node_struct["info"]["exit_reason"] = val
        self.update_file(write)

    def get_fav_factor(self):
        return self.node_struct["fav_factor"]

    def set_score(self, val):
        self.node_struct["score"] = val

    def get_score(self):
        return self.node_struct["score"]

    def set_fav_factor(self, val, write=True):
        self.node_struct["fav_factor"] = val
        self.update_file(write)

    def set_free(self):
        self.busy = False

    def set_busy(self):
        self.busy = True

    def is_busy(self):
        return self.busy
    
    # ----------------------------
    # 추가된 필드의 Getter/Setter
    # ----------------------------
    def get_was_fuzzed(self):
        return self.node_struct["was_fuzzed"]

    def set_was_fuzzed(self, val: bool, write=True):
        self.node_struct["was_fuzzed"] = val
        self.update_file(write)

    def get_favored(self):
        return self.node_struct["favored"]
    
    def set_favored(self, val: bool, write=True):
        self.node_struct["favored"] = val
        self.update_file(write)

    def get_fs_redundant(self):
        return self.node_struct["fs_redundant"]

    def set_fs_redundant(self, val: bool, write=True):
        self.node_struct["fs_redundant"] = val
        self.update_file(write)

    def get_trace_mini(self):
        return self.node_struct["trace_mini"] 

    def set_trace_mini(self, minimized_bits: bytes, write=True):
        self.node_struct["trace_mini"] = minimized_bits
        self.update_file(write)

    def has_trace_mini(self):
        return self.node_struct["trace_mini"] is not None

    def get_tc_ref(self):
        return self.node_struct["tc_ref"]
    
    def inc_tc_ref(self, write=True):
        self.node_struct["tc_ref"] += 1
        self.update_file(write)

    def dec_tc_ref(self, write=True):
        self.node_struct["tc_ref"] -= 1
        self.update_file(write)
    
    def get_bitmap_size(self):
        return self.node_struct["bitmap_size"]

    def set_bitmap_size(self, val: int, write=True):
        self.node_struct["bitmap_size"] = val
        self.update_file(write)

    def get_has_new_cov(self):
        return self.node_struct["has_new_cov"]

    def set_has_new_cov(self, val: bool, write=True):
        self.node_struct["has_new_cov"] = val
        self.update_file(write)

    def get_regions(self):
        """
        region 정보를 Region 객체 리스트로 복원해서 반환
        """
        from kafl_fuzzer.network.region import Region
        
        region_dicts = self.node_struct.get("regions", [])
        #print (f"[** DEBUG get_regions] got {len(region_dicts)} regions: {region_dicts}")
        return [Region.from_dict(d) for d in region_dicts]

    def set_regions(self, regions, write=True):
        """
        Region 객체 리스트를 dict로 변환해 node_struct에 저장
        """
        region_dicts = [r.to_dict() for r in regions]
        self.node_struct["regions"] = region_dicts
        self.node_struct["region_count"] = len(region_dicts)
        #print (f"[** DEBUG set_regions] set {len(region_dicts)} regions: {region_dicts}")
        self.update_file(write)

    def get_region_count(self):
        return self.node_struct.get("region_count", 0)

    def get_net_state_sequence(self):
        return self.node_struct["info"].get("net_state_sequence", [])

    def get_generating_net_state_id(self):
        return self.node_struct["generating_net_state_id"]

    def set_generating_net_state_id(self, val: int, write=True):
        self.node_struct["generating_net_state_id"] = val
        self.update_file(write)

    def is_initial_seed(self):
        return self.get_state() in ["initial"]
    
    def is_passed_det(self):
        return self.get_state() in ["havoc", "final"]
        
    def set_dg_score(self, val: float, write=True):
        self.node_struct["dg_score"] = val
        self.update_file(write)
        
    def get_dg_score(self):
        return self.node_struct.get("dg_score", 0.0)

    def set_final_priority(self, val: float, write=True):
        self.node_struct["final_priority"] = val
        self.update_file(write)

    def get_final_priority(self):
        return self.node_struct.get("final_priority", 0.0)


'''
# node_Struct 구조 예시
# node_Struct는 msgpack으로 직렬화되어 metadata 파일로 저장됨

node_struct = {
  "id": 3,                              # 노드 고유 ID (QueueNode.NextID로 부여됨)
  "payload_len": 512,                  # 입력(payload) 길이 (bytes)
  "performance": 123.4,                # 현재 퍼포먼스 (처리 속도, seconds/input)
  "score": 5.2,                         # 스케줄러 우선순위 점수
  "fav_bits": {12: 0, 45: 0},          # 이 노드가 발견한 중요 비트맵 인덱스
  "new_bytes": b"\x01\x02",            # 실행 결과에서 새롭게 트리거된 바이트
  "new_bits": 3,                       # 실행 결과에서 새롭게 트리거된 비트 수
  "level": 1,                          # 부모 노드 기준으로 한 탐색 깊이 (트리 레벨)
  "fav_factor": 0.7,                   # 이 노드의 중요도 또는 영향도 점수

  "info": {
    "parent": 1,                       # 부모 노드의 ID
    "method": "havoc",                 # 입력이 생성된 방법 (e.g., havoc, redqueen 등)
    "time": 1721129489.5,              # 노드 생성 시각 (timestamp)
    "performance": 123.4,              # 최초 성능 측정값 (baseline)
    "exit_reason": "regular",          # 실행 결과: regular, crash, timeout 등
    "trimmed": True,                   # payload가 교체(갱신)되었는지 여부 (MSFuzz 기준)
    "net_state_sequence": [1,2,3],     # 네트워크 상태 시퀀스 (@ AFLNet 확장)
    "flag_list": [1,1,1],              # response 유무에 대한 플래그 목록 (@ AFLNet 확장)
    "generating_net_state_id": 5       # 해당 노드가 생성될 때의 target_state_id (@ AFLNet 확장)
  },

  "state": {
    "name": "initial"                  # 현재 fuzzing 상태 (e.g., initial, havoc, final)
  },

  "attention_execs": 10,               # attention stage에서의 실행 횟수
  "attention_secs": 2.1,               # attention stage에서 소비한 시간

  # === AFLNet 호환 확장 필드 ===
  "was_fuzzed": True,                  # fuzzing을 수행한 적 있는지 여부
  "favored": False,                    # 이 노드가 중요 비트맵으로 간주되는지 여부
  "fs_redundant": False,               # 파일 시스템 상에서 중복으로 간주되었는지
  "trace_mini": b"...",               # 실행 trace 요약 바이트
  "tc_ref": 1,                         # trace_mini의 참조 횟수
  "bitmap_size": 23,                   # 비트맵 상 1로 설정된 비트의 수
  "has_new_cov": True,                 # 새로운 커버리지를 유도했는가
  "regions": [],                       # 서버에 전송된 메시지 영역 정보
  "region_count": 0,                   # region의 개수
  "is_initial_seed": False,            # 이 노드가 초기 입력(seed)인지 여부 (메서드로만)
  "passed_det": True,                  # deterministic stage를 완료했는지 여부 (메서드로만)
}
'''