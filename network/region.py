# network/region.py

from typing import List, Tuple, Optional
from kafl_fuzzer.manager.node import QueueNode
# from kafl_fuzzer.manager.manager import M2_REGION_INFO
import random

class Region:
    def __init__(self, start_byte: int, end_byte: int, modifiable: bool,
                 state_sequence: Optional[List[int]] = None, smb_version: int = 2):
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.modifiable = modifiable
        self.state_sequence = state_sequence or []
        self.state_count = len(self.state_sequence)
        self.smb_version = smb_version

    def to_dict(self):
        # node.set_regions([r.to_dict() for r in regions])
        return {
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "modifiable": self.modifiable,
            "state_sequence": self.state_sequence,
            "smb_version": self.smb_version
        }

    @staticmethod
    def from_dict(d):
        # region_objs = [Region.from_dict(d) for d in node.get_regions()]
        return Region(
            d["start_byte"],
            d["end_byte"],
            d["modifiable"],
            d.get("state_sequence", []),
            d.get("smb_version", 0)
        )
    
    def __repr__(self):
        return (f"Region(start={self.start_byte}, end={self.end_byte}, "
                f"modifiable={self.modifiable}, states={self.state_sequence}, "
                f"smb_version={self.smb_version})")

def extract_requests_smb(buf: bytes) -> List[Region]:
    # print(f"[** extract_requests_smb] buf: {buf}")
    smb3_compression_signature = b'\xFC\x53\x4D\x42'  # 0xFC 'S' 'M' 'B'
    smb3_signature = b'\xFD\x53\x4D\x42'  # 0xFD 'S' 'M' 'B'
    smb2_signature = b'\xFE\x53\x4D\x42'  # 0xFE 'S' 'M' 'B'
    smb1_signature = b'\xFF\x53\x4D\x42'  # 0xFF 'S' 'M' 'B'

    buf_size = len(buf)
    regions: List[Region] = []
    i = 0

    while i + 4 <= buf_size:
        if i + 4 > buf_size:
            break

        # NetBIOS length field (3 bytes, big-endian)
        netbios_len = (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3]
        smb_msg_len = 4 + netbios_len  # total: NetBIOS header + SMB message
        # print(f"[** extract_requests_smb] smb_msg_len: {smb_msg_len}")
        if i + smb_msg_len > buf_size:
            break

        signature = buf[i + 4:i + 8]
        if signature == smb3_compression_signature:
            regions.append(Region(start_byte=i,
                                  end_byte=i + smb_msg_len - 1,
                                  modifiable=True,
                                  smb_version=4))
        elif signature == smb3_signature:
            regions.append(Region(start_byte=i,
                                  end_byte=i + smb_msg_len - 1,
                                  modifiable=True,
                                  smb_version=3))
        elif signature == smb2_signature:
            regions.append(Region(start_byte=i,
                                  end_byte=i + smb_msg_len - 1,
                                  modifiable=True,
                                  smb_version=2))
        elif signature == smb1_signature:
            regions.append(Region(start_byte=i,
                                  end_byte=i + smb_msg_len - 1,
                                  modifiable=True,
                                  smb_version=1))

        i += smb_msg_len  # move to the next NetBIOS block
        # print(f"[** extract_requests_smb] Region[{len(regions) - 1}] length {smb_msg_len}")

    # If no regions found, fall back to full buffer
    if not regions and buf_size > 0:
        regions.append(Region(start_byte=0,
                              end_byte=buf_size - 1,
                              modifiable=True,
                              smb_version=0))  # unknown

    # print(f"[** extract_requests_smb] Extracted {len(regions)} SMB message regions")
    return regions

def extract_m2_region(metadata, config, target_state_id=0):
    """
    region의 state_sequence 및 state_count를 기반으로 M2 region을 추출하여 m2_start_id, m2_count 반환
    """
    # payload = QueueNode.get_payload(config.workdir, metadata)
    # node = QueueNode(config, payload, bitmap=None, node_struct=metadata, write=False)
    # regions = node.get_regions()

    region_dicts = metadata.get("regions", [])
    regions = [Region.from_dict(d) for d in region_dicts]
    # print(f"[***** DEBUG extract_m2_region] metadata ({len(metadata)})={metadata}") # @@ 디버깅용
    # print(f"[*****@@@@@@@@@ DEBUG extract_m2_region] got {len(regions)} regions: {regions}") # @@ 디버깅용

    total_region = len(regions)
    if total_region == 0:
        raise ValueError("No regions found")

    if not config.directed:
        return 0, total_region, None
    
    # target_state_id에 해당하는 M2 region 선택
    # Case 1: target_state_id == 0 → 앞에서부터 state_count가 바뀌는 지점까지
    if target_state_id == 0:
        base_count = regions[0].state_count
        m2_start_id = 0
        m2_count = 0
        for r in regions:
            if r.state_count != base_count:
                break
            m2_count += 1
        m2_count = max(1, m2_count)
    # Case 2: target_state_id > 0 → 해당 state가 처음 등장하는 region을 M2 시작으로
    else: 
        m2_start_id = 0
        found = False
        for r in regions:
            if r.state_count == 0:
                raise ValueError("Region has no state annotation")
            last_state_id = r.state_sequence[-1]
            if last_state_id == target_state_id:
                found = True
                break
            m2_start_id += 1
        if not found or m2_start_id >= total_region:
            # 마지막 region의 state_sequence를 '반복'의 기준으로 삼고, 이 시퀀스가 '두 번째'로 등장하는 region의 인덱스를 찾음
            target_sequence = regions[-1].state_sequence
            first_occurrence_index = -1
            second_occurrence_index = -1
            
            for i, r in enumerate(regions):
                if r.state_sequence == target_sequence:
                    if first_occurrence_index == -1:
                        first_occurrence_index = i
                    elif second_occurrence_index == -1:
                        second_occurrence_index = i
                        break # 두 번째 항목을 찾았으므로 중단

            if second_occurrence_index != -1:
                # 두 번째 일치 항목을 찾음
                m2_start_id = second_occurrence_index
            elif first_occurrence_index != -1:
                # 두 번째는 없지만 첫 번째 항목은 찾음 (fallback)
                m2_start_id = first_occurrence_index
                print(f"[** extract_m2_region] @@@ Warning: Only one occurrence of the target state sequence found..")
            else:
                # 마지막 region의 시퀀스조차 찾지 못함 (비정상)
                # 가장 안전한 0번 인덱스로 fallback
                m2_start_id = 0
                print(f"[** extract_m2_region] @@@ Warning: Could not find matching state sequence. Falling back to index 0..")
            # m2_start_id = random.randint(0, total_region - 1) # selecting random M2 region..
            m2_count = 1

            # --- [Logging] save extract_m2_region at log file ---
            # node_id = f"node: {metadata['id']}"
            # start_id = f"m2_start_id: {m2_start_id}"
            # count = f"m2_count: {m2_count}"
            # region_version = f"smb_version: {regions[m2_start_id].smb_version}"
            # log_line = f"{node_id:<10}, {start_id:<15}, {count:<15}, {region_version:<15} @@@@@@@@@@ selecting random M2 region\nregions: {regions}\n"
            # with open(M2_REGION_INFO, "a", encoding="utf-8") as f:
            #     f.write(log_line)
            #     f.flush()
            # --- [Logging Done] ---
            # return m2_start_id, m2_count, new_target_state_id
            return m2_start_id, m2_count, None
        base_count = regions[m2_start_id].state_count
        # m2_count = 같은 state_count를 갖는 region 묶음 선택
        m2_count = 0
        for r in regions[m2_start_id:]:
            if r.state_count != base_count:
                break
            m2_count += 1
        m2_count = max(1, m2_count)

    # --------------------- smb_version == 4인 region을 우선
    # 1. smb_version == 4인 region을 우선 탐색합니다.
    # found_smb4_id = -1
    # for i, region in enumerate(regions):
    #     if region.smb_version == 4:
    #         found_smb4_id = i
    #         break # 첫 번째로 찾은 region을 사용

    # m2_start_id = 0
    # m2_count = 1 # m2_count는 항상 1로 고정

    # if found_smb4_id != -1:
    #     # 2. Case 1: smb_version == 4인 region을 찾음
    #     m2_start_id = found_smb4_id
    #     # print(f"[** extract_m2_region] Found smb_version 4 at index {m2_start_id}")
    # else:
    #     # 3. Case 2: smb_version == 4인 region이 없음 -> state_count가 가장 큰 region 탐색
    #     # print(f"[** extract_m2_region] No smb_version 4 found. Searching for max state_count.")
        
    #     max_state_count = -1
    #     max_state_index = 0 # state_count가 모두 0일 경우를 대비해 0으로 기본값 설정
        
    #     for i, region in enumerate(regions):
    #         if region.state_count > max_state_count:
    #             max_state_count = region.state_count
    #             max_state_index = i
        
    #     m2_start_id = max_state_index
    #     m2_count = total_region - m2_start_id # 해당 region부터 끝까지
        
    #     print(f"[** extract_m2_region] Max state_count ({max_state_count}) found at index {m2_start_id}. Setting count to {m2_count}.")
    # --------------------- 
    
    # --- [Logging] save extract_m2_region at log file ---
    # node_id = f"node: {metadata['id']}"
    # start_id = f"m2_start_id: {m2_start_id}"
    # count = f"m2_count: {m2_count}"
    # region_version = f"smb_version: {regions[m2_start_id].smb_version}"
    # log_line = f"{node_id:<10}, {start_id:<15}, {count:<15}, {region_version:<15} @@@@@@@@@@\nregions: {regions}\n"
    # with open(M2_REGION_INFO, "a", encoding="utf-8") as f:
    #     f.write(log_line)
    #     f.flush()
    # --- [Logging Done] ---

    return m2_start_id, m2_count, None

def _get_header_len_for_region(region):
    """
    Region 객체의 smb_version을 기반으로 
    알고 있는 헤더의 길이를 반환합니다.
    """
    if region.smb_version == 1:
        return 32
    elif region.smb_version == 2 or region.smb_version == 3:
        return 64
    elif region.smb_version == 4:
        return 16
    else:
        # smb_version 0 (unknown) 또는 
        # SMB가 아닌 Region의 경우 헤더 길이를 0으로 간주합니다.
        return 0

# def calculate_redqueen_range(metadata):
#     """
#     'headers_orig' (모든 헤더가 합쳐진) 버퍼를 기준으로, 
#     M2 Region에 해당하는 헤더들의 '로컬' (start, end_exclusive) 범위를 계산합니다.
#     """
    
#     # 1. Region 객체 리스트를 가져옵니다.
#     region_dicts = metadata.get("regions", [])
#     if not region_dicts:
#         return None # Region 정보가 없으면 계산 불가
        
#     regions = [Region.from_dict(d) for d in region_dicts]
#     total_regions = len(regions)

#     # 2. 변이할 M2 Region 인덱스(시작 ID, 개수)를 가져옵니다.
#     target_state_id = metadata.get("target_state_id", 0)
    
#     try:
#         m2_region_id, m2_count, target_state_id = extract_m2_region(metadata, None, target_state_id) # @@
#         if target_state_id:
#             metadata["target_state_id"] = target_state_id
#     except ValueError:
#         return None # "No regions found"

#     # 3. M2 Region 인덱스의 유효성을 검사합니다.
#     if m2_region_id >= total_regions:
#         return None # 유효하지 않은 M2 ID

#     # 4. 'headers_orig' 버퍼 내의 로컬 오프셋을 계산합니다.
#     current_offset = 0
#     allowed_start = None
#     allowed_end = None
    
#     last_m2_index = m2_region_id + m2_count - 1

#     for i in range(total_regions):
#         region = regions[i]
#         header_len = _get_header_len_for_region(region)

#         # 5. M2 시작 Region을 찾으면, 현재까지 누적된 오프셋이 'allowed_start'입니다.
#         if i == m2_region_id:
#             allowed_start = current_offset

#         # 6. M2 마지막 Region을 찾으면, 'allowed_end'를 계산하고 중단합니다.
#         if i == last_m2_index:
#             allowed_end = current_offset + header_len
#             break # 범위를 찾았으므로 더 이상 순회할 필요 없음

#         # 7. (M2 Region이 아닐 경우) 다음 Region을 위해 현재 헤더 길이를 누적합니다.
#         current_offset += header_len
            
#     # 8. 유효한 범위를 찾았는지 확인합니다.
#     if allowed_start is not None and allowed_end is not None:
#         # (e.g., allowed_start=64, allowed_end=128)
#         if allowed_start < allowed_end: # 유효한 범위
#             return (allowed_start, allowed_end)
#         else:
#             # M2 Region의 헤더 길이가 0인 경우 (start == end)
#             return None
#     else:
#         # M2 Region ID가 유효하지 않았거나(e.g., last_m2_index가 범위를 벗어남)
#         # 루프가 끝까지 돌았는데 last_m2_index를 못 만난 경우
#         # (이 코드는 m2_count=1일 때도 i == m2_start_id, i == last_m2_index가 모두 참이므로 정상 동작합니다)
#         return None

def calculate_redqueen_range(metadata, config):
    
    # 2. config에서 mutation_part를 가져옵니다.
    if not config:
        print("[WARNING] calculate_redqueen_range: config 객체가 None입니다. mutation_part를 알 수 없습니다.")
        return None # 기본값: 범위 없음
        
    mutation_part = config.mutation_part
    
    # 3. "all" 모드는 범위 제한 해제
    if mutation_part == "all":
        # "all" 모드에서 M2 리전은 버퍼 내에 비연속적으로 존재합니다.
        # 범위 제한을 해제하여 Redqueen이 전체를 보도록 합니다.
        return None 

    # 4. Region 객체 리스트를 가져옵니다.
    region_dicts = metadata.get("regions", [])
    if not region_dicts:
        return None # Region 정보가 없으면 계산 불가
        
    regions = [Region.from_dict(d) for d in region_dicts]
    total_regions = len(regions)

    # 5. 변이할 M2 Region 인덱스(시작 ID, 개수)를 가져옵니다.
    target_state_id = metadata.get("target_state_id", 0)
    print(f"[@@@@@] calculate_redqueen_range: target_state_id={target_state_id}") # @@ 디버깅용
    
    try:
        # 6. (버그 수정) 'None' 대신 'config' 객체를 전달합니다.
        m2_region_id, m2_count, tmp_target_state_id = extract_m2_region(metadata, config, target_state_id)
        print(f"[@@@@@] extracted m2_region_id: {m2_region_id}, m2_count: {m2_count}, target_state_id: {target_state_id}") # @@ 디버깅용
        if tmp_target_state_id:
            target_state_id = tmp_target_state_id
            metadata["target_state_id"] = tmp_target_state_id
    except ValueError:
        return None # "No regions found"

    # 7. M2 Region 인덱스의 유효성을 검사합니다.
    if m2_region_id >= total_regions:
        return None # 유효하지 않은 M2 ID

    # 8. 'headers_orig' 또는 'datas_orig' 버퍼 내의 로컬 오프셋을 계산합니다.
    current_offset = 0
    allowed_start = None
    allowed_end = None
    
    last_m2_index = m2_region_id + m2_count - 1

    for i in range(total_regions):
        region = regions[i]
        
        part_len = 0
        if mutation_part == "header":
            # 9. "header" 모드: 헤더 길이를 사용
            part_len = _get_header_len_for_region(region) + 4 # +4: NetBIOS 길이 필드 포함
        elif mutation_part == "body":
            # 10. "body" 모드: 바디 길이를 계산
            header_len = _get_header_len_for_region(region) + 4 # +4: NetBIOS 길이 필드 포함
            total_len = region.end_byte - region.start_byte + 1
            part_len = total_len - header_len
            if part_len < 0: 
                part_len = 0 # 안전장치
        
        # 11. M2 시작 Region을 찾으면, 현재까지 누적된 오프셋이 'allowed_start'입니다.
        if i == m2_region_id:
            allowed_start = current_offset

        # 12. M2 마지막 Region을 찾으면, 'allowed_end'를 계산하고 중단합니다.
        if i == last_m2_index:
            allowed_end = current_offset + part_len
            break # 범위를 찾았으므로 더 이상 순회할 필요 없음

        # 13. (M2 Region이 아닐 경우) 다음 Region을 위해 현재 파트의 길이를 누적합니다.
        current_offset += part_len
            
    # 14. 유효한 범위를 찾았는지 확인합니다.
    if allowed_start is not None and allowed_end is not None:
        if allowed_start < allowed_end: # 유효한 범위
            return (allowed_start, allowed_end)
        else:
            # M2 Region의 헤더/바디 길이가 0인 경우 (start == end)
            return None
    else:
        return None