import json
import re
import os
from openai import OpenAI

client = OpenAI()

def extract_code_from_response(text):
    """LLM 응답에서 Python 코드 블록만 추출"""
    match = re.search(r"```(?:python)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    return text

def generate_context_aware_script(sequence_file, constraints_file, structs_file, output_script):
    print(f"[+] Phase 5: Generating Context-Aware Impacket Fuzzer...")
    print(f"    - Sequence Input: {sequence_file}")
    print(f"    - Constraints Input: {constraints_file}")

    # 1. Input Validation & Load Context (사용자 요청 코드 반영)
    if not os.path.exists(sequence_file) or not os.path.exists(constraints_file):
        print(f"[-] Error: Input files missing.\n    {sequence_file}\n    {constraints_file}")
        return

    # Load Sequence
    with open(sequence_file, 'r', encoding='utf-8') as f:
        seq_data = json.load(f)
        optimized_sequence = seq_data.get("final_optimized_sequence", [])

    # Load Constraints
    with open(constraints_file, 'r', encoding='utf-8') as f:
        constraints_data = json.load(f)
        target_context = constraints_data.get("target_function_context", "Unknown Function")
        constraints = constraints_data.get("reachability_constraints", [])
        vuln_logic = constraints_data.get("vulnerability_logic", {})

    # Load Reference Source (smb3structs.py)
    if not os.path.exists(structs_file):
        print(f"[-] Error: Reference file '{structs_file}' not found.")
        return
        
    with open(structs_file, 'r', encoding='utf-8') as f:
        structs_source = f.read()

    print(f"    - Target Function: {target_context}")
    print(f"    - Reference Source: {structs_file} ({len(structs_source)} bytes)")

    # 2. Construct the Prompt
    # 두 개의 입력 데이터(Sequence, Constraints)와 소스코드(Structs)를 결합
    prompt = f"""
    Role:
    Expert Windows Kernel Network Protocol Security Researcher & Fuzzing Engineer.

    Task:
    Write a Python script to generate raw-byte fuzzing seeds targeting Windows kernel network protocol handlers implemented in kernel drivers
    (e.g., TCP/IP, IPv6, NETIO, NDIS-based protocols, or custom network transport drivers).

    The goal is NOT to directly trigger vulnerabilities, but to generate valid-by-construction fuzzing seeds that satisfy all mandatory
    reachability and state prerequisites (e.g., negotiation, session setup, reassembly context creation), so that a fuzzer can later mutate
    these seeds to trigger vulnerabilities.

    In other words, the generated packets must be structurally correct, executable, and capable of reaching deep kernel parsing logic,
    based strictly on the provided reference structure definitions.

    ---

    [Key Inputs]

    You are given three inputs:

    1. Sequence:
    - An ordered sequence of protocol messages or encapsulation layers.
    - Represents the logical packet flow required to reach the target kernel code path.
    - Examples: negotiation → setup → data transfer, or outer transport → inner protocol → payload.

    2. Constraints:
    - Reachability constraints derived from kernel parsing logic
        (e.g., minimum size checks, flag requirements, state-machine conditions).
    - These constraints define what must be satisfied for the packet to be accepted and processed.

    3. Reference Code (provided at the end of this prompt):
    - Python structure/class definitions that exactly mirror on-wire protocol layouts
        and Windows kernel parsing expectations.
    - These definitions may originate from:
        - impacket
        - a custom Python protocol model
        - or a direct translation of Windows kernel network structures
    - These definitions are authoritative and MUST be followed exactly.

    ---

    [Input 1: Protocol Sequence]

    An ordered description of protocol messages or encapsulation layers that must be generated.

    {json.dumps(optimized_sequence, indent=2)}

    ---

    [Input 2: Constraints & Vulnerability Logic]

    Reachability Constraints:
    {json.dumps(constraints, indent=2)}

    Vulnerability Logic (for identifying fuzz-relevant variables only; do NOT directly trigger):
    {json.dumps(vuln_logic, indent=2)}

    ---

    [Requirements]

    1. Combinatorial Fuzz Configuration (FUZZ_CONFIG)
    - Analyze the Reachability Constraints and Vulnerability Logic to identify variables involved in:
        - Length, size, or count checks
        - Offset or index calculations
        - Flag, type, or mode decisions
        - Encapsulation, segmentation, or reassembly logic
    - Map these logical variables to ACTUAL fields defined in the Reference Code.
    - Define a FUZZ_CONFIG dictionary at the top of the script.
    - Include:
        - Boundary values
        - Cross-field inconsistencies
        - Spec-valid but implementation-risky values
    - All values must still produce structurally valid packets.

    2. Sequence → Structure Class Mapping
    - Each message or layer name in the Protocol Sequence MUST map explicitly to a structure class
        defined in the Reference Code.
    - This mapping must be explicit and visible in the Python script.
    - The script must be adaptable to other protocol families by modifying only:
        - the Sequence
        - the Constraints
        - and the Reference Code

    3. Raw Byte Construction Strategy
    - Do NOT use high-level networking APIs, sockets, or connection helpers.
    - Construct all packets strictly as raw byte sequences.
    - Support layered or encapsulated protocols, including:
        - outer transport headers
        - inner protocol headers
        - payloads or reassembled fragments
    - Automatically compute size- or length-related fields when possible,
        based on the Reference structure definitions and embedded payloads.

    4. Seed Generation Logic
    - Use itertools.product to generate all combinations defined in FUZZ_CONFIG.
    - Each generated seed must:
        - Be structurally valid according to the Reference Code
        - Respect the ordering defined in the Protocol Sequence
        - Satisfy mandatory reachability constraints
    - Seeds must be suitable for:
        - kernel driver fuzzing
        - network stack replay
        - snapshot-based or coverage-guided kernel fuzzers

    5. Output Format
    - Print exactly one line per generated seed:
        [SEED_ID] <MessageType> : <HexDump>

    ---

    [STRICT OUTPUT RULE]

    - Output ONLY the Python code.
    - No explanations, comments outside the code, or additional text.
    - Assume all required dependencies are installed.

    ---

    [Reference: Protocol Structure Definitions]

    IMPORTANT:
    - Use ONLY the class names and field names defined below.
    - Strictly follow the declared structure/layout definitions.
    - Do NOT guess, rename, reorder, or invent any fields.
    - All packet construction MUST be based on these definitions.

    {structs_source}
    """


    # 3. Request Code Generation
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a compiler-level code generator. Follow the reference source strictly."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        
        code = extract_code_from_response(response.choices[0].message.content)
        
        with open(output_script, 'w', encoding='utf-8') as f:
            f.write(code)
            
        print(f"    -> Generated: {output_script}")
        print(f"    -> Next: Review the 'FUZZ_CONFIG' in the generated script to ensure boundary values are correct.")
        
    except Exception as e:
        print(f"[-] Generation Failed: {e}")

# ==============================================================================
if __name__ == "__main__":
    # Case Number 설정
    case_num = "0796"
    
    # 입력 파일 경로 구성
    input_constraints = f"binary_constraints_summary_{case_num}_v2.json"
    input_sequence = f"state_sequence_{case_num}_v4.json"
    structs_file = "C:\\Users\\User\\anaconda3\\Lib\\site-packages\\impacket\\smb3structs.py" # 사용자가 제공한 파일
    
    # 출력 파일명
    output_py = f"fuzzer_{case_num}_context_aware.py"

    generate_context_aware_script(input_sequence, input_constraints, structs_file, output_py)