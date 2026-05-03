# Fuzzing Seed Blueprint JSON으로부터 "fuzzer_{num}_impacket.py" 생성 + itertools 조합 생성
import json
import re
from openai import OpenAI

client = OpenAI()

def extract_code_from_response(text):
    """LLM 응답에서 Python 코드 블록만 추출"""
    match = re.search(r"```(?:python)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    return text

def generate_impacket_script(blueprint_file, output_script):
    # 1. Load Blueprint
    with open(blueprint_file, 'r', encoding='utf-8') as f:
        blueprint = json.load(f)

    target_func = blueprint.get("target_function", "Unknown")
    
    print(f"[+] Phase 4: Translating Blueprint to Combinatorial Impacket Code...")
    print(f"    - Target: {target_func}")
    print(f"    - Input: {blueprint_file}")

    # 2. Construct the "Developer" Prompt
    # 프롬프트 강화: 변수 추출 및 조합 생성 로직 추가
    prompt = f"""
    Role: Senior Python Developer & Security Researcher specialized in Network Protocol Fuzzing.

    Task:
    Convert the provided "Seed Blueprint JSON" into a **Combinatorial Offline Seed Generator** using Impacket.
    
    Instead of generating just one static packet sequence, you must:
    1. Identify key parameters in the blueprint that should be mutated (e.g., Flags, OpCodes, Payload Sizes, Names).
    2. Define these as lists in a global `FUZZ_CONFIG` dictionary at the top of the script.
    3. Generate **ALL possible combinations** of these parameters to create diverse valid seeds.

    The goal is to produce raw packet payloads (NetBIOS + Protocol + Body) for offline kernel fuzzing.

    ---

    [Input Blueprint]
    {json.dumps(blueprint, indent=2)}

    ---

    [Core Requirements]

    1. Explicit Variable Configuration (The "FUZZ_CONFIG")
       - Analyze the blueprint. Extract important fields that affect code path coverage (e.g., 'AccessMask', 'ShareAccess', 'Options', 'Command').
       - Create a dictionary named `FUZZ_CONFIG` at the top of the code.
       - Each key must be the parameter name, and the value must be a **list of interesting values** (including boundary values, valid/invalid flags).
       - Example:
         ```python
         FUZZ_CONFIG = {{
             'flags': [0x00, 0x01, 0xFF],
             'access_mask': [0x00000001, 0x00000000, 0x001F01FF],
             'filename_len': [10, 255, 1024]
         }}
         ```

    2. Combinatorial Generation Engine
       - Use `itertools.product` to iterate through EVERY combination of values in `FUZZ_CONFIG`.
       - For each combination:
         - Instantiate the Impacket classes.
         - Apply the specific values from the current combination.
         - Apply proper framing (e.g., NetBIOS/NBSS header) so the kernel driver parses it correctly.
         - Mock stateful values (SessionID, TreeID) consistently.

    3. Output Format
       - Do NOT connect to any socket.
       - Print the output in a parseable format for each generated combination.
       - Format: `[SEED_ID: <Combination_Values>] :: <PacketName> :: <Hexdump>`

    ---

    [Output Code Structure]

    1. Imports (include `itertools`, `struct`, `impacket`, etc.)
    2. `FUZZ_CONFIG = { ... }` (Defined explicitly with lists of values)
    3. Helper functions to build packets (accepting `config` dict as input).
    4. `main` function:
       - Loop through `itertools.product(*FUZZ_CONFIG.values())`.
       - Map values back to keys.
       - Build packets.
       - Print Output.

    ---

    [STRICT OUTPUT RULE]
    OUTPUT ONLY THE PYTHON CODE.
    NO EXPLANATIONS.
    NO COMMENTS OUTSIDE THE CODE.
    """

    # 3. Request Code Generation
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an expert Python network programmer. Write production-ready Impacket code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0 # 정확한 코드 구조를 위해 0.0 유지
        )
        
        code = extract_code_from_response(response.choices[0].message.content)
        
        with open(output_script, 'w', encoding='utf-8') as f:
            f.write(code)
            
        print(f"    -> Successfully generated: {output_script}")
        print(f"    -> Usage: python {output_script} > seeds.txt")
        
    except Exception as e:
        print(f"[-] Code Generation Failed: {e}")

# ==============================================================================
if __name__ == "__main__":
    # 이전 단계에서 생성된 JSON 파일명 (예시)
    num = "0796"
    blueprint_file = f"fuzz_seed_blueprint_{num}.json" 
    # 생성할 파이썬 스크립트명
    output_py = f"fuzzer_{num}_impacket.py"

    generate_impacket_script(blueprint_file, output_py)