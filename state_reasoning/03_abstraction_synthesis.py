import re
import json
import os
from openai import OpenAI

MODEL = "gpt-5.2"  # gpt-5.2-codex 대신 사용 (API에서 사용 가능)

client = OpenAI()

def clean_json_output(response_text):
    """LLM 응답에서 Markdown 코드 블록(```json ... ```)을 제거하고 순수 문자열만 추출"""
    cleaned = response_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned

def derive_abstraction_synthesis(summary_file, driver_name, function_name):
    # 파일 존재 여부 확인 및 로드
    if not os.path.exists(summary_file):
        print(f"[-] Error: File {summary_file} not found.")
        return json.dumps({"error": "File not found"})

    # with open(summary_file, 'r') as f:
    with open(summary_file, 'r', encoding='utf-8') as f:
        cim_output = json.load(f)

    # ==============================================================================
    # PHASE 1: Initial Research (Constraint-Guided Standard Path Derivation)
    # ==============================================================================
    abstraction_synthesis_prompt = f"""
    Role: Senior Exploit Developer & Network Protocol Engineer.

    [Objective]
    You are the 'Abstraction Synthesis Module' (ASM). Your goal is to translate an 'Optimized Abstract Sequence' into a concrete, executable Python reproduction script.
    You must strictly follow the "Validation-by-Construction" methodology: use high-level libraries (Impacket, Scapy) to guarantee protocol correctness (checksums, session states, sequence numbers) for the transport/handshake layers, and only manually manipulate the raw bytes for the specific 'Trigger' step defined by the constraints.

    [Input Data]
    - Target Driver: {driver_name}
    - Target Function: {function_name}
    - Abstract Sequence (from CIM): 
    {json.dumps(cim_output)}

    [Reasoning Guidelines - Validation-by-Construction]
    1. LIBRARY SELECTION: Prefer 'Impacket' for high-level Windows protocols (SMB, DCERPC, NTLM) to handle authentication and session state automatically. Use 'Scapy' only if raw TCP/IP fragmentation or lower-level manipulation is explicitly required by the constraint.
    2. STATE CONTINUITY: You must maintain state variables across steps.
       - Example: The 'SessionId' returned from Step 2 (Session Setup) must be passed into the header of Step 3 (Tree Connect).
       - Do not create new connections for each step unless specified.
    3. HYBRID PAYLOAD CONSTRUCTION:
       - For standard headers: Use library classes (e.g., `smb2.SMB2Packet()`).
       - For the TRIGGER step: You may need to override specific fields or append raw bytes to satisfy the `critical_constraints` (e.g., `packet['Header_Size'] = 0xFFFFFFFF` to trigger overflow).
    4. NO HALLUCINATED CONSTANTS: Do not invent magic numbers. Use values derived from the `critical_constraints` or standard protocol defaults.

    [Chain-of-Thought Steps]
    Step 1: API & Object Mapping
    - Map each 'step_category' from the input to a specific Library Class/Method.
    - (e.g., "Negotiate" -> `impacket.smb3.SMB3.negotiate()`)
    
    Step 2: Data Flow Planning
    - Identify which variables need to be captured and reused.
    - (e.g., "Need to capture `TreeId` from `TreeConnect` response to use in `Create` request.")
    
    Step 3: Constraint Implementation (The Trigger)
    - Focus on the 'Trigger' step. How will you implement the `critical_constraints`?
    - Explain how to use the library to create a malformed packet (e.g., "I will instantiate a valid SMB2Packet, then manually set `OriginalSize` to `0xFFFFFFFF` before serialization").

    [Output Format]
    Return ONLY a valid JSON object.
    
    {{
      "step": "Abstraction_Synthesis",
      "reasoning": {{
        "library_strategy": "Explanation of libraries chosen (e.g., Impacket for auth, raw struct packing for payload).",
        "state_management": "How session/tree IDs are passed between steps.",
        "trigger_logic": "Specific code logic to implement the vulnerability constraint (e.g., 'Overriding struct field X with overflow value')."
      }},
      "reproduction_script": "Full Python script code here..."
    }}
    """

    print(f"[+] Phase 1: Deriving Initial Standard Path for {function_name}...")
    try:
        response_1 = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are an expert exploit developer and binary security researcher. Generate precise, executable Python code for vulnerability reproduction following the Validation-by-Construction methodology."},
                {"role": "user", "content": abstraction_synthesis_prompt}
            ],
            temperature=0.0
        )
        abstraction_synthesis_json_str = clean_json_output(response_1.choices[0].message.content)
        abstraction_synthesis_json = json.loads(abstraction_synthesis_json_str)
        print("    -> Phase 1 Complete. Initial path derived.")
        # print(json.dumps(abstraction_synthesis_json, indent=2))
        return json.dumps(abstraction_synthesis_json, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Phase 1 failed: {str(e)}"})

def save_python_script(json_output, py_filename):
    """JSON 결과에서 Python 스크립트를 추출하여 지정된 파일로 저장"""
    try:
        data = json.loads(json_output)
        if "reproduction_script" not in data:
            print("[-] Warning: No reproduction_script found in output")
            return False
        
        py_code = data["reproduction_script"]
        
        if not py_code:
            print("[-] Warning: No code found in reproduction_script")
            return False
        
        with open(py_filename, "w", encoding='utf-8') as f:
            f.write(py_code)
        
        print(f"[+] Python script saved to {py_filename}")
        return True
    
    except json.JSONDecodeError as e:
        print(f"[-] Error: Failed to parse JSON output - {str(e)}")
        return False
    except Exception as e:
        print(f"[-] Error while saving Python script: {str(e)}")
        return False

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # CONFIGURATION
    # ------------------------------------------------------------------
    # Case 1
    driver = "srv2.sys"
    func = "Srv2DecompressData"
    num = "0796"

    # Case2
    # driver = "srv2.sys"
    # func = "Smb2ValidateVolumeObjectsMatch"
    # num = "32230"

    # Case3
    # driver = "srv2.sys"
    # func = "Smb2ValidateSigningCapabilities"
    # num = "43642"

    input_file = f"state_sequence_{num}_v4_{MODEL}.json"
    py_output_file = f"03_reproduce_{num}_v4_{MODEL}.py"

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    final_output = derive_abstraction_synthesis(input_file, driver, func)
    
    # JSON 결과 저장
    json_output_filename = f"03_abstraction_synthesis_{num}_v4_{MODEL}.json"
    with open(json_output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {json_output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)
    
    # Python 스크립트 추출 및 저장
    print(f"\n[*] Extracting and saving Python script to {py_output_file}...")
    if save_python_script(final_output, py_output_file):
        print("[+] Python script extraction completed successfully!")
    else:
        print("[-] Python script extraction failed.")
