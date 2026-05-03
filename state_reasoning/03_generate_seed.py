import os
import json
import re
from openai import OpenAI

client = OpenAI()

def clean_python_output(text):
    """LLM 응답에서 Python 코드 블록만 추출"""
    cleaned = text.strip()
    match = re.search(r"```(?:python)?\s*(.*?)\s*```", cleaned, re.DOTALL)
    return match.group(1) if match else cleaned

def phase_3_impacket_gen(sequence_file, constraints_file, output_script_name):
    # 1. Input Validation
    if not os.path.exists(sequence_file) or not os.path.exists(constraints_file):
        print(f"[-] Error: Input files missing.\n    {sequence_file}\n    {constraints_file}")
        return

    # 2. Load Context from Phase 1 & 2 Artifacts
    with open(sequence_file, 'r', encoding='utf-8') as f:
        seq_data = json.load(f)
        optimized_sequence = seq_data.get("final_optimized_sequence", seq_data)
        # Protocol Hint가 없으면 SMB2를 기본값으로
        protocol_hint = seq_data.get("inferred_protocol_family", "SMB2/SMB3")

    with open(constraints_file, 'r', encoding='utf-8') as f:
        summary_data = json.load(f)
        # Constraints와 Vuln Logic 분리
        constraints = summary_data.get("reachability_constraints", [])
        vuln_logic = summary_data.get("vulnerability_logic", {})

    print(f"[+] Phase 3: Generating Impacket-Based Hybrid Fuzzer...")
    print(f"    - Protocol: {protocol_hint}")
    print(f"    - Strategy: Impacket (Setup) + Struct (Trigger)")

    # 3. Construct the Research-Grade Prompt
    prompt = f"""
        Role: Senior Exploit Developer & Network Security Researcher.
        Task: Generate a Python script using the `impacket` library to create a high-fidelity fuzzing seed.

        **[Strategy: Hybrid Generation]**
        1.  **State Establishment (Validity):** Use `impacket` to generate perfectly valid Negotiate and Session Setup packets. This solves the "Dialect Mismatch" and "Empty NTLM" issues automatically.
        2.  **Vulnerability Trigger (Exploit):** Use `struct` to manually construct the malformed/vulnerable packet, as `impacket` might prevent us from creating invalid headers.

        **[Input Context]**
        - **Target Sequence**: {json.dumps(optimized_sequence, indent=2)}
        - **Binary Constraints**: {json.dumps(constraints, indent=2)}
        - **Vulnerability Logic**: {json.dumps(vuln_logic, indent=2)}

        **CODE GENERATION REQUIREMENTS (Strictly Follow)**:

        **1. Setup Phase (Impacket)**:
        - Import: `from impacket.smb3structs import *`, `from impacket import ntlmssp`
        - **Function `get_negotiate()`**:
            - Create `SMB2Packet` with `SMB2_COM_NEGOTIATE`.
            - Use `SMB2Negotiate_Request`. Set Dialects to include `SMB2_DIALECT_311`.
            - **CRITICAL**: You MUST add a `NegotiateContext` of type `SMB2_COMPRESSION_CAPABILITIES` (Value: `0x03`). Without this, the target ignores compressed packets.
        - **Function `get_session_setup()`**:
            - Create `SMB2Packet` with `SMB2_COM_SESSION_SETUP`.
            - Use `SMB2SessionSetup_Request`.
            - Generate a valid NTLM Type 1 blob using `ntlmssp.getNTLMSSPType1()`. Assign this to the `Buffer`.

        **2. Trigger Phase (Struct)**:
        - **Function `get_trigger()`**:
            - Do NOT use impacket here. We need raw byte manipulation.
            - Analyze the **[Binary Constraints]**. Map offsets to fields.
            - **Apply [Vulnerability Logic]**:
                - If logic is "Integer Overflow", set the mapped field (e.g., `OriginalCompressedSegmentSize`) to a malicious value (e.g., `0xFFFFFFFF`).
            - **Structure**: `\\xfcSMB` (4s) + `OriginalSize` (I) + `Algorithm` (H) + `Flags` (H) + `Offset` (I) + `Payload`.
            - Format String: `'<4s I H H I'`

        **3. Output**:
        - Provide a complete, runnable Python script.
        - The `main()` function should print the HEX representation of all 3 packets.
        - Add comments explaining how the constraints mapped to the trigger packet.
    """

    # 4. Request Generation
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an expert in SMB internals and Impacket. Generate working exploit code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        
        # 5. Process and Save Output
        code = clean_python_output(response.choices[0].message.content)
        
        with open(output_script_name, 'w', encoding='utf-8') as f:
            f.write(code)
            
        print(f"    -> Successfully generated: {output_script_name}")
        print(f"    -> Dependencies needed: pip install impacket")
        print(f"    -> Run: python {output_script_name}")
        
    except Exception as e:
        print(f"[-] Generation Failed: {e}")

# ==============================================================================
# EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    # Case Number (0796)
    case_num = "0796"
    
    # Define File Paths (Using variables from your environment)
    input_constraints = f"binary_constraints_summary_{case_num}_v2.json"
    input_sequence = f"state_sequence_{case_num}_v4.json"
    
    # Output File Name
    output_script = f"poc_generator_{case_num}_impacket.py"

    # Run Phase 3
    phase_3_impacket_gen(input_sequence, input_constraints, output_script)