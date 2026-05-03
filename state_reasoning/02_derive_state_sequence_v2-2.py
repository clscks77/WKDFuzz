import re
import json
import os
from openai import OpenAI

# OpenAI 클라이언트 설정 (환경 변수에 OPENAI_API_KEY가 설정되어 있어야 합니다)
client = OpenAI()

def clean_json_output(response_text):
    """LLM 응답에서 Markdown 코드 블록(```json ... ```)을 제거하고 순수 문자열만 추출"""
    cleaned = response_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned

def derive_state_sequence(summary_file, driver_name, function_name):
    # 파일 존재 여부 확인 및 로드
    if not os.path.exists(summary_file):
        print(f"[-] Error: File {summary_file} not found.")
        return json.dumps({"error": "File not found"})

    with open(summary_file, 'r') as f:
        summary_data = json.load(f)

    # ==============================================================================
    # 실험: Initial 단계에서만 Binary Analysis Artifacts가 없을 경우
    # ==============================================================================
    initial_prompt = f"""
        Role: Senior Vulnerability Research Scientist specializing in Kernel Drivers and Network Protocols.
        Task: Reconstruct the logical state transition path required to reach a specific target function based on protocol specifications and function semantics.
        
        **[Input Context]**
        - **Target Driver**: "{driver_name}"
        - **Target Function**: "{function_name}" ( The vulnerable endpoint )
        
        **REASONING FRAMEWORK (Execute Step-by-Step)**:

        **Phase 1: Protocol Schema Inference**
        1. Identify the protocol family implementing `{driver_name}`.
        2. Define the **"State Model"** for this protocol based on Public Specifications (RFC, MS Docs).
        - *Definition:* A "State" is a credential or context (e.g., Established Connection, Authenticated Session) required to reach deep code paths.

        **Phase 2: Semantic Mapping (Function to Message)**
        1. Analyze the `{function_name}` semantics. Break down the naming convention (Prefix, Verb, Noun).
        2. **Map to Protocol Spec**: Correlate the function name with known protocol message types or IRP Major Functions.
        3. Deduce the **Target Message/Command** most likely to route to this function.
        - *Heuristic:* If the function implies a specific action, identify the specific protocol command that carries that data type.

        **Phase 3: Backward State Resolution (The Chain)**
        1. Determine the **Pre-requisite State** required to legitimately send the Target Message identified in Phase 2.
        2. Identify the **Setup Message** responsible for establishing this state.
        3. Repeat this backward chaining until you reach the "Initial/Unconnected" state.
        4. *Filtering Rule:* Focus ONLY on Control Plane / Handshake / Context Setup messages necessary to satisfy the dependency.

        **Phase 4: Forward Sequence Construction**
        - Reverse the chain from Phase 3 to form a chronological execution flow.
        - Assign a generic step name (e.g., "Initialization", "Authentication").

        **Output Requirement**:
        Output ONLY a valid JSON object. Do not explain outside the JSON.

        Format:
        {{
        "inferred_protocol_family": "String",
        "phase_2_inference_logic": "String (Explain how the function name maps to the specific protocol command based on specs)",
        "deduced_target_message": "String ( The specific command/opcode name )",
        "state_dependency_chain": [
            {{
            "required_state": "String (e.g., Valid Session ID)",
            "acquired_via_message": "String (The packet that creates this state)"
            }}
        ],
        "final_sequence": [
            {{
            "step_index": 1,
            "step_category": "String (Abstract Stage)",
            "packet_name": "String (Technical Name)",
            "rationale": "String (Why is this strictly necessary per the protocol spec?)"
            }},
            ...
        ]
        }}
    """

    print(f"[+] Phase 1: Deriving Initial Standard Path for {function_name}...")
    try:
        response_1 = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a methodical researcher. Prioritize binary constraints over standard protocol behavior."},
                {"role": "user", "content": initial_prompt}
            ],
            temperature=0.0
        )
        initial_json_str = clean_json_output(response_1.choices[0].message.content)
        initial_json = json.loads(initial_json_str)
        print("    -> Phase 1 Complete. Initial path derived.")

    except Exception as e:
        return json.dumps({"error": f"Phase 1 failed: {str(e)}"})

    # ==============================================================================
    # PHASE 2: Self-Correction (Optimization for Fuzzing)
    # ==============================================================================
    correction_prompt = f"""
        Role: Lead Exploit Researcher & Fuzzing Logic Specialist.
        Task: Critically review and optimize the "Standard Path" derived in Phase 1 to create an "Exploit Minimal Path".
        Goal: Eliminate any state setup steps that are NOT strictly required to trigger the code execution of the target function.

        **[Input Context]**
        - **Target Function**: "{function_name}"
        - **Phase 1 Derived Standard Path**: {initial_json_str}
        - **Binary Constraints**: {json.dumps(summary_data)}

        **OPTIMIZATION LOGIC (Execute Step-by-Step)**:

        **Step 1: Execution Pipeline Classification**
        Analyze the `{function_name}` semantics and constraints. Where does this function sit in the packet processing pipeline?
        
        * **Type A: Pre-computation / Data Transformation Layer**
            * *Characteristics:* Functions that handle data *representation* rather than business intent.
            * *Generic Keywords:* Decrypt, Decode, Decompress, Unpack, VerifyChecksum, Reassemble, ParseHeader.
            * *Execution Timing:* Executes **IMMEDIATELY** upon packet receipt to make the data readable, usually *BEFORE* the kernel parses the inner "Logical Context IDs" (e.g., UserID, TreeID, FileID).
            
        * **Type B: Business Logic / State Manipulation Layer**
            * *Characteristics:* Functions that act upon a specific resource or object.
            * *Generic Keywords:* Create, Open, Write, Read, Query, Set, IoControl.
            * *Execution Timing:* Executes **AFTER** the protocol stack has validated that the request belongs to a valid Session/Resource/Object.

        **Step 2: Dependency Pruning (The "Validation Gap" Test)**
        Apply this rule to the "Standard Path":
        
        * **IF the function is Type A (Data Transformation):**
            * **RULE:** The kernel must transform (Type A) the packet to even *see* the Resource IDs required for Type B. Therefore, the crash occurs *before* the validity of Resource/Object is checked.
            * **ACTION:** REMOVE all "Resource Context" (Level 3) and "Object Handle" (Level 4) setup steps.
            * **ACTION:** Only keep "Connection" (Level 1) and "Session/Auth" (Level 2) IF and ONLY IF the transformation requires session-bound keys.
            
        * **IF the function is Type B (Business Logic):**
            * **ACTION:** RETAIN the full state chain. The kernel will drop the packet if the Handle is invalid.

        **Step 3: Trigger Packet Identification (Container vs. Content)**
        * If Type A: The target is the **"Wrapper/Container Packet"** (the outer layer that requires transformation), NOT the inner command payload.
        * If Type B: The target is the specific **"Command Packet"** (the business request).

        **Output Requirement**:
        Output ONLY a valid JSON object.

        Format:
        {{
            "optimization_analysis": {{
                "classification": "Type A or Type B",
                "pipeline_reasoning": "String (Explain based on 'Pre-computation' vs 'Post-validation' logic)",
                "pruned_steps": ["List of steps removed"]
            }},
            "final_optimized_sequence": [
                {{
                    "step_index": 1,
                    "step_category": "String",
                    "packet_name": "String",
                    "rationale": "String (Why is this strictly minimal?)"
                }},
                ...
            ]
        }}
    """

    print(f"[+] Phase 2: Optimizing Path for Fuzzing Efficiency...")
    try:
        response_2 = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an exploit developer. Focus on bypassing checks and minimizing state."},
                {"role": "user", "content": correction_prompt}
            ],
            temperature=0.0
        )
        final_json_str = clean_json_output(response_2.choices[0].message.content)
        # Validate JSON parsing
        final_json = json.loads(final_json_str)
        print("    -> Phase 2 Complete. Optimization finished.")
        return json.dumps(final_json, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Phase 2 failed: {str(e)}"})


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # CONFIGURATION
    # ------------------------------------------------------------------
    # Case 1
    # driver = "srv2.sys"
    # func = "Srv2DecompressData"
    # num = "0796"

    # Case2
    driver = "srv2.sys"
    func = "Smb2ValidateVolumeObjectsMatch"
    num = "32230"

    # Case3
    # driver = "srv2.sys"
    # func = "Smb2ValidateSigningCapabilities"
    # num = "43642"

    input_file = f"binary_constraints_summary_{num}.json" 

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    # 1. 시퀀스 도출 (Two-Step Process)
    final_output = derive_state_sequence(input_file, driver, func)
    
    # 2. 결과 저장
    output_filename = f"state_sequence_{num}_v2-2.json"
    with open(output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)