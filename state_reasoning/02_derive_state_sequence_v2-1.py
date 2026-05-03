import re
import json
import os
from openai import OpenAI

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
    # PHASE 1: Initial Research (Constraint-Guided Standard Path Derivation)
    # ==============================================================================
    initial_prompt = f"""
        Role: Senior Vulnerability Research Scientist specializing in Kernel Drivers and Network Protocols.
        Task: Reconstruct the minimal state transition path required to reach a specific vulnerable function within a target driver.
        
        **[Input Context]**
        - **Target Driver**: "{driver_name}"
        - **Target Function**: "{function_name}" ( The vulnerable endpoint )
        
        **[Binary Analysis Artifacts]**
        - **Path Constraints**: {json.dumps(summary_data, indent=2)}
        (Note: This JSON contains hard-coded checks found in the binary path to the function, such as magic numbers, size checks, or specific enum values.)

        **REASONING FRAMEWORK (Execute Step-by-Step)**:

        **Phase 1: Protocol Schema Inference**
        1. Infer the target protocol family based on the `{driver_name}`.
        2. Define the **"State Model"** for this protocol. Do NOT list all packets. Instead, define the abstract states a client must acquire to interact with deep functionality.
        - *Definition:* A "State" is a credential or context (e.g., Established Connection, Authenticated Session, Object Handle) required to send subsequent commands.

        **Phase 2: Target Anchoring via Constraint Alignment**
        1. Analyze the `{function_name}` semantics.
        2. **CRITICAL**: Cross-reference the **[Path Constraints]** (Magic Numbers, Enums) with your knowledge of the protocol's message structures.
        3. Identify the specific **Target Message/Command** that routes to this function.
        - *Reasoning Rule:* If the function semantics imply 'X', but the binary constraint checks for a magic value associated with 'Y', prioritize the binary evidence ('Y').

        **Phase 3: Backward State Resolution (The Chain)**
        1. Determine the **Pre-requisite State** required to send the Target Message identified in Phase 2.
        2. Identify the **Setup Message** responsible for granting this Pre-requisite State.
        3. Repeat this backward chaining until you reach the "Initial/Unconnected" state.
        4. *Filtering Rule:* Exclude extraneous business logic messages (e.g., Read/Write/Query) unless they are explicitly required to change the state needed for the Target Message. Focus ONLY on Control Plane / Handshake / Context Setup messages.

        **Phase 4: Forward Sequence Construction**
        - Reverse the chain from Phase 3 to form a chronological execution flow.
        - Assign a generic step name (e.g., "Initialization", "Authentication", "Context Creation") to each step.

        For every inferred state, message, or protocol rule:
        - Explicitly tag the knowledge source: [Binary Evidence | Public Spec | MS Documentation | Inferred Heuristic | Assumption]
        - Assign a confidence level. If a step relies purely on assumption, it MUST be marked as such.

        **Output Requirement**:
        Output ONLY a valid JSON object. Do not explain outside the JSON.

        Format:
        {{
        "inferred_protocol_family": "String",
        "phase_2_anchor_reasoning": "String (Explain how function name AND binary constraints (magic numbers/enums) point to the specific Target Message)",
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
            "step_category": "String (Abstract Stage, e.g., Setup/Auth)",
            "packet_name": "String (Technical Name)",
            "rationale": "String (Why is this strictly necessary for the next step?)"
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
        # print(json.dumps(initial_json, indent=2))

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

    input_file = f"binary_constraints_summary_{num}_v2.json" 

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    # 1. 시퀀스 도출 (Two-Step Process)
    final_output = derive_state_sequence(input_file, driver, func)
    
    # 2. 결과 저장
    output_filename = f"state_sequence_{num}_v4.json"
    with open(output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)