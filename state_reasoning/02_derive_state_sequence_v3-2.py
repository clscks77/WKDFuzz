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
        Role: Windows Kernel Network Stack Analyst & Protocol Fuzzing Architect.

        Task:
        Construct a generic "Reachability State Sequence" to trigger a specific kernel function.
        You must generalize beyond specific protocols (like SMB) and apply "Protocol State Machine" logic applicable to any Windows Kernel Driver (e.g., HTTP.sys, tcpip.sys, condrv.sys, etc.).

        [Input Artifacts]
        - Target Driver: "{driver_name}"
        - Target Function: "{function_name}" ( The vulnerable endpoint )
        - Vulnerability Context & Binary Constraints: {json.dumps(summary_data)}

        [GENERIC INFERENCE METHODOLOGY]

        Step 1: Protocol & Layer Identification
        * Analyze the function name prefix.
        * Determine the abstract protocol layer:
            * **L2/L3:** Raw packet processing (IP/TCP headers).
            * **L7/Application:** High-level parsing (HTTP Requests, RPC calls).
            * **IOCTL/Interface:** Local communication via DeviceIoControl.

        Step 2: Function Lifecycle Placement
        * Where does this function sit in the connection lifecycle?
            * **Initialization:** Handshake, Capability Negotiation (e.g., SYN, Hello).
            * **Context Setup:** Authentication, Session Creation, Object Binding.
            * **Dispatch/Action:** Processing specific commands, queries, or data payloads.
            * **Teardown:** Closing handles, freeing memory.
        * *Hint:* "Validate", "Parse", "Check" usually happen *immediately upon receiving a specific packet type*.

        Step 3: Constraint Translation (Assembly -> Protocol Logic)
        * Translate binary constraints into protocol requirements:
            * `cmp [offset], value` -> Requires a specific **Header Flag** or **Version Field**.
            * `test ptr, ptr` (Null Check) -> Requires a pre-allocated **Session/Object Context**.
        * **Bug Strategy:** If the bug is "Null Pointer Dereference", the sequence must create a *Partial State* (e.g., Authenticated but no Resource allocated) or use a *Mismatched Object Type* (e.g., Sending a Data packet on a Control channel).

        Step 4: Abstract Sequence Generation
        * Build a 3~5 step sequence using generic categories.
        * **Step 1:** Protocol Handshake (Version/Capability).
        * **Step 2:** Context Establishment (Session/Auth).
        * **Step 3:** Resource/Object Allocation (File, Socket, Stream).
        * **Step 4 (Trigger):** The specific Command/Packet that invokes the target function.

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
        phase2_json_str = clean_json_output(response_2.choices[0].message.content)
        # Validate JSON parsing
        phase2_json = json.loads(phase2_json_str)
        print("    -> Phase 2 Complete. Optimization finished.")

    except Exception as e:
        return json.dumps({"error": f"Phase 2 failed: {str(e)}"})
    
    # ==============================================================================
    # PHASE 3: Self-Correction2 (Check Triggeribility of the Optimized Path)
    # ==============================================================================
    verification_prompt = f"""
        Role: Reverse Engineering Lead & Protocol Architecture Critic.
        Task: Verify the accuracy of the "Trigger Packet" identified in the previous optimization step and correct it if a more logically precise call path exists.

        **[Input Context]**
        - **Target Function**: "{function_name}"
        - **Previous Best Guess**: {phase2_json_str} (Note: The user suspects this might be hallucinated or imprecise.)
        - **Vulnerability Context**: {json.dumps(summary_data)}

        **VERIFICATION LOGIC (Execute Step-by-Step)**:

        **Step 1: Dispatch Strategy Analysis (Generic vs. Specific)**
        Analyze how Windows Kernel Drivers typically route packets to the function `{function_name}`.
        Determine which "Dispatch Category" this function belongs to:
        
        * **Category A: Generic Administration (IOCTL)**
            * *Indicator:* The function handles driver configuration, debugging, or non-standard operations.
            * *Trigger:* `IRP_MJ_DEVICE_CONTROL` with a specific IOCTL Code.
        
        * **Category B: Protocol-Specific Command (The "Verb")**
            * *Indicator:* The function implements a core protocol action (e.g., Querying attributes, Reading data, Establishing context).
            * *Trigger:* A specific Protocol Opcode.
            
        * **Heuristic Rule:** Vulnerabilities in "Validation" or "Parsing" logic usually reside in **Category B** (Specific Commands) because these handlers process complex, variable-length user payloads.

        **Step 2: Semantic Mapping (The "Action" Test)**
        Analyze the *semantics* of `{function_name}` based on its name and constraints:
        - If the function validates *metadata* or *attributes* -> Look for **QUERY/GET** commands.
        - If the function validates *configuration changes* -> Look for **SET/POST** commands.
        - If the function validates *buffer sizes* for snapshots/backups -> Look for **IOCTL** or **FSCTL**.
        
        *Critique the Previous Guess:* Does the previous guess (e.g., IOCTL) match the *semantic action*? Or is there a more precise Protocol Command (e.g., QUERY_INFO) that maps 1:1 to this logic?

        **Step 3: Call Graph Reconstruction**
        Simulate the call stack.
        - [Protocol Dispatcher] -> [Switch Statement on Opcode] -> [Specific Handler] -> `{function_name}`
        - Identify the **[Specific Handler]** that is the *direct parent* of the target function.
        - The "Trigger Packet" MUST be the packet that invokes this specific handler.

        **Output Requirement**:
        Output ONLY a valid JSON object.

        Format:
        {{
            "analysis_correction": {{
                "critique_of_previous_guess": "String (Why was IOCTL likely incorrect or less precise?)",
                "identified_call_path": "String (e.g., Smb2QueryInfo -> ValidateVolume...)",
                "confidence_score": "High/Medium/Low"
            }},
            "final_verified_sequence": [
                // Keep the setup steps (Negotiate/Session/Tree/Create) from the input if valid.
                // Replace ONLY the final trigger step with the corrected packet and rationale.
                {{
                    "step_index": N,
                    "step_category": "Trigger",
                    "packet_name": "CORRECTED_PACKET_NAME (e.g., SMB2_QUERY_INFO)",
                    "rationale": "String (Technical justification based on call graph)"
                }}
            ]
        }}
    """

    print(f"[+] Phase 3: Checking Triggeribility of the Optimized Path.")
    try:
        response_3 = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an exploit developer. Confirm the path can trigger the target function."},
                {"role": "user", "content": verification_prompt}
            ],
            temperature=0.0
        )
        final_json_str = clean_json_output(response_3.choices[0].message.content)
        # Validate JSON parsing
        final_json = json.loads(final_json_str)
        print("    -> Phase 3 Complete. Triggeribility check finished.")
        return json.dumps(final_json, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Phase 3 failed: {str(e)}"})

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # CONFIGURATION
    # ------------------------------------------------------------------
    # Case 1
    # driver = "srv2.sys"
    # func = "Srv2DecompressData"
    # num = "0796"

    # Case2
    # driver = "srv2.sys"
    # func = "Smb2ValidateVolumeObjectsMatch"
    # num = "32230"

    # Case3
    driver = "srv2.sys"
    func = "Smb2ValidateSigningCapabilities"
    num = "43642"

    input_file = f"binary_constraints_summary_{num}_v2.json" 

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    # 1. 시퀀스 도출 (Two-Step Process)
    final_output = derive_state_sequence(input_file, driver, func)
    
    # 2. 결과 저장
    output_filename = f"state_sequence_{num}_v3-2.json"
    with open(output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)