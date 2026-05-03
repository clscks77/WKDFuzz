
# 차선

import re
import json
import os
from openai import OpenAI

MODEL = "gpt-5.2"  # gpt-4o

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

    # with open(summary_file, 'r') as f:
    with open(input_file, 'r', encoding='utf-8') as f:
        summary_data = json.load(f)

    # ==============================================================================
    # PHASE 1: Initial Research (Constraint-Guided Standard Path Derivation)
    # ==============================================================================
    initial_prompt = f"""
    Role: Protocol State Machine Architect & Causal Logic Reasoner.

    [Objective]
    You are the 'Causal Inference Module' (CIM). Your goal is to construct the minimal viable state transition sequence required to reach a specific vulnerable state in a Windows Kernel Driver.
    You must use "Backward Chaining" logic to determine dependencies and "Counterfactual Pruning" to remove unnecessary steps.

    [Input Data]
    - Target Driver: {driver_name}
    - Target Function: {function_name}
    - Semantic Anchor (From previous step): 
    {json.dumps(summary_data)}

    [Reasoning Guidelines - The 'Backward State Resolution' Method]
    1. START AT THE TARGET: Begin with the 'required_capability' and 'semantic_constraint' defined in the Input Data.
    2. BACKWARD CHAINING: Ask "What acts as a pre-condition for this state?" 
       - Example: To send a Compressed Packet (Target), the session must have Negotiated Compression (Pre-condition 1). To Negotiate, a Connection must be established (Pre-condition 2).
    3. COUNTERFACTUAL PRUNING (CRITICAL): For every potential step, ask: "If I remove this step, does the Target State become unreachable?"
       - If the answer is "Yes", KEEP IT.
       - If the answer is "No", DISCARD IT.
    4. MINIMALISM: The sequence must be the *shortest possible path* to trigger the function.

    [Chain-of-Thought Steps]
    Step 1: Anchor Analysis
    - Identify the specific protocol feature triggered.
    
    Step 2: Dependency Mapping
    - Trace back the dependencies based on Protocol Axioms (e.g., MS-SMB2).
    - Does 'Srv2DecompressData' happen before or after Session Setup? (Hint: Decompression usually happens at the transport/connection layer, but requires Session keys or Negotiated Context).
    
    Step 3: Sequence Construction
    - Order the essential steps chronologically: Connection -> Negotiation -> Authentication -> Trigger.
    - Name the packets using standard protocol terminology (e.g., SMB2_NEGOTIATE, SMB2_SESSION_SETUP).

    [Output Format]
    Return ONLY a valid JSON object containing the "final_optimized_sequence" list.
    
    {{
      "final_optimized_sequence": [
        {{
          "step_index": 1,
          "step_category": "Category",
          "packet_name": "Standard Packet Name",
          "rationale": "Why is this step strictly necessary?"
        }},
        {{
          "step_index": 2,
          "step_category": "...",
          "packet_name": "...",
          "rationale": "..."
        }},
        ...
        {{
          "step_index": N,
          "step_category": "Trigger",
          "packet_name": "The packet containing the Semantic Constraint",
          "rationale": "Explains how this triggers the target function based on the Semantic Anchor."
        }}
      ]
    }}
    """

    print(f"[+] Phase 1: Deriving Initial Standard Path for {function_name}...")
    try:
        response_1 = client.chat.completions.create(
            model=MODEL,
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
        return json.dumps(initial_json, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Phase 1 failed: {str(e)}"})

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

    input_file = f"binary_constraints_summary_{num}_v3_{MODEL}.json" 

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    # 1. 시퀀스 도출 (Two-Step Process)
    final_output = derive_state_sequence(input_file, driver, func)
    
    # 2. 결과 저장
    output_filename = f"state_sequence_{num}_v4-2_{MODEL}.json"
    with open(output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)