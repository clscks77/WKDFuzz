
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
    [Role]
    Protocol State Logic Architect & Causal Inference Engine.

    [Objective]
    You are the 'Causal Inference Module' (CIM). Your goal is to construct the *minimal sufficient sequence* of abstract protocol states required to reach the vulnerability location described in the provided Semantic Anchor.
    You must use 'Backward Chaining' logic: Start from the target state and deduce the necessary pre-conditions based on your internalized knowledge of the protocol.

    [Input Data]
    - Target Driver: {driver_name}
    - Target Function: {function_name}
    - Semantic Anchor (from SAM): 
    {json.dumps(summary_data)}

    [Reasoning Guidelines - The 'Backward Chaining' Approach]
    1. START AT THE END: Begin with the `required_capability` defined in the Semantic Anchor.
    2. DEDUCE DEPENDENCIES: Ask "What prior state is strictly required to enable this capability?".
    3. PRUNE NOISE (Counterfactual Check): For every step, ask: "If I skip this step, is the target still reachable?"
    4. ABSTRACT ACTIONS: Do not write code yet. Define 'Abstract Actions'.

    [Chain-of-Thought Steps]
    Step 1: Anchor Analysis
    - Review the `semantic_constraint` and `required_capability` from the input. What is the specific protocol feature?

    Step 2: Backward State Resolution
    - Trace back from the Target Function to identify the minimal set of prior states and messages needed.
    - For each required state, identify the specific protocol message that establishes it.
    - Build a dependency chain until you reach the "Initial/Unconnected" state.

    Step 3: Noise Pruning
    - Filter out standard but unnecessary traffic unless they alter the state needed for the exploit.

    Step 4: Constraint Propagation
    - Ensure the constraints from SAM are applied to the relevant setup steps.

    [Output Format]
    Return ONLY a valid JSON object. Do not include markdown formatting (```json ... ```) or conversational text.
    The output must strictly follow this Hybrid Schema to demonstrate both the reasoning process and the actionable result:

    {{
      "module": "Causal_Inference",
      "reasoning_trace": {{
        "backward_dependency_chain": [
          "Step-by-step logic trace from Target back to Initial State.",
          "Format: [Target State] -> depends_on -> [Pre-condition] -> depends_on -> [Initial State]",
        ],
        "pruning_decisions": [
          {{
            "excluded_action": "Name of the step removed",
            "reason": "Counterfactual explanation: Why is this step NOT required?"
          }}
        ]
      }},
      "final_optimized_sequence": [
        {{
          "step_index": 1,
          "step_category": "Category",
          "packet_name": "Standard Protocol Name",
          "state_intent": "The 'Macro-Goal' of this packet.",
          "critical_constraints": [
            "Specific flags or fields that MUST be set."
          ]
        }},
        {{
          "step_index": N,
          "step_category": "Trigger",
          "packet_name": "The Malicious/Trigger Packet",
          "state_intent": "Deliver the payload to the Semantic Anchor.",
          "critical_constraints": [
            "Constraint derived from Semantic Anchor."
          ]
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

    input_file = f"binary_constraints_summary_{num}_v3_{MODEL}.json" 

    # ------------------------------------------------------------------
    # EXECUTION
    # ------------------------------------------------------------------
    # 1. 시퀀스 도출 (Two-Step Process)
    final_output = derive_state_sequence(input_file, driver, func)
    
    # 2. 결과 저장
    output_filename = f"state_sequence_{num}_v4_{MODEL}.json"
    with open(output_filename, "w", encoding='utf-8') as f:
        f.write(final_output)
    
    print(f"\n[Success] Final Optimized Sequence saved to {output_filename}")
    print("-" * 60)
    print(final_output)
    print("-" * 60)