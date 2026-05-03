import os
import json
from openai import OpenAI

client = OpenAI()

def semantic_alignment(full_vuln_code, patch_diff_info, target_driver, target_function):
    """
    Phase 2: Semantic Alignment & Constraint Extraction
    Goal: Analyze Gatekeepers and Vulnerability Logic with specific driver context.
    """
    
    # Protocol-Agnostic Prompt with Context Injection
    prompt = f"""
    Role: Windows Kernel Binary Vulnerability Researcher.
    Task: Analyze the provided Assembly Code to extract (1) Reachability Constraints (Gatekeepers) and (2) Vulnerability Logic.

    **[Input Context]**
    - **Target Driver**: {target_driver} (Hint for Protocol Context)
    - **Target Function**: {target_function} (Hint for Functionality)

    **[Input 1: Full Vulnerable Function Code]** (The Execution Flow)
    Focus on: Conditional jumps (`jb`, `jz`, `jnz`, `ja`) acting as "Gatekeepers" (Early Exit).
    {full_vuln_code}

    **[Input 2: Patch/Diff Information]** (The Root Cause)
    {patch_diff_info}

    **Analysis Framework (General Kernel Driver Patterns)**:
    1. **Identify Gatekeepers (Reachability)**:
       - Scan Input 1 from the top. Identify checks (`cmp`, `test`) performed *before* the vulnerable instruction.
       - **Magic Numbers & Signatures**: Check for constants. **Interpret broadly**:
         - Could be Protocol Magic (e.g., 0xFE534D42).
         - Could be **Structure Tags / Object Signatures** (Common in Kernel).
         - Could be **Version Fields**.
         - Could be **Enum Discriminators** (Switch case values).
       - **State/Context Check**: Checks on offsets (e.g., `[reg+0x28]`) often imply a required connection/session state.
       - **Header Validation**: Size/Length checks against minimum values.

    2. **Identify Trigger Logic (Vulnerability)**:
       - Use Input 2 to pinpoint the exact instruction.
       - Explain the logic error (e.g., Integer Overflow, Type Confusion).

    **Output Requirement**:
    Output ONLY a valid JSON object.
    
    Format:
    {{
      "inferred_protocol_hint": "Protocol name. If uncertain, generate a descriptive name (e.g., 'Unknown_Proprietary_Protocol' or 'Driver_Specific_Header'). DO NOT leave empty.",
      "target_function_context": "Brief summary of what this function does.",
      "reachability_constraints": [
        {{
          "address": "Hex Address",
          "instruction": "Assembly instruction",
          "check_type": "Magic/Signature, State/Context, or Header/Size",
          "inference": "What is being checked? (e.g., 'Checks if Object Tag is 'SmbS')",
          "required_state": "Condition to pass (e.g., 'Must provide header with Version 1')"
        }}
      ],
      "vulnerability_logic": {{
        "bug_type": "Bug Class",
        "trigger_strategy": "How to exploit"
      }}
    }}
    """

    print(f"[+] Phase 2: Analyzing {target_driver}::{target_function}...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o", 
            messages=[
                {"role": "system", "content": "You are a binary analysis expert. Output valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0,
            response_format={"type": "json_object"} # API 차원에서 JSON 강제
        )
        content = response.choices[0].message.content

        # 혹시 모를 Markdown 태그 제거 (이중 안전장치)
        if content.strip().startswith("```json"):
            content = content.replace("```json", "").replace("```", "").strip()
            
        return content

    except Exception as e:
        return json.dumps({"error": str(e)})

# --- Execution Example ---
if __name__ == "__main__":

    # Input Code (Simulated for srv2.sys)
    vulnerable_snippet = """
    TODO
    """

    patched_snippet = """
    TODO
    """

    # User Inputs (Variables)
    t_driver = "TODO"
    t_func = "TODO"

    # 4. Run Analysis
    result_json = semantic_alignment(vulnerable_snippet, patched_snippet, t_driver, t_func)
    
    # 5. Save Output
    output_filename = "binary_constraints_summary_0796.json"
    try:
        parsed = json.loads(result_json)
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(parsed, f, indent=4, ensure_ascii=False)
        print(f"[+] Constraints Saved to {output_filename}")
        # print(json.dumps(parsed, indent=2)) # 결과 확인용
    except json.JSONDecodeError as e:
        print("[-] JSON Parse Error. Cleaned Content:")
        print(result_json)
        print(f"Error details: {e}")
    except Exception as e:
        print(f"[-] Unexpected Error: {e}")