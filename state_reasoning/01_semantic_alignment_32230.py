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

    print(f"[+] Phase 1: Analyzing {target_driver}::{target_function}...")
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
    ; Block 10651 @ 0x1c005bb7c
    0x1C005BB7C : mov ss: [rsp + arg_0], rbx
    0x1C005BB81 : push rdi
    0x1C005BB82 : sub rsp, 0x20
    0x1C005BB86 : mov rdi, ds: [rcx + 0x1F8]
    0x1C005BB8D : mov rax, ds: [rdi + 0x40]
    0x1C005BB91 : mov rcx, ds: [rax + 0x70]
    0x1C005BB95 : mov rax, ds: [rdi + 0x30]
    0x1C005BB99 : cmp ds: [rax + 0x89], 0
    0x1C005BBA0 : jnz 0x1C005BBE6
    
    ; Block 10652 @ 0x1c005bba2
    0x1C005BBA2 : mov rcx, ds: [rcx + 0x110]
    
    ; Block 10653 @ 0x1c005bba9
    0x1C005BBA9 : mov rcx, ds: [rcx + 0x50]
    0x1C005BBAD : call cs: [__imp_IoGetBaseFileSystemDeviceObject]
    0x1C005BBB4 : nop ds: [rax + rax 0]
    0x1C005BBB9 : mov rcx, ds: [rdi + 0x40]
    0x1C005BBBD : mov rbx, rax
    0x1C005BBC0 : mov rcx, ds: [rcx + 0x68]
    0x1C005BBC4 : mov rcx, ds: [rcx + 0x50]
    0x1C005BBC8 : call cs: [__imp_IoGetBaseFileSystemDeviceObject]
    0x1C005BBCF : nop ds: [rax + rax 0]
    0x1C005BBD4 : cmp rbx, rax
    0x1C005BBD7 : mov rbx, ss: [rsp + arg_0]
    0x1C005BBDC : setz al
    0x1C005BBDF : add rsp, 0x20
    0x1C005BBE3 : pop rdi
    0x1C005BBE4 : retn
    
    ; Block 10654 @ 0x1c005bbe6
    0x1C005BBE6 : mov rcx, ds: [rcx + 0x118]
    0x1C005BBED : jmp 0x1C005BBA9
    """

    patched_snippet = """
    ; Block 10821 @ 0x1c005cec4
    0x1C005CEC4 : mov ss: [rsp + arg_0], rbx
    0x1C005CEC9 : push rdi
    0x1C005CECA : sub rsp, 0x20
    0x1C005CECE : mov rdi, ds: [rcx + 0x1F8]
    0x1C005CED5 : mov rax, ds: [rdi + 0x30]
    0x1C005CED9 : cmp ds: [rax + 0x89], 0
    0x1C005CEE0 : jz 0x1C005CEEB
    
    ; Block 10822 @ 0x1c005cee2
    0x1C005CEE2 : mov rcx, ds: [rdx + 0x118]
    0x1C005CEE9 : jmp 0x1C005CEF2
    
    ; Block 10823 @ 0x1c005ceeb
    0x1C005CEEB : mov rcx, ds: [rdx + 0x110]
    
    ; Block 10824 @ 0x1c005cef2
    0x1C005CEF2 : test rcx, rcx
    0x1C005CEF5 : jnz 0x1C005CEFB
    
    ; Block 10825 @ 0x1c005cef7
    0x1C005CEF7 : xor al, al
    0x1C005CEF9 : jmp 0x1C005CF28
    
    ; Block 10826 @ 0x1c005cefb
    0x1C005CEFB : mov rcx, ds: [rcx + 0x50]
    0x1C005CEFF : call cs: [__imp_IoGetBaseFileSystemDeviceObject]
    0x1C005CF06 : nop ds: [rax + rax 0]
    0x1C005CF0B : mov rcx, ds: [rdi + 0x48]
    0x1C005CF0F : mov rbx, rax
    0x1C005CF12 : mov rcx, ds: [rcx + 0x50]
    0x1C005CF16 : call cs: [__imp_IoGetBaseFileSystemDeviceObject]
    0x1C005CF1D : nop ds: [rax + rax 0]
    0x1C005CF22 : cmp rbx, rax
    0x1C005CF25 : setz al
    
    ; Block 10827 @ 0x1c005cf28
    0x1C005CF28 : mov rbx, ss: [rsp + arg_0]
    0x1C005CF2D : add rsp, 0x20
    0x1C005CF31 : pop rdi
    0x1C005CF32 : retn
    """

    # User Inputs (Variables)
    t_driver = "srv2.sys"
    t_func = "Smb2QueryFileNormalizedName"

    # 4. Run Analysis
    result_json = semantic_alignment(vulnerable_snippet, patched_snippet, t_driver, t_func)
    
    # 5. Save Output
    output_filename = "binary_constraints_summary_32230.json"
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