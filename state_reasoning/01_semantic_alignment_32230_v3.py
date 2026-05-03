import os
import json
from openai import OpenAI

MODEL = "gpt-5.2"  # gpt-4o  gpt-5.2-codex

client = OpenAI()

def semantic_alignment(vuln_diff_info, patch_diff_info, target_driver, target_function):
    """
    Phase 2: Semantic Alignment & Constraint Extraction
    Goal: Analyze Gatekeepers and Vulnerability Logic with specific driver context.
    """
    
    # Protocol-Agnostic Prompt with Context Injection
    prompt = f"""
    [Role]
    Elite Windows Kernel Vulnerability Researcher & Protocol Standard Analyst.
    
    [Objective]
    Your goal is to function as a 'Semantic Anchoring Module'. You must bridge the semantic gap between low-level assembly/diffs and high-level protocol specifications. 
    You are provided with a target driver, a vulnerable function, and the diff information (vulnerable code vs. patch).
    
    [Input Data]
    - Target Driver: {target_driver}
    - Target Function: {target_function}
    - Vulnerable Code Context (Assembly/Source): 
    {vuln_diff_info}
    - Patch/Diff Context: 
    {patch_diff_info}

    [Reasoning Guidelines - The 'Macro-Logic' Approach]
    1. AVOID Micro-Grounding: Do not attempt to simulate exact assembly execution (e.g., "rax becomes 0"). LLMs fail at bit-exact state tracking.
    2. PERFORM Macro-Abstraction: Instead of interpreting `cmp [rax+0x10], 0x30` literally, map it to the Protocol Schema. Ask: "What protocol field corresponds to offset 0x10? Does 0x30 represent a Header Size or a Flag?"
    3. INTERNALIZED KNOWLEDGE: Use your internal knowledge of Windows Protocols to infer the context.
    4. IDENTIFY ANCHORS: Determine the 'Semantic Anchor'—the high-level protocol state or capability required to even reach this function.

    [Chain-of-Thought Steps]
    Step 1: Context Identification
    - Analyze function names and keywords in the diff. What specific protocol feature is this?.
    
    Step 2: Syntactic-to-Semantic Lifting
    - Map the constraints found in the code to Protocol Specification definitions. 
    
    Step 3: Pre-condition Definition
    - What global state or capability must be active for this code to be reachable?.

    [Output Format]
    Return ONLY a valid JSON object. No markdown formatting, no conversational text.
    
    {{
      "step": "Semantic_Anchoring",
      "reasoning": {{
        "context_identification": "Brief analysis of the function's role.",
        "abstraction_logic": "Explanation of how code constants map to spec."
      }},
      "semantic_anchor": {{
        "target_function": "{target_function}",
        "protocol_feature": "Name of the feature",
        "required_capability": "The abstract capability required.",
        "semantic_constraint": "The abstract constraint on the payload."
      }}
    }}
    """

    print(f"[+] Phase 1: Analyzing {target_driver}::{target_function}...")
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are a binary analysis expert. Output valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0,
            response_format={"type": "json_object"}
        )
        content = response.choices[0].message.content

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
    output_filename = f"binary_constraints_summary_32230_v3_{MODEL}.json"
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