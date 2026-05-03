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
    ; Block 9702 @ 0x1c005b348
    0x1C005B348 : mov ss: [rsp + arg_0], rbx
    0x1C005B34D : mov ss: [rsp + arg_8], rbp
    0x1C005B352 : mov ss: [rsp + arg_10], rsi
    0x1C005B357 : push rdi
    0x1C005B358 : sub rsp, 0x30
    0x1C005B35C : xor ebp, ebp
    0x1C005B35E : mov rbx, rdx
    0x1C005B361 : mov rdi, rcx
    0x1C005B364 : cmp bp, ds: [rcx + 0xFA]
    0x1C005B36B : jz 0x1C005B3AC
    
    ; Block 9703 @ 0x1c005b36d
    0x1C005B36D : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B374 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B37B : cmp rcx, rax
    0x1C005B37E : jz 0x1C005B3A2
    
    ; Block 9704 @ 0x1c005b380
    0x1C005B380 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B387 : jz 0x1C005B3A2
    
    ; Block 9705 @ 0x1c005b389
    0x1C005B389 : cmp ds: [rcx + 0x29], 1
    0x1C005B38D : jb 0x1C005B3A2
    
    ; Block 9706 @ 0x1c005b38f
    0x1C005B38F : mov rcx, ds: [rcx + 0x18]
    0x1C005B393 : lea edx, ss: [rbp + 0x3E]
    0x1C005B396 : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B39D : call WPP_SF_
    
    ; Block 9707 @ 0x1c005b3a2
    0x1C005B3A2 : mov edx, 0x10
    0x1C005B3A7 : jmp 0x1C005B582
    
    ; Block 9708 @ 0x1c005b3ac
    0x1C005B3AC : cmp r8w, 4
    0x1C005B3B1 : jnb 0x1C005B3F8
    
    ; Block 9709 @ 0x1c005b3b3
    0x1C005B3B3 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B3BA : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B3C1 : cmp rcx, rax
    0x1C005B3C4 : jz 0x1C005B3EE
    
    ; Block 9710 @ 0x1c005b3c6
    0x1C005B3C6 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B3CD : jz 0x1C005B3EE
    
    ; Block 9711 @ 0x1c005b3cf
    0x1C005B3CF : cmp ds: [rcx + 0x29], 1
    0x1C005B3D3 : jb 0x1C005B3EE
    
    ; Block 9712 @ 0x1c005b3d5
    0x1C005B3D5 : mov rcx, ds: [rcx + 0x18]
    0x1C005B3D9 : mov edx, 0x3F
    0x1C005B3DE : movzx r9d, r8w
    0x1C005B3E2 : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B3E9 : call WPP_SF_D
    
    ; Block 9713 @ 0x1c005b3ee
    0x1C005B3EE : mov edx, 0x11
    0x1C005B3F3 : jmp 0x1C005B582
    
    ; Block 9714 @ 0x1c005b3f8
    0x1C005B3F8 : movzx edx, ds: [rdx]
    0x1C005B3FB : mov esi, edx
    0x1C005B3FD : add rsi, rsi
    0x1C005B400 : cmp bp, dx
    0x1C005B403 : jnz 0x1C005B446
    
    ; Block 9715 @ 0x1c005b405
    0x1C005B405 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B40C : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B413 : cmp rcx, rax
    0x1C005B416 : jz 0x1C005B43C
    
    ; Block 9716 @ 0x1c005b418
    0x1C005B418 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B41F : jz 0x1C005B43C
    
    ; Block 9717 @ 0x1c005b421
    0x1C005B421 : cmp ds: [rcx + 0x29], 1
    0x1C005B425 : jb 0x1C005B43C
    
    ; Block 9718 @ 0x1c005b427
    0x1C005B427 : mov rcx, ds: [rcx + 0x18]
    0x1C005B42B : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B432 : mov edx, 0x41
    0x1C005B437 : call WPP_SF_
    
    ; Block 9719 @ 0x1c005b43c
    0x1C005B43C : mov edx, 0x13
    0x1C005B441 : jmp 0x1C005B582
    
    ; Block 9720 @ 0x1c005b446
    0x1C005B446 : lea rcx, ds: [rsi + 2]
    0x1C005B44A : cmp rcx, 2
    0x1C005B44E : jb 0x1C005B53B
    
    ; Block 9721 @ 0x1c005b454
    0x1C005B454 : mov eax, 0xFFFFFFFFFFFFFFFF
    0x1C005B459 : cmp rcx, rax
    0x1C005B45C : ja 0x1C005B53B
    
    ; Block 9722 @ 0x1c005b462
    0x1C005B462 : movzx eax, r8w
    0x1C005B466 : cmp rcx, rax
    0x1C005B469 : ja 0x1C005B53B
    
    ; Block 9723 @ 0x1c005b46f
    0x1C005B46F : test bl, 1
    0x1C005B472 : jnz 0x1C005B53B
    
    ; Block 9724 @ 0x1c005b478
    0x1C005B478 : mov r8d, 0x7732534C
    0x1C005B47E : mov rdx, rsi
    0x1C005B481 : mov ecx, 0x102
    0x1C005B486 : call cs: [__imp_ExAllocatePool2]
    0x1C005B48D : nop ds: [rax + rax 0]
    0x1C005B492 : mov ds: [rdi + 0xD8], rax
    0x1C005B499 : test rax, rax
    0x1C005B49C : jnz 0x1C005B4E3
    
    ; Block 9725 @ 0x1c005b49e
    0x1C005B49E : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B4A5 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B4AC : cmp rcx, rax
    0x1C005B4AF : jz 0x1C005B4D9
    
    ; Block 9726 @ 0x1c005b4b1
    0x1C005B4B1 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B4B8 : jz 0x1C005B4D9
    
    ; Block 9727 @ 0x1c005b4ba
    0x1C005B4BA : cmp ds: [rcx + 0x29], 1
    0x1C005B4BE : jb 0x1C005B4D9
    
    ; Block 9728 @ 0x1c005b4c0
    0x1C005B4C0 : movzx r9d, ds: [rbx]
    0x1C005B4C4 : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B4CB : mov rcx, ds: [rcx + 0x18]
    0x1C005B4CF : mov edx, 0x43
    0x1C005B4D4 : call WPP_SF_D
    
    ; Block 9729 @ 0x1c005b4d9
    0x1C005B4D9 : mov ebx, 0xFFFFFFFFC000009A
    0x1C005B4DE : jmp 0x1C005B58F
    
    ; Block 9730 @ 0x1c005b4e3
    0x1C005B4E3 : lea rdx, ds: [rbx + 2]
    0x1C005B4E7 : mov r8, rsi
    0x1C005B4EA : mov rcx, rax
    0x1C005B4ED : call memmove
    0x1C005B4F2 : movzx eax, ds: [rbx]
    0x1C005B4F5 : mov ds: [rdi + 0xFA], ax
    0x1C005B4FC : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B503 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B50A : cmp rcx, rax
    0x1C005B50D : jz 0x1C005B537
    
    ; Block 9731 @ 0x1c005b50f
    0x1C005B50F : test ds: [rcx + 0x2C], 0x8000
    0x1C005B516 : jz 0x1C005B537
    
    ; Block 9732 @ 0x1c005b518
    0x1C005B518 : cmp ds: [rcx + 0x29], 4
    0x1C005B51C : jb 0x1C005B537
    
    ; Block 9733 @ 0x1c005b51e
    0x1C005B51E : movzx r9d, ds: [rbx]
    0x1C005B522 : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B529 : mov rcx, ds: [rcx + 0x18]
    0x1C005B52D : mov edx, 0x44
    0x1C005B532 : call WPP_SF_D
    
    ; Block 9734 @ 0x1c005b537
    0x1C005B537 : mov ebx, ebp
    0x1C005B539 : jmp 0x1C005B5AB
    
    ; Block 9735 @ 0x1c005b53b
    0x1C005B53B : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B542 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B549 : cmp rcx, rax
    0x1C005B54C : jz 0x1C005B57D
    
    ; Block 9736 @ 0x1c005b54e
    0x1C005B54E : test ds: [rcx + 0x2C], 0x8000
    0x1C005B555 : jz 0x1C005B57D
    
    ; Block 9737 @ 0x1c005b557
    0x1C005B557 : cmp ds: [rcx + 0x29], 1
    0x1C005B55B : jb 0x1C005B57D
    
    ; Block 9738 @ 0x1c005b55d
    0x1C005B55D : mov rcx, ds: [rcx + 0x18]
    0x1C005B561 : mov r9d, edx
    0x1C005B564 : movzx eax, r8w
    0x1C005B568 : mov edx, 0x42
    0x1C005B56D : lea r8, cs: [WPP_0f167aa2677637c5c3b199739035b059_Traceguids]
    0x1C005B574 : mov ss: [rsp + var_18], eax
    0x1C005B578 : call WPP_SF_DD
    
    ; Block 9739 @ 0x1c005b57d
    0x1C005B57D : mov edx, 0x14
    
    ; Block 9740 @ 0x1c005b582
    0x1C005B582 : mov rcx, rdi
    0x1C005B585 : call Smb2LkmdTelCollectParsingFailureNegotiateHelper
    0x1C005B58A : mov ebx, 0xFFFFFFFFC000000D
    
    ; Block 9741 @ 0x1c005b58f
    0x1C005B58F : mov rcx, ds: [rdi + 0xD8]
    0x1C005B596 : xor edx, edx
    0x1C005B598 : call cs: [__imp_ExFreePoolWithTag]
    0x1C005B59F : nop ds: [rax + rax 0]
    0x1C005B5A4 : mov ds: [rdi + 0xD8], rbp
    
    ; Block 9742 @ 0x1c005b5ab
    0x1C005B5AB : mov rbp, ss: [rsp + arg_8]
    0x1C005B5B0 : mov eax, ebx
    0x1C005B5B2 : mov rbx, ss: [rsp + arg_0]
    0x1C005B5B7 : mov rsi, ss: [rsp + arg_10]
    0x1C005B5BC : add rsp, 0x30
    0x1C005B5C0 : pop rdi
    0x1C005B5C1 : retn
    """

    patched_snippet = """
    ; Block 9713 @ 0x1c005b358
    0x1C005B358 : mov ss: [rsp + arg_0], rbx
    0x1C005B35D : mov ss: [rsp + arg_8], rbp
    0x1C005B362 : mov ss: [rsp + arg_10], rsi
    0x1C005B367 : push rdi
    0x1C005B368 : sub rsp, 0x30
    0x1C005B36C : xor ebp, ebp
    0x1C005B36E : mov rbx, rdx
    0x1C005B371 : mov rdi, rcx
    0x1C005B374 : cmp bp, ds: [rcx + 0xFA]
    0x1C005B37B : jz 0x1C005B3BC
    
    ; Block 9714 @ 0x1c005b37d
    0x1C005B37D : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B384 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B38B : cmp rcx, rax
    0x1C005B38E : jz 0x1C005B3B2
    
    ; Block 9715 @ 0x1c005b390
    0x1C005B390 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B397 : jz 0x1C005B3B2
    
    ; Block 9716 @ 0x1c005b399
    0x1C005B399 : cmp ds: [rcx + 0x29], 1
    0x1C005B39D : jb 0x1C005B3B2
    
    ; Block 9717 @ 0x1c005b39f
    0x1C005B39F : mov rcx, ds: [rcx + 0x18]
    0x1C005B3A3 : lea edx, ss: [rbp + 0x3E]
    0x1C005B3A6 : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B3AD : call WPP_SF_
    
    ; Block 9718 @ 0x1c005b3b2
    0x1C005B3B2 : mov edx, 0x10
    0x1C005B3B7 : jmp 0x1C005B592
    
    ; Block 9719 @ 0x1c005b3bc
    0x1C005B3BC : cmp r8w, 4
    0x1C005B3C1 : jnb 0x1C005B408
    
    ; Block 9720 @ 0x1c005b3c3
    0x1C005B3C3 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B3CA : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B3D1 : cmp rcx, rax
    0x1C005B3D4 : jz 0x1C005B3FE
    
    ; Block 9721 @ 0x1c005b3d6
    0x1C005B3D6 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B3DD : jz 0x1C005B3FE
    
    ; Block 9722 @ 0x1c005b3df
    0x1C005B3DF : cmp ds: [rcx + 0x29], 1
    0x1C005B3E3 : jb 0x1C005B3FE
    
    ; Block 9723 @ 0x1c005b3e5
    0x1C005B3E5 : mov rcx, ds: [rcx + 0x18]
    0x1C005B3E9 : mov edx, 0x3F
    0x1C005B3EE : movzx r9d, r8w
    0x1C005B3F2 : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B3F9 : call WPP_SF_D
    
    ; Block 9724 @ 0x1c005b3fe
    0x1C005B3FE : mov edx, 0x11
    0x1C005B403 : jmp 0x1C005B592
    
    ; Block 9725 @ 0x1c005b408
    0x1C005B408 : movzx edx, ds: [rdx]
    0x1C005B40B : mov esi, edx
    0x1C005B40D : add rsi, rsi
    0x1C005B410 : cmp bp, dx
    0x1C005B413 : jnz 0x1C005B456
    
    ; Block 9726 @ 0x1c005b415
    0x1C005B415 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B41C : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B423 : cmp rcx, rax
    0x1C005B426 : jz 0x1C005B44C
    
    ; Block 9727 @ 0x1c005b428
    0x1C005B428 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B42F : jz 0x1C005B44C
    
    ; Block 9728 @ 0x1c005b431
    0x1C005B431 : cmp ds: [rcx + 0x29], 1
    0x1C005B435 : jb 0x1C005B44C
    
    ; Block 9729 @ 0x1c005b437
    0x1C005B437 : mov rcx, ds: [rcx + 0x18]
    0x1C005B43B : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B442 : mov edx, 0x41
    0x1C005B447 : call WPP_SF_
    
    ; Block 9730 @ 0x1c005b44c
    0x1C005B44C : mov edx, 0x13
    0x1C005B451 : jmp 0x1C005B592
    
    ; Block 9731 @ 0x1c005b456
    0x1C005B456 : lea rcx, ds: [rsi + 2]
    0x1C005B45A : cmp rcx, 2
    0x1C005B45E : jb 0x1C005B54B
    
    ; Block 9732 @ 0x1c005b464
    0x1C005B464 : mov eax, 0xFFFFFFFFFFFFFFFF
    0x1C005B469 : cmp rcx, rax
    0x1C005B46C : ja 0x1C005B54B
    
    ; Block 9733 @ 0x1c005b472
    0x1C005B472 : movzx eax, r8w
    0x1C005B476 : cmp rcx, rax
    0x1C005B479 : ja 0x1C005B54B
    
    ; Block 9734 @ 0x1c005b47f
    0x1C005B47F : test bl, 1
    0x1C005B482 : jnz 0x1C005B54B
    
    ; Block 9735 @ 0x1c005b488
    0x1C005B488 : mov r8d, 0x7732534C
    0x1C005B48E : mov rdx, rsi
    0x1C005B491 : mov ecx, 0x102
    0x1C005B496 : call cs: [__imp_ExAllocatePool2]
    0x1C005B49D : nop ds: [rax + rax 0]
    0x1C005B4A2 : mov ds: [rdi + 0xD8], rax
    0x1C005B4A9 : test rax, rax
    0x1C005B4AC : jnz 0x1C005B4F3
    
    ; Block 9736 @ 0x1c005b4ae
    0x1C005B4AE : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B4B5 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B4BC : cmp rcx, rax
    0x1C005B4BF : jz 0x1C005B4E9
    
    ; Block 9737 @ 0x1c005b4c1
    0x1C005B4C1 : test ds: [rcx + 0x2C], 0x8000
    0x1C005B4C8 : jz 0x1C005B4E9
    
    ; Block 9738 @ 0x1c005b4ca
    0x1C005B4CA : cmp ds: [rcx + 0x29], 1
    0x1C005B4CE : jb 0x1C005B4E9
    
    ; Block 9739 @ 0x1c005b4d0
    0x1C005B4D0 : movzx r9d, ds: [rbx]
    0x1C005B4D4 : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B4DB : mov rcx, ds: [rcx + 0x18]
    0x1C005B4DF : mov edx, 0x43
    0x1C005B4E4 : call WPP_SF_D
    
    ; Block 9740 @ 0x1c005b4e9
    0x1C005B4E9 : mov ebx, 0xFFFFFFFFC000009A
    0x1C005B4EE : jmp 0x1C005B59F
    
    ; Block 9741 @ 0x1c005b4f3
    0x1C005B4F3 : lea rdx, ds: [rbx + 2]
    0x1C005B4F7 : mov r8, rsi
    0x1C005B4FA : mov rcx, rax
    0x1C005B4FD : call memmove
    0x1C005B502 : movzx eax, ds: [rbx]
    0x1C005B505 : mov ds: [rdi + 0xFA], ax
    0x1C005B50C : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B513 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B51A : cmp rcx, rax
    0x1C005B51D : jz 0x1C005B547
    
    ; Block 9742 @ 0x1c005b51f
    0x1C005B51F : test ds: [rcx + 0x2C], 0x8000
    0x1C005B526 : jz 0x1C005B547
    
    ; Block 9743 @ 0x1c005b528
    0x1C005B528 : cmp ds: [rcx + 0x29], 4
    0x1C005B52C : jb 0x1C005B547
    
    ; Block 9744 @ 0x1c005b52e
    0x1C005B52E : movzx r9d, ds: [rbx]
    0x1C005B532 : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B539 : mov rcx, ds: [rcx + 0x18]
    0x1C005B53D : mov edx, 0x44
    0x1C005B542 : call WPP_SF_D
    
    ; Block 9745 @ 0x1c005b547
    0x1C005B547 : mov ebx, ebp
    0x1C005B549 : jmp 0x1C005B59F
    
    ; Block 9746 @ 0x1c005b54b
    0x1C005B54B : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C005B552 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C005B559 : cmp rcx, rax
    0x1C005B55C : jz 0x1C005B58D
    
    ; Block 9747 @ 0x1c005b55e
    0x1C005B55E : test ds: [rcx + 0x2C], 0x8000
    0x1C005B565 : jz 0x1C005B58D
    
    ; Block 9748 @ 0x1c005b567
    0x1C005B567 : cmp ds: [rcx + 0x29], 1
    0x1C005B56B : jb 0x1C005B58D
    
    ; Block 9749 @ 0x1c005b56d
    0x1C005B56D : mov rcx, ds: [rcx + 0x18]
    0x1C005B571 : mov r9d, edx
    0x1C005B574 : movzx eax, r8w
    0x1C005B578 : mov edx, 0x42
    0x1C005B57D : lea r8, cs: [WPP_7ac0e2d6ae433461e181434be4abfc45_Traceguids]
    0x1C005B584 : mov ss: [rsp + var_18], eax
    0x1C005B588 : call WPP_SF_DD
    
    ; Block 9750 @ 0x1c005b58d
    0x1C005B58D : mov edx, 0x14
    
    ; Block 9751 @ 0x1c005b592
    0x1C005B592 : mov rcx, rdi
    0x1C005B595 : call Smb2LkmdTelCollectParsingFailureNegotiateHelper
    0x1C005B59A : mov ebx, 0xFFFFFFFFC000000D
    
    ; Block 9752 @ 0x1c005b59f
    0x1C005B59F : call Feature_1607844152__private_IsEnabledDeviceUsageNoInline
    0x1C005B5A4 : test eax, eax
    0x1C005B5A6 : jnz 0x1C005B5C8
    
    ; Block 9753 @ 0x1c005b5a8
    0x1C005B5A8 : test ebx, ebx
    0x1C005B5AA : jns 0x1C005B5C8
    
    ; Block 9754 @ 0x1c005b5ac
    0x1C005B5AC : mov rcx, ds: [rdi + 0xD8]
    0x1C005B5B3 : xor edx, edx
    0x1C005B5B5 : call cs: [__imp_ExFreePoolWithTag]
    0x1C005B5BC : nop ds: [rax + rax 0]
    0x1C005B5C1 : mov ds: [rdi + 0xD8], rbp
    
    ; Block 9755 @ 0x1c005b5c8
    0x1C005B5C8 : mov rbp, ss: [rsp + arg_8]
    0x1C005B5CD : mov eax, ebx
    0x1C005B5CF : mov rbx, ss: [rsp + arg_0]
    0x1C005B5D4 : mov rsi, ss: [rsp + arg_10]
    0x1C005B5D9 : add rsp, 0x30
    0x1C005B5DD : pop rdi
    0x1C005B5DE : retn
    """

    # User Inputs (Variables)
    t_driver = "srv2.sys"
    t_func = "Smb2ValidateSigningCapabilities"

    # 4. Run Analysis
    result_json = semantic_alignment(vulnerable_snippet, patched_snippet, t_driver, t_func)
    
    # 5. Save Output
    output_filename = "binary_constraints_summary_43642.json"
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