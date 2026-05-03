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
    vanilla_prompt = f"""
    [Role]
    You are an expert Vulnerability Researcher and Exploit Developer.

    [Objective]
    Your goal is to generate a Python reproduction script (PoC) for a specific 1-day vulnerability in the Windows Kernel Driver (srv2.sys).
    You are provided with the target function's assembly code derived from a binary diff.

    [Input Data]
    - Target Driver: {target_driver} (srv2.sys)
    - Target Function: {target_function}
    - Vulnerable Assembly Code:
    {vuln_diff_info}

    [Instruction]
    Analyze the provided assembly code to understand the vulnerability logic.
    Based on your analysis, write a standalone Python script using the 'scapy' library to trigger this vulnerability.
    
    Requirements:
    1. Analyze the assembly instructions (cmp, test, jnz, etc.) to calculate the required packet structure and values.
    2. Construct a valid SMBv2/v3 packet sequence that satisfies these path constraints.
    3. The script must send the crafted packet to the target IP.

    [Output Format]
    Return ONLY the executable Python code block. Do not include explanations.
    """

    print(f"[+] Phase 1: Analyzing {target_driver}::{target_function}...")
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are a binary analysis expert. Output valid JSON only."},
                {"role": "user", "content": vanilla_prompt}
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
    ; Block 4272 @ 0x1c0017e60
    0x1C0017E60 : mov rax, rsp
    0x1C0017E63 : mov ds: [rax + 0x10], rbx
    0x1C0017E67 : mov ds: [rax + 0x18], rbp
    0x1C0017E6B : mov ds: [rax + 0x20], rsi
    0x1C0017E6F : push rdi
    0x1C0017E70 : push r14
    0x1C0017E72 : push r15
    0x1C0017E74 : sub rsp, 0x40
    0x1C0017E78 : and ds: [rax + 8], 0
    0x1C0017E7C : mov rdi, rcx
    0x1C0017E7F : mov rax, ds: [rcx + 0xF0]
    0x1C0017E86 : cmp ds: [rax + 0x24], 0x10
    0x1C0017E8A : jb 0x1C0017F94
    
    ; Block 4273 @ 0x1c0017e90
    0x1C0017E90 : mov rax, ds: [rax + 0x18]
    0x1C0017E94 : movups xmm0, ds: [rax]
    0x1C0017E97 : mov rax, ds: [rcx + 0x50]
    0x1C0017E9B : movups ss: [rsp + Size], xmm0
    0x1C0017EA0 : mov rcx, ds: [rax + 0x1F0]
    0x1C0017EA7 : psrldq xmm0, 8
    0x1C0017EAC : mov ebp, ds: [rcx + 0x8C]
    0x1C0017EB2 : movq rcx, xmm0
    0x1C0017EB7 : movzx eax, cx
    0x1C0017EBA : cmp ebp, eax
    0x1C0017EBC : jz 0x1C0017EC8
    
    ; Block 4274 @ 0x1c0017ebe
    0x1C0017EBE : mov eax, 0xFFFFFFFFC00000BB
    0x1C0017EC3 : jmp 0x1C0017F99
    
    ; Block 4275 @ 0x1c0017ec8
    0x1C0017EC8 : mov rax, ss: [rsp + Size]
    0x1C0017ECD : xor edx, edx
    0x1C0017ECF : shr rax, 0x20
    0x1C0017ED3 : shr rcx, 0x20
    0x1C0017ED7 : add ecx, eax
    0x1C0017ED9 : call cs: [__imp_SrvNetAllocateBuffer]
    0x1C0017EE0 : nop ds: [rax + rax 0]
    0x1C0017EE5 : mov rbx, rax
    0x1C0017EE8 : test rax, rax
    0x1C0017EEB : jnz 0x1C0017EF7
    
    ; Block 4276 @ 0x1c0017eed
    0x1C0017EED : mov eax, 0xFFFFFFFFC000009A
    0x1C0017EF2 : jmp 0x1C0017F99
    
    ; Block 4277 @ 0x1c0017ef7
    0x1C0017EF7 : mov rdx, ds: [rdi + 0xF0]
    0x1C0017EFE : mov ecx, ebp
    0x1C0017F00 : mov r9, ds: [rax + 0x18]
    0x1C0017F04 : mov esi, ss: [rsp + Size]
    0x1C0017F08 : mov r14d, ss: [rsp + Size]
    0x1C0017F0D : add r9, rsi
    0x1C0017F10 : mov r8d, ds: [rdx + 0x24]
    0x1C0017F14 : mov rax, ds: [rdx + 0x18]
    0x1C0017F18 : sub r8d, esi
    0x1C0017F1B : lea rdx, ds: [rsi + 0x10]
    0x1C0017F1F : sub r8d, 0x10
    0x1C0017F23 : add rdx, rax
    0x1C0017F26 : lea rax, ss: [rsp + arg_0]
    0x1C0017F2B : mov ss: [rsp + var_30], rax
    0x1C0017F30 : mov ss: [rsp + var_38], r14d
    0x1C0017F35 : call cs: [__imp_SmbCompressionDecompress]
    0x1C0017F3C : nop ds: [rax + rax 0]
    0x1C0017F41 : test eax, eax
    0x1C0017F43 : js 0x1C0017F85
    
    ; Block 4278 @ 0x1c0017f45
    0x1C0017F45 : mov eax, ss: [rsp + arg_0]
    0x1C0017F49 : cmp eax, r14d
    0x1C0017F4C : jnz 0x1C0017F85
    
    ; Block 4279 @ 0x1c0017f4e
    0x1C0017F4E : test esi, esi
    0x1C0017F50 : jz 0x1C0017F71
    
    ; Block 4280 @ 0x1c0017f52
    0x1C0017F52 : mov rax, ds: [rdi + 0xF0]
    0x1C0017F59 : mov r8d, esi
    0x1C0017F5C : mov rcx, ds: [rbx + 0x18]
    0x1C0017F60 : mov rdx, ds: [rax + 0x18]
    0x1C0017F64 : add rdx, 0x10
    0x1C0017F68 : call memmove
    0x1C0017F6D : mov eax, ss: [rsp + arg_0]
    
    ; Block 4281 @ 0x1c0017f71
    0x1C0017F71 : add eax, esi
    0x1C0017F73 : mov rdx, rbx
    0x1C0017F76 : mov rcx, rdi
    0x1C0017F79 : mov ds: [rbx + 0x24], eax
    0x1C0017F7C : call Srv2ReplaceReceiveBuffer
    0x1C0017F81 : xor eax, eax
    0x1C0017F83 : jmp 0x1C0017F99
    
    ; Block 4282 @ 0x1c0017f85
    0x1C0017F85 : mov rcx, rbx
    0x1C0017F88 : call cs: [__imp_SrvNetFreeBuffer]
    0x1C0017F8F : nop ds: [rax + rax 0]
    
    ; Block 4283 @ 0x1c0017f94
    0x1C0017F94 : mov eax, 0xFFFFFFFFC000090B
    
    ; Block 4284 @ 0x1c0017f99
    0x1C0017F99 : mov rbx, ss: [rsp + arg_8]
    0x1C0017F9E : mov rbp, ss: [rsp + arg_10]
    0x1C0017FA3 : mov rsi, ss: [rsp + arg_18]
    0x1C0017FA8 : add rsp, 0x40
    0x1C0017FAC : pop r15
    0x1C0017FAE : pop r14
    0x1C0017FB0 : pop rdi
    0x1C0017FB1 : retn
    """

    patched_snippet = """
    ; Block 4277 @ 0x1c0017f14
    0x1C0017F14 : mov ss: [rsp + arg_10], rbx
    0x1C0017F19 : mov ss: [rsp + arg_18], rsi
    0x1C0017F1E : push rbp
    0x1C0017F1F : push rdi
    0x1C0017F20 : push r12
    0x1C0017F22 : push r14
    0x1C0017F24 : push r15
    0x1C0017F26 : mov rbp, rsp
    0x1C0017F29 : sub rsp, 0x40
    0x1C0017F2D : mov rax, ds: [rcx + 0x50]
    0x1C0017F31 : mov rdi, rcx
    0x1C0017F34 : and ss: [rbp + arg_0], 0
    0x1C0017F38 : and ss: [rbp + pulResult], 0
    0x1C0017F3C : mov r10, ds: [rax + 0x1F0]
    0x1C0017F43 : mov rax, ds: [rcx + 0xF0]
    0x1C0017F4A : cmp ds: [rax + 0x24], 0x10
    0x1C0017F4E : jb 0x1C00180DA
    
    ; Block 4278 @ 0x1c0017f54
    0x1C0017F54 : mov rax, ds: [rax + 0x18]
    0x1C0017F58 : mov r12d, ds: [r10 + 0x8C]
    0x1C0017F5F : movups xmm0, ds: [rax]
    0x1C0017F62 : movups ss: [rbp + ulSubtrahend], xmm0
    0x1C0017F66 : psrldq xmm0, 8
    0x1C0017F6B : movq rcx, xmm0
    0x1C0017F70 : movzx eax, cx
    0x1C0017F73 : cmp r12d, eax
    0x1C0017F76 : jz 0x1C0017F82
    
    ; Block 4279 @ 0x1c0017f78
    0x1C0017F78 : mov ebx, 0xFFFFFFFFC00000BB
    0x1C0017F7D : jmp 0x1C00180DF
    
    ; Block 4280 @ 0x1c0017f82
    0x1C0017F82 : mov rax, ss: [rbp + ulSubtrahend]
    0x1C0017F86 : lea r8, ss: [rbp + pulResult]
    0x1C0017F8A : shr rcx, 0x20
    0x1C0017F8E : shr rax, 0x20
    0x1C0017F92 : mov edx, ecx
    0x1C0017F94 : mov ecx, eax
    0x1C0017F96 : call RtlULongAdd
    0x1C0017F9B : test eax, eax
    0x1C0017F9D : jns 0x1C0017FF5
    
    ; Block 4281 @ 0x1c0017f9f
    0x1C0017F9F : mov ebx, 0xFFFFFFFFC000090B
    0x1C0017FA4 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C0017FAB : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C0017FB2 : cmp rcx, rax
    0x1C0017FB5 : jz 0x1C00180DF
    
    ; Block 4282 @ 0x1c0017fbb
    0x1C0017FBB : mov eax, ds: [rcx + 0x2C]
    0x1C0017FBE : test al, 1
    0x1C0017FC0 : jz 0x1C00180DF
    
    ; Block 4283 @ 0x1c0017fc6
    0x1C0017FC6 : cmp ds: [rcx + 0x29], 1
    0x1C0017FCA : jb 0x1C00180DF
    
    ; Block 4284 @ 0x1c0017fd0
    0x1C0017FD0 : mov eax, ss: [rbp + ulSubtrahend]
    0x1C0017FD3 : lea r8, cs: [WPP_d48b5adabecd352fe4827eb6fcbd2951_Traceguids]
    0x1C0017FDA : mov r9d, ss: [rbp + ulSubtrahend]
    0x1C0017FDE : mov edx, 0xA
    0x1C0017FE3 : mov rcx, ds: [rcx + 0x18]
    0x1C0017FE7 : mov ss: [rsp + var_20], eax
    0x1C0017FEB : call WPP_SF_DD
    0x1C0017FF0 : jmp 0x1C00180DF
    
    ; Block 4285 @ 0x1c0017ff5
    0x1C0017FF5 : mov ecx, ds: [r10 + 0x24]
    0x1C0017FF9 : mov r9d, ss: [rbp + pulResult]
    0x1C0017FFD : add ecx, 0x100
    0x1C0018003 : add rcx, 0x34
    0x1C0018007 : cmp r9, rcx
    0x1C001800A : jbe 0x1C0018057
    
    ; Block 4286 @ 0x1c001800c
    0x1C001800C : mov ebx, 0xFFFFFFFFC000090B
    0x1C0018011 : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C0018018 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C001801F : cmp rcx, rax
    0x1C0018022 : jz 0x1C00180DF
    
    ; Block 4287 @ 0x1c0018028
    0x1C0018028 : mov eax, ds: [rcx + 0x2C]
    0x1C001802B : test al, 1
    0x1C001802D : jz 0x1C00180DF
    
    ; Block 4288 @ 0x1c0018033
    0x1C0018033 : cmp ds: [rcx + 0x29], 1
    0x1C0018037 : jb 0x1C00180DF
    
    ; Block 4289 @ 0x1c001803d
    0x1C001803D : mov rcx, ds: [rcx + 0x18]
    0x1C0018041 : lea r8, cs: [WPP_d48b5adabecd352fe4827eb6fcbd2951_Traceguids]
    0x1C0018048 : mov edx, 0xB
    0x1C001804D : call WPP_SF_d
    0x1C0018052 : jmp 0x1C00180DF
    
    ; Block 4290 @ 0x1c0018057
    0x1C0018057 : xor edx, edx
    0x1C0018059 : mov rcx, r9
    0x1C001805C : call cs: [__imp_SrvNetAllocateBuffer]
    0x1C0018063 : nop ds: [rax + rax 0]
    0x1C0018068 : mov rbx, rax
    0x1C001806B : test rax, rax
    0x1C001806E : jnz 0x1C0018077
    
    ; Block 4291 @ 0x1c0018070
    0x1C0018070 : mov ebx, 0xFFFFFFFFC000009A
    0x1C0018075 : jmp 0x1C00180DF
    
    ; Block 4292 @ 0x1c0018077
    0x1C0018077 : mov r11, ds: [rdi + 0xF0]
    0x1C001807E : lea r8, ss: [rbp + pulResult]
    0x1C0018082 : mov esi, ss: [rbp + ulSubtrahend]
    0x1C0018085 : mov edx, esi
    0x1C0018087 : mov r10d, ds: [r11 + 0x24]
    0x1C001808B : lea ecx, ds: [r10 + 0xFFFFFFFFFFFFFFF0]
    0x1C001808F : mov ss: [rbp + pulResult], ecx
    0x1C0018092 : call RtlULongSub
    0x1C0018097 : test eax, eax
    0x1C0018099 : jns 0x1C00180FA
    
    ; Block 4293 @ 0x1c001809b
    0x1C001809B : mov rcx, cs: [WPP_GLOBAL_Control]
    0x1C00180A2 : lea rax, cs: [WPP_GLOBAL_Control]
    0x1C00180A9 : cmp rcx, rax
    0x1C00180AC : jz 0x1C00180CB
    
    ; Block 4294 @ 0x1c00180ae
    0x1C00180AE : mov eax, ds: [rcx + 0x2C]
    0x1C00180B1 : test al, 1
    0x1C00180B3 : jz 0x1C00180CB
    
    ; Block 4295 @ 0x1c00180b5
    0x1C00180B5 : cmp ds: [rcx + 0x29], 1
    0x1C00180B9 : jb 0x1C00180CB
    
    ; Block 4296 @ 0x1c00180bb
    0x1C00180BB : mov rcx, ds: [rcx + 0x18]
    0x1C00180BF : mov r9d, r10d
    0x1C00180C2 : mov ss: [rsp + var_18], esi
    0x1C00180C6 : call WPP_SF_LLL
    
    ; Block 4297 @ 0x1c00180cb
    0x1C00180CB : mov rcx, rbx
    0x1C00180CE : call cs: [__imp_SrvNetFreeBuffer]
    0x1C00180D5 : nop ds: [rax + rax 0]
    
    ; Block 4298 @ 0x1c00180da
    0x1C00180DA : mov ebx, 0xFFFFFFFFC000090B
    
    ; Block 4299 @ 0x1c00180df
    0x1C00180DF : mov eax, ebx
    
    ; Block 4300 @ 0x1c00180e1
    0x1C00180E1 : lea r11, ss: [rsp + var_s0]
    0x1C00180E6 : mov rbx, ds: [r11 + 0x40]
    0x1C00180EA : mov rsi, ds: [r11 + 0x48]
    0x1C00180EE : mov rsp, r11
    0x1C00180F1 : pop r15
    0x1C00180F3 : pop r14
    0x1C00180F5 : pop r12
    0x1C00180F7 : pop rdi
    0x1C00180F8 : pop rbp
    0x1C00180F9 : retn
    
    ; Block 4301 @ 0x1c00180fa
    0x1C00180FA : mov r9, ds: [rbx + 0x18]
    0x1C00180FE : lea rax, ss: [rbp + arg_0]
    0x1C0018102 : mov r14d, ss: [rbp + ulSubtrahend]
    0x1C0018106 : lea rdx, ds: [rsi + 0x10]
    0x1C001810A : add rdx, ds: [r11 + 0x18]
    0x1C001810E : add r9, rsi
    0x1C0018111 : mov r8d, ss: [rbp + pulResult]
    0x1C0018115 : mov ecx, r12d
    0x1C0018118 : mov ss: [rsp + var_18], rax
    0x1C001811D : mov ss: [rsp + var_20], r14d
    0x1C0018122 : call cs: [__imp_SmbCompressionDecompress]
    0x1C0018129 : nop ds: [rax + rax 0]
    0x1C001812E : test eax, eax
    0x1C0018130 : js 0x1C00180CB
    
    ; Block 4302 @ 0x1c0018132
    0x1C0018132 : mov eax, ss: [rbp + arg_0]
    0x1C0018135 : cmp eax, r14d
    0x1C0018138 : jnz 0x1C00180CB
    
    ; Block 4303 @ 0x1c001813a
    0x1C001813A : test esi, esi
    0x1C001813C : jz 0x1C001815C
    
    ; Block 4304 @ 0x1c001813e
    0x1C001813E : mov rax, ds: [rdi + 0xF0]
    0x1C0018145 : mov r8, rsi
    0x1C0018148 : mov rcx, ds: [rbx + 0x18]
    0x1C001814C : mov rdx, ds: [rax + 0x18]
    0x1C0018150 : add rdx, 0x10
    0x1C0018154 : call memmove
    0x1C0018159 : mov eax, ss: [rbp + arg_0]
    
    ; Block 4305 @ 0x1c001815c
    0x1C001815C : add eax, esi
    0x1C001815E : mov rdx, rbx
    0x1C0018161 : mov rcx, rdi
    0x1C0018164 : mov ds: [rbx + 0x24], eax
    0x1C0018167 : call Srv2ReplaceReceiveBuffer
    0x1C001816C : xor eax, eax
    0x1C001816E : jmp 0x1C00180E1
    """

    # User Inputs (Variables)
    t_driver = "srv2.sys"
    t_func = "Srv2DecompressData"

    # 4. Run Analysis
    result_json = semantic_alignment(vulnerable_snippet, patched_snippet, t_driver, t_func)
    
    # 5. Save Output
    output_filename = f"binary_constraints_summary_0796_v3_vanilla_{MODEL}.json"
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