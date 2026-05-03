import json
import re
import os
from openai import OpenAI

client = OpenAI()

AUDITOR_PROMPT = """
Role: Senior Protocol Implementation Auditor.
Task: rigorous_code_review

**[Objective]**
Compare the "Blueprint JSON" (The Specification) against the "Generated Python Code" (The Implementation).
Identify logic gaps, missing layers, or static value errors.
**DO NOT focus on syntax errors.** Focus on **Protocol Logic & Data Structure**.

**[Inputs]**
1. Blueprint JSON:
{blueprint_json}

2. Generated Code:
{generated_code}

**[Audit Checklist - Chain of Thought]**
1. **Encapsulation Check (CRITICAL)**:
   - Does the JSON define a hierarchy (e.g., Header -> Body)?
   - Does the Python code implement this nesting?
   - *Failure Pattern:* The code sends the Body directly without the Header wrapper defined in the JSON.

2. **Transport Framing Check**:
   - If the protocol runs on TCP/Stream, does the code handle message boundaries (e.g., Length Prefixes)?
   - *Failure Pattern:* Sending raw bytes without the required 4-byte length header (if implied by the protocol family).

3. **Data Flow & Dependencies**:
   - Does the code dynamically extract values from responses?
   - Or does it use hardcoded/null values where dynamic values are required?

4. **Field Completeness**:
   - Are all fields listed in the JSON present in the code construction?
   - Are critical "Context" or "Capability" fields (defined in JSON) actually added to the packet?

**[Output Format]**
Return a JSON object only.
{{
    "status": "PASS" or "FAIL",
    "critical_errors": [
        "Description of error 1...",
        "Description of error 2..."
    ],
    "correction_guidance": "Specific instructions on how to fix the code..."
}}
"""

PATCHER_PROMPT = """
Role: Lead Python Developer (Network Security).
Task: Code Remediation based on Audit Report.

**[Input Context]**
1. Original Code:
{original_code}

2. Audit Report (Errors found):
{audit_report}

**[Instructions]**
- Rewrite the Python code to resolve ALL critical errors listed in the Audit Report.
- **Encapsulation**: Ensure inner structures are properly wrapped in outer headers as per the report.
- **Framing**: Add transport layer length headers (e.g., struct.pack('>I', len(data))) if reported missing.
- **Dependencies**: Implement response parsing to update session variables dynamically.
- Do NOT remove necessary imports. Keep the code runnable.

**[Output]**
Return ONLY the full, corrected Python script.
"""

def extract_content(text, type="json"):
    """LLM 응답에서 JSON 또는 Code 블록 추출"""
    pattern = r"```(?:json|python)?\s*(.*?)\s*```"
    match = re.search(pattern, text, re.DOTALL)
    content = match.group(1) if match else text.strip()
    
    if type == "json":
        try:
            return json.loads(content)
        except:
            return None
    return content

def run_self_correction_loop(blueprint_path, script_path, max_retries=3):
    # 1. Load Initial Files
    with open(blueprint_path, 'r', encoding='utf-8') as f:
        blueprint_data = json.dumps(json.load(f), indent=2)
    
    with open(script_path, 'r', encoding='utf-8') as f:
        current_code = f.read()

    print(f"[+] Starting Self-Correction Loop for {script_path}")
    
    for i in range(1, max_retries + 1):
        print(f"\n[Iteration {i}/{max_retries}] Running Auditor...")

        # --- Step 1: Audit ---
        audit_prompt = AUDITOR_PROMPT.format(
            blueprint_json=blueprint_data,
            generated_code=current_code
        )
        
        audit_resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": audit_prompt}],
            temperature=0.0
        )
        
        audit_result = extract_content(audit_resp.choices[0].message.content, type="json")
        
        if not audit_result:
            print("[-] Auditor failed to produce valid JSON. Skipping.")
            continue

        if audit_result["status"] == "PASS":
            print(f"[+] Code passed audit on iteration {i}. Optimization Complete!")
            break
        
        print(f"[-] Issues Found: {len(audit_result['critical_errors'])}")
        for err in audit_result['critical_errors']:
            print(f"    ! {err}")

        # --- Step 2: Patch ---
        print(f"[Iteration {i}/{max_retries}] Running Patcher...")
        
        patch_prompt = PATCHER_PROMPT.format(
            original_code=current_code,
            audit_report=json.dumps(audit_result, indent=2)
        )
        
        patch_resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": patch_prompt}],
            temperature=0.0
        )
        
        patched_code = extract_content(patch_resp.choices[0].message.content, type="code")
        
        # Save validated code
        current_code = patched_code
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(current_code)
            
        print(f"[+] Code patched and saved.")

    print("\n[=] Final Code Generation Complete.")

# ==============================================================================
# AUDITOR_PROMPT & PATCHER_PROMPT 변수는 위에 정의된 문자열을 사용합니다.
# ==============================================================================

if __name__ == "__main__":
    number = "0796"
    blueprint_file = f"fuzz_seed_blueprint_{number}.json"
    target_script = f"fuzzer_{number}_impacket.py"
    
    run_self_correction_loop(blueprint_file, target_script)