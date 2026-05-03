# 이전 정보들로부터 Fuzzing Seed Blueprint JSON 생성
import os
import json
import re
from openai import OpenAI

client = OpenAI()

def extract_json_from_response(text):
    """LLM 응답에서 JSON 블록만 추출하고 파싱"""
    cleaned = text.strip()
    match = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
    json_str = match.group(1) if match else cleaned
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"[-] JSON Parsing Failed: {e}\n[-] Raw content: {cleaned[:100]}...")
        return None

def phase_3_seed_gen(sequence_file, constraints_file, output_json_name):
    # 1. Input Validation
    if not os.path.exists(sequence_file) or not os.path.exists(constraints_file):
        print(f"[-] Error: Input files missing.\n    {sequence_file}\n    {constraints_file}")
        return

    # 2. Load Context (구조에 맞게 데이터 로드)
    with open(sequence_file, 'r', encoding='utf-8') as f:
        seq_data = json.load(f)
        # sequence_file 구조 반영
        optimized_sequence = seq_data.get("final_optimized_sequence", [])

    with open(constraints_file, 'r', encoding='utf-8') as f:
        constraints_data = json.load(f)
        # constraints_file 구조 반영
        target_context = constraints_data.get("target_function_context", "Unknown Function")
        constraints = constraints_data.get("reachability_constraints", [])
        vuln_logic = constraints_data.get("vulnerability_logic", {})

    print(f"[+] Phase 3: Generating Fuzzing Seed Blueprint...")
    print(f"    - Target Context: {target_context[:50]}...")
    print(f"    - Sequence Steps: {len(optimized_sequence)}")
    print(f"    - Constraints: {len(constraints)}")

    # 3. Construct the Research-Grade Prompt (구체적 매핑 지시 추가)
    prompt = f"""
        Role: Fuzzing Architect.
        Task: Create a "Seed Blueprint" JSON for the Fuzzing Harness (This task targets protocol processing logic inside Windows kernel drivers).

        **[Goal]**
        You are constructing a "Seed Blueprint" JSON for protocol-aware packet sequences.
        Generate a strictly structured JSON object that defines the network traffic states required to reach and trigger the vulnerability.
        Your critical failure in previous attempts was leaving "packet_structure" arrays empty or incomplete.
        **You must populate `packet_structure` for EVERY packet in the sequence**, using standard protocol definitions and the provided constraints.

        **[Input Context]**
        1. **Target Function Context**: "{target_context}"
           - ACTION: Extract the function name from this string.
        
        2. **Traffic Sequence** (From Analysis): 
           {json.dumps(optimized_sequence, indent=2)}
           - ACTION: Map each `packet_name` to a logical state.

        3. **Binary Constraints** (From Reverse Engineering):
           {json.dumps(constraints, indent=2)}
           - ACTION: Apply these constraints to the "trigger_exploit" packet structure.
           - Use `high_level_inference` as the Field Name.
           - Use `required_state` to determine the Value (satisfy the check).

        4. **Vulnerability Logic**:
           {json.dumps(vuln_logic, indent=2)}
           - ACTION: Ensure the final payload aligns with this logic.

        **[Execution Procedure]**

        Step 1. Protocol & Spec Resolution (MANDATORY)
        For each packet in the traffic sequence:
        - Identify the exact network protocol(s) involved.
        - Identify the authoritative specification(s) that define the packet format.
        Acceptable sources include:
        - RFCs
        - Microsoft Open Specifications (MS-*)
        - Identify the exact spec section numbers that define the packet layout.

        If a packet cannot be mapped to a spec section, the output is INVALID.

        Step 2. Layered Packet Decomposition (MANDATORY)
        For EACH packet, decompose the structure into ALL required protocol layers.

        At minimum, consider:
        - Link / Transport layer headers (if applicable)
        - Session / Message headers
        - Command-specific request or response structures
        - Mandatory context, trailer, or transform structures

        Each layer MUST correspond to a formally defined structure in the spec.

        Step 3. Spec-Complete Field Expansion (CRITICAL)
        For EACH identified structure:

        - Expand ALL fields explicitly defined in the referenced spec section.
        - NO field may be omitted.
        - NO field may be merged or abstracted.
        - Field order MUST follow the specification order.

        Each field entry MUST include:
        - `name`
        - `type`
        - `value` (first: Constraint-Satisfied, second: Spec-Default)
        - `desc` (Rationale for inclusion)

        It is FORBIDDEN to:
        - Invent semantic, state, or implementation-level fields
        - Introduce flags or conditions not defined in the spec
        - Use placeholders or empty arrays

        Step 4. Cardinality & Structural Sanity Check (MANDATORY)
        Before finalizing a packet:

        - Estimate the expected field count for each structure based on the spec.
        - If the generated structure contains significantly fewer fields than expected,
        the packet MUST be regenerated.

        Examples:
        - Fixed-size headers MUST expand to all documented fields.
        - Variable-length structures MUST include all mandatory fixed fields.

        Step 5. Constraint Application (SECONDARY)
        Apply any user-provided constraints ONLY AFTER the full structure is defined.

        - Constraints MAY affect field values.
        - Constraints MUST NOT remove or replace spec-defined fields.
        - If a constraint conflicts with the spec, the spec takes precedence.

        Step 6. Cross-Packet Consistency (WHEN APPLICABLE)
        If the traffic sequence includes protocol state progression:
        - Ensure later packets are structurally valid given earlier packets.
        - Do NOT encode state as artificial fields.
        - State must be implied by protocol correctness alone.

        Step 7. Final Validation Gate (HARD REQUIREMENT)
        Before outputting the Seed Blueprint JSON:

        - Verify that EVERY packet contains a fully populated `packet_structure`.
        - Verify that EVERY structure maps to an explicit spec section.
        - Verify that NO non-spec fields exist.
        - If ANY check fails, REBUILD the entire output.

        **[Output Structure Requirement]**
        You MUST generate a valid JSON object strictly following this format:

        ```json
        {{
            "target_function": "<Extracted Function Name>",
            "required_states": ["packet_name_1", "packet_name_2", ...],
            "traffic_sequence": [
                {{
                    "packet_name": "packet_name_1",
                    "description": "Rationale for this packet",
                    "source_spec": "RFC XXXX",
                    "packet_structure": [
                        {{ "name": "FieldName", "type": "u32", "value": "0x12345678", "desc": "Reasoning..."}},
						{{ "name": "FieldName", "type": "u32", "value": "0x12345678", "desc": "Reasoning..."}},
                        ...
                    ]
                }},
                {{
                    "packet_name": "packet_name _2",
                    "description": "Rationale for this packet",
                    "source_spec": "RFC XXXX",
                    "packet_structure": [
                        {{ "name": "FieldName", "type": "u32", "value": "0x12345678", "desc": "Reasoning..."}},
						{{ "name": "FieldName", "type": "u32", "value": "0x12345678", "desc": "Reasoning..."}},
                        ...
                    ]
                }},
                ...
            ]
        }}
        ```

        **Rules:**
        1. Extract the `target_function` name intelligently from the text provided.
        2. For the `trigger_exploit` state, explicitly list fields found in the `Binary Constraints`. 
        3. Output ONLY the JSON.
    """

    # 4. Request Generation
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a Fuzzing Architect and Network Engineer. Output only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        
        # 5. Process and Save Output
        result_json = extract_json_from_response(response.choices[0].message.content)
        
        if result_json:
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(result_json, f, indent=2)
                
            print(f"    -> Successfully generated: {output_filename}")
        else:
            print("[-] Failed to extract valid JSON from LLM response.")
        
    except Exception as e:
        print(f"[-] Generation Failed: {e}")

# ==============================================================================
# EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    # Case Number (0796)
    case_num = "0796"
    
    # Define File Paths (Using variables from your environment)
    input_constraints = f"binary_constraints_summary_{case_num}_v2.json"
    input_sequence = f"state_sequence_{case_num}_v4.json"
    output_filename = f"fuzz_seed_blueprint_{case_num}.json"

    # 실행
    phase_3_seed_gen(input_sequence, input_constraints, output_filename)