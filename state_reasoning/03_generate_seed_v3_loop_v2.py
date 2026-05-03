import json
import re
import os
from openai import OpenAI

client = OpenAI()
MAX_RETRIES = 3
MODEL_NAME = "gpt-4o"

def extract_code_from_response(text):
    match = re.search(r"```(?:python)?\s*(.*?)\s*```", text, re.DOTALL)
    return match.group(1) if match else text

def load_file_content(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[-] File not found: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

# -------------------------------------------------------------------------
# [Phase 1] Initial Draft Generation
# -------------------------------------------------------------------------
def generate_initial_draft(sequence_content, constraints_content, structs_source):
    print(f"[*] [Phase 1] Generating Initial Draft based on Analysis...")

    prompt = f"""
    [Role]
    You are a Senior Security Researcher specializing in Windows kernel-level network protocol implementations and stateful binary protocol fuzzing.
    You design protocol seed generators, not exploits.

    [Objective]
    Create a standalone Python script ("Offline Protocol Seed Generator") that constructs FULL, WELL-FORMED raw network packets offline.

    Each generated packet MUST include:
    1. A transport-layer framing header (for message boundary definition)
    2. A protocol common header (shared by all messages)
    3. A protocol-specific message body

    The goal is to generate packets that the Windows kernel can realistically parse and use to advance protocol state.

    [Context - Protocol State Sequence]
    To reach the target kernel code path, the following protocol state sequence must be satisfied:
    {sequence_content}

    Each step corresponds to a complete protocol message, not just a body structure.

    [Context - Reachability Constraints (CRITICAL)]
    For the TARGET message in the sequence, the following constraints MUST hold:

    {constraints_content}

    Constraints may apply to:
    - Common header fields
    - Message body fields
    - Cross-layer relationships (lengths, offsets)

    [Key Design Requirements]

    1. **Explicit Message Layering**
    Every generated message MUST be constructed in the following order:

        [Transport Framing Header]
        - Defines message length or boundary for stream-based transports
        - Length MUST reflect the full payload size

        [Protocol Common Header]
        - Fixed-size header shared across all message types
        - Includes protocol identifier, command/type, flags, and context identifiers

        [Protocol Message Body]
        - Message-type-specific structure
        - Serialized strictly according to the reference definitions

    2. **Protocol-Agnostic FUZZ_CONFIG**
    - You MUST define a `FUZZ_CONFIG` dictionary yourself.
    - Organize it per message type.
    - Values must represent NORMAL, SPEC-COMPLIANT variations.
    - FUZZ_CONFIG is for state-space enumeration, not malformed input.

    3. **Structure-Driven Serialization**
    - Construct headers and bodies using reference structure logic.
    - Prefer `Structure.getData()` or equivalent serializers.
    - Avoid manual packing unless explicitly required by the reference.

    4. **Length & Offset Correctness**
    - Transport framing length MUST be computed AFTER full serialization.
    - Common header fields that depend on message size MUST be set correctly.
    - Cross-field invariants MUST hold.

    5. **Offline-Only Generation**
    - No sockets
    - No send/recv
    - No dependency on a live peer

    6. **State-Aware Packet Sequences**
    - Generate messages in correct protocol order.
    - Earlier messages must establish valid state for later ones.
    - The target message MUST satisfy all reachability constraints.

    [Authoritative Reference - Binary Structure Definitions]
    The following source provides authoritative structure definitions.

    Treat it as a protocol specification:
    - Do NOT invent fields
    - Do NOT omit mandatory headers
    - Preserve ordering, size, alignment, and padding
    - Respect computed fields and dynamic offsets

    {structs_source}

    [Implementation Constraints]
    - Language: Python
    - Allowed imports: struct, itertools, sys
    - External libraries may be used ONLY if they provide the reference structures.
    - Output must be raw bytes.

    [Output]
    Return the COMPLETE, EXECUTABLE Python script only.
    No explanation.
    """

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a compiler-level Python coder. Follow protocol specs strictly."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1 
    )
    return extract_code_from_response(response.choices[0].message.content)

# -------------------------------------------------------------------------
# [Phase 2] Iterative Refinement (Self-Correction)
# -------------------------------------------------------------------------
def refine_code(current_code, iteration_idx, sequence_content, constraints_content, structs_source):
    print(f"[*] [Phase 2] Refinement Iteration {iteration_idx + 1}...")

    prompt = f"""
    You are refining existing code that constructs network protocol messages
    intended to be parsed by Windows kernel-mode network drivers.

    The objective of this refinement is STRICT PROTOCOL CORRECTNESS and
    KERNEL REACHABILITY, not refactoring, simplification, or stylistic cleanup.

    Follow these rules without exception:

    1. Do NOT redefine, recreate, or reinterpret protocol headers that already
    exist in reference implementations or official specifications.

    2. Preserve strict structural separation between:
    - transport-layer framing,
    - common protocol headers,
    - message-specific bodies or payloads.

    3. Do NOT merge headers and bodies into a single structure, even if they are
    contiguous on the wire.

    4. Assume the target implementation performs strict structural validation
    in kernel mode. Any deviation in size, order, or alignment may cause the
    packet to be dropped before reaching deeper code paths.

    5. Transport-layer framing headers MUST be preserved or explicitly modeled.
    Never omit framing fields required for stream-based protocols.

    6. Length, offset, and size fields MUST be computed dynamically from the
    serialized data. Do NOT hardcode values unless explicitly required by
    the specification.

    7. If the semantic meaning of a field is unclear, preserve the original
    structure and behavior rather than attempting to "fix" or reinterpret it.

    8. Prefer minimal, structure-preserving changes over architectural or
    conceptual refactoring.

    9. Do NOT introduce protocol-specific assumptions beyond what is already
    present in the original code.

    The refined code must remain wire-compatible with the original protocol
    format and must be suitable for kernel-level protocol fuzzing.

    READ-ONLY CONTEXT (DO NOT MODIFY OR REINTERPRET)
    The following sections are provided for reference only.
    They must NOT be used as a basis for redesigning, restructuring,
    or reimplementing protocol layouts.

    [Current Script]
    {current_code}

    [Reachability Constraints]
    {constraints_content}

    [Reference Structure Definitions]
    {structs_source}

    OUTPUT REQUIREMENTS
    - Return the refined Python script only.
    - Preserve all existing protocol structures unless a change is strictly
    required to maintain kernel reachability.
    """

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a vulnerability researcher auditing code. Find and fix bugs."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.0
    )
    return extract_code_from_response(response.choices[0].message.content)

# -------------------------------------------------------------------------
# Main Workflow
# -------------------------------------------------------------------------
def main_workflow(sequence_file, constraints_file, structs_file, output_base_name):
    print(f"[+] Starting Context-Aware Fuzzer Generation")
    
    try:
        # Load raw content strings
        structs_source = load_file_content(structs_file)
        sequence_content = load_file_content(sequence_file)
        constraints_content = load_file_content(constraints_file)
    except Exception as e:
        print(f"[-] Error loading input files: {e}")
        return

    # 1. Initial Draft
    current_code = generate_initial_draft(sequence_content, constraints_content, structs_source)
    
    with open(f"{output_base_name}_v0_draft.py", 'w', encoding='utf-8') as f:
        f.write(current_code)
    print(f"    -> Draft saved.")

    # 2. Refinement Loop
    for i in range(MAX_RETRIES):
        try:
            current_code = refine_code(current_code, i, sequence_content, constraints_content, structs_source)
            
            with open(f"{output_base_name}_v{i+1}_refined.py", 'w', encoding='utf-8') as f:
                f.write(current_code)
            print(f"    -> Refined version {i+1} saved.")
        except Exception as e:
            print(f"[-] Error during refinement: {e}")
            break

    print(f"[+] Final script: {output_base_name}_v{MAX_RETRIES}_refined.py")

if __name__ == "__main__":
    case_num = "0796"
    input_constraints = f"binary_constraints_summary_{case_num}_v2.json"
    input_sequence = f"state_sequence_{case_num}_v4.json"
    
    # Impacket 소스 경로 (사용자 환경에 맞게 수정)
    structs_file_path = "C:\\Users\\User\\anaconda3\\Lib\\site-packages\\impacket\\smb3structs.py" 
    
    output_base = f"fuzzer_{case_num}_auto_config"
    
    main_workflow(input_sequence, input_constraints, structs_file_path, output_base)