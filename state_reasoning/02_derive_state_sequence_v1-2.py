import re
import json
from openai import OpenAI

client = OpenAI()

def derive_state_sequence(summary_file, driver_name, function_name):
    with open(summary_file, 'r') as f:
        summary_data = json.load(f)

    # ------------------------------------------------------------------
    # 실험: Binary Analysis Artifacts가 없을 경우
    # ------------------------------------------------------------------
    prompt = f"""
        Role: Senior Vulnerability Research Scientist specializing in Kernel Drivers and Network Protocols.
        Task: Reconstruct the logical state transition path required to reach a specific target function based on protocol specifications and function semantics.
        
        **[Input Context]**
        - **Target Driver**: "{driver_name}"
        - **Target Function**: "{function_name}" ( The vulnerable endpoint )
        
        **REASONING FRAMEWORK (Execute Step-by-Step)**:

        **Phase 1: Protocol Schema Inference**
        1. Identify the protocol family implementing `{driver_name}`.
        2. Define the **"State Model"** for this protocol based on Public Specifications (RFC, MS Docs).
        - *Definition:* A "State" is a credential or context (e.g., Established Connection, Authenticated Session) required to reach deep code paths.

        **Phase 2: Semantic Mapping (Function to Message)**
        1. Analyze the `{function_name}` semantics. Break down the naming convention (Prefix, Verb, Noun).
        2. **Map to Protocol Spec**: Correlate the function name with known protocol message types or IRP Major Functions.
        3. Deduce the **Target Message/Command** most likely to route to this function.
        - *Heuristic:* If the function implies a specific action, identify the specific protocol command that carries that data type.

        **Phase 3: Backward State Resolution (The Chain)**
        1. Determine the **Pre-requisite State** required to legitimately send the Target Message identified in Phase 2.
        2. Identify the **Setup Message** responsible for establishing this state.
        3. Repeat this backward chaining until you reach the "Initial/Unconnected" state.
        4. *Filtering Rule:* Focus ONLY on Control Plane / Handshake / Context Setup messages necessary to satisfy the dependency.

        **Phase 4: Forward Sequence Construction**
        - Reverse the chain from Phase 3 to form a chronological execution flow.
        - Assign a generic step name (e.g., "Initialization", "Authentication").

        **Output Requirement**:
        Output ONLY a valid JSON object. Do not explain outside the JSON.

        Format:
        {{
        "inferred_protocol_family": "String",
        "phase_2_inference_logic": "String (Explain how the function name maps to the specific protocol command based on specs)",
        "deduced_target_message": "String ( The specific command/opcode name )",
        "state_dependency_chain": [
            {{
            "required_state": "String (e.g., Valid Session ID)",
            "acquired_via_message": "String (The packet that creates this state)"
            }}
        ],
        "final_sequence": [
            {{
            "step_index": 1,
            "step_category": "String (Abstract Stage)",
            "packet_name": "String (Technical Name)",
            "rationale": "String (Why is this strictly necessary per the protocol spec?)"
            }},
            ...
        ]
        }}
    """

    print(f"[+] Research Mode: Deriving Sequence for {function_name}...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a methodical researcher. Expand vocabulary first, then select constraints."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )
        return response.choices[0].message.content
    except Exception as e:
        return json.dumps({"error": str(e)})

if __name__ == "__main__":
    # Case 1
    # driver = "srv2.sys"
    # func = "Srv2DecompressData"
    # num = "0796"

    # Case2
    driver = "srv2.sys"
    func = "Smb2ValidateVolumeObjectsMatch"
    num = "32230"

    # Case3
    # driver = "srv2.sys"
    # func = "Smb2ValidateSigningCapabilities"
    # num = "43642"
    
    result = derive_state_sequence(f"binary_constraints_summary_{num}.json", driver, func)
    
    result = result.strip()
    result = re.sub(r"^```(?:json)?\s*", "", result)
    result = re.sub(r"\s*```$", "", result)

    with open(f"state_sequence_{num}_v1-2.json", "w") as f:    # state_sequence_0796, state_sequence_32230, state_sequence_43642
        f.write(result)
    print(result)