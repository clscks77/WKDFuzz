import re
import json
from openai import OpenAI

client = OpenAI()

def derive_state_sequence(summary_file, driver_name, function_name):
    with open(summary_file, 'r') as f:
        summary_data = json.load(f)
        
    prompt = f"""
        Role: Senior Vulnerability Research Scientist specializing in Kernel Drivers and Network Protocols.
        Task: Reconstruct the minimal state transition path required to reach a specific vulnerable function within a target driver.
        
        **[Input Context]**
        - **Target Driver**: "{driver_name}"
        - **Target Function**: "{function_name}" ( The vulnerable endpoint )
        
        **[Binary Analysis Artifacts]**
        - **Path Constraints**: {json.dumps(summary_data, indent=2)}
        (Note: This JSON contains hard-coded checks found in the binary path to the function, such as magic numbers, size checks, or specific enum values.)

        **REASONING FRAMEWORK (Execute Step-by-Step)**:

        **Phase 1: Protocol Schema Inference**
        1. Infer the target protocol family based on the `{driver_name}`.
        2. Define the **"State Model"** for this protocol. Do NOT list all packets. Instead, define the abstract states a client must acquire to interact with deep functionality.
        - *Definition:* A "State" is a credential or context (e.g., Established Connection, Authenticated Session, Object Handle) required to send subsequent commands.

        **Phase 2: Target Anchoring via Constraint Alignment**
        1. Analyze the `{function_name}` semantics.
        2. **CRITICAL**: Cross-reference the **[Path Constraints]** (Magic Numbers, Enums) with your knowledge of the protocol's message structures.
        3. Identify the specific **Target Message/Command** that routes to this function.
        - *Reasoning Rule:* If the function semantics imply 'X', but the binary constraint checks for a magic value associated with 'Y', prioritize the binary evidence ('Y').

        **Phase 3: Backward State Resolution (The Chain)**
        1. Determine the **Pre-requisite State** required to send the Target Message identified in Phase 2.
        2. Identify the **Setup Message** responsible for granting this Pre-requisite State.
        3. Repeat this backward chaining until you reach the "Initial/Unconnected" state.
        4. *Filtering Rule:* Exclude extraneous business logic messages (e.g., Read/Write/Query) unless they are explicitly required to change the state needed for the Target Message. Focus ONLY on Control Plane / Handshake / Context Setup messages.

        **Phase 4: Forward Sequence Construction**
        - Reverse the chain from Phase 3 to form a chronological execution flow.
        - Assign a generic step name (e.g., "Initialization", "Authentication", "Context Creation") to each step.

        For every inferred state, message, or protocol rule:
        - Explicitly tag the knowledge source: [Binary Evidence | Public Spec | MS Documentation | Inferred Heuristic | Assumption]
        - Assign a confidence level. If a step relies purely on assumption, it MUST be marked as such.

        **Output Requirement**:
        Output ONLY a valid JSON object. Do not explain outside the JSON.

        Format:
        {{
        "inferred_protocol_family": "String",
        "phase_2_anchor_reasoning": "String (Explain how function name AND binary constraints (magic numbers/enums) point to the specific Target Message)",
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
            "step_category": "String (Abstract Stage, e.g., Setup/Auth)",
            "packet_name": "String (Technical Name)",
            "rationale": "String (Why is this strictly necessary for the next step?)"
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

    with open(f"state_sequence_{num}_v1-1.json", "w") as f:    # state_sequence_0796, state_sequence_32230, state_sequence_43642
        f.write(result)
    print(result)