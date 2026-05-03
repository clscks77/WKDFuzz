import re
import json
from openai import OpenAI

client = OpenAI()

def derive_state_sequence(summary_file, driver_name, function_name):
    with open(summary_file, 'r') as f:
        summary_data = json.load(f)
        
    prompt = f"""
        Role: Windows Kernel Network Stack Analyst & Protocol Fuzzing Architect.

        Task:
        Construct a generic "Reachability State Sequence" to trigger a specific kernel function.
        You must generalize beyond specific protocols (like SMB) and apply "Protocol State Machine" logic applicable to any Windows Kernel Driver (e.g., HTTP.sys, tcpip.sys, condrv.sys, etc.).

        [Input Artifacts]
        - Target Function: "{function_name}"
        - Vulnerability Context & Binary Constraints: {json.dumps(summary_data)}

        [GENERIC INFERENCE METHODOLOGY]

        Step 1: Protocol & Layer Identification
        * Analyze the function name prefix.
        * Determine the abstract protocol layer:
            * **L2/L3:** Raw packet processing (IP/TCP headers).
            * **L7/Application:** High-level parsing (HTTP Requests, RPC calls).
            * **IOCTL/Interface:** Local communication via DeviceIoControl.

        Step 2: Function Lifecycle Placement
        * Where does this function sit in the connection lifecycle?
            * **Initialization:** Handshake, Capability Negotiation (e.g., SYN, Hello).
            * **Context Setup:** Authentication, Session Creation, Object Binding.
            * **Dispatch/Action:** Processing specific commands, queries, or data payloads.
            * **Teardown:** Closing handles, freeing memory.
        * *Hint:* "Validate", "Parse", "Check" usually happen *immediately upon receiving a specific packet type*.

        Step 3: Constraint Translation (Assembly -> Protocol Logic)
        * Translate binary constraints into protocol requirements:
            * `cmp [offset], value` -> Requires a specific **Header Flag** or **Version Field**.
            * `test ptr, ptr` (Null Check) -> Requires a pre-allocated **Session/Object Context**.
        * **Bug Strategy:** If the bug is "Null Pointer Dereference", the sequence must create a *Partial State* (e.g., Authenticated but no Resource allocated) or use a *Mismatched Object Type* (e.g., Sending a Data packet on a Control channel).

        Step 4: Abstract Sequence Generation
        * Build a 3~5 step sequence using generic categories.
        * **Step 1:** Protocol Handshake (Version/Capability).
        * **Step 2:** Context Establishment (Session/Auth).
        * **Step 3:** Resource/Object Allocation (File, Socket, Stream).
        * **Step 4 (Trigger):** The specific Command/Packet that invokes the target function.

        **Output Requirement**:
        Return a valid JSON object.

        Format:
        {{
            "inference_logic": {{
                "identified_protocol": "Inferred Protocol Family",
                "lifecycle_stage": "Stage (e.g., Post-Handshake, Pre-Auth)",
                "trigger_hypothesis": "Explanation of why this sequence reaches the target."
            }},
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
    driver = "srv2.sys"
    func = "Srv2DecompressData"
    num = "0796"

    # Case2
    # driver = "srv2.sys"
    # func = "Smb2ValidateVolumeObjectsMatch"
    # num = "32230"

    # Case3
    # driver = "srv2.sys"
    # func = "Smb2ValidateSigningCapabilities"
    # num = "43642"
    
    result = derive_state_sequence(f"binary_constraints_summary_{num}.json", driver, func)
    
    result = result.strip()
    result = re.sub(r"^```(?:json)?\s*", "", result)
    result = re.sub(r"\s*```$", "", result)

    with open(f"state_sequence_{num}_v1-3.json", "w") as f:    # state_sequence_0796, state_sequence_32230, state_sequence_43642
        f.write(result)
    print(result)