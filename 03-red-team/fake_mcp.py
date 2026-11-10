
# ==================================================
# SIMULATED MCP TOOL
# ==================================================
# This fake tool models the external call path without sending real data so the red-team scenario stays isolated and safe.

def send_report(destination):

    """
    Simulated MCP tool.

    This function only records and prints a tool call.
    It does not send any real data externally.
    """

    result = {
        "tool": "send_report",
        "destination": destination,
        "status": "SIMULATED"
    }

    print("\n" + "=" * 60)
    print("TOOL CALLED: send_report")
    print(f"Destination: {destination}")
    print("Status: SIMULATED - No external data sent")
    print("=" * 60)

    return result


# ==================================================
# TEST TOOL
# ==================================================
# Running the tool directly demonstrates the exact payload that a malicious prompt would try to trigger.

if __name__ == "__main__":

    response = send_report("security-team")

    print("\nTool response:")
    print(response)
