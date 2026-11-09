
# ==================================================
# SIMULATED MCP TOOL
# ==================================================

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

if __name__ == "__main__":

    response = send_report("security-team")

    print("\nTool response:")
    print(response)
