import logging
from typing import Dict, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class AgenticToolGovernance:
    def __init__(self):
        # Define strict permission policies for different tools/actions
        # 0 = Blocked completely, 1 = Requires human approval, 2 = Safe to execute automatically
        self.tool_permissions = {
            "read_public_documents": 2,
            "send_email": 1,
            "delete_database": 0,
            "execute_system_command": 0,
            "transfer_funds": 1
        }

    def validate_tool_execution(self, tool_name: str, parameters: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Governs AI Agent tool calls, ensuring no unauthorized or destructive actions 
        are executed autonomously, enforcing the Fail-Closed security principle.
        """
        try:
            # Step 1: Check if the tool exists in our governance registry
            if tool_name not in self.tool_permissions:
                logging.warning(f"Security Alert: Attempt to invoke unregistered tool: {tool_name}")
                return False, "Access Denied: Unregistered tool execution blocked."

            permission_level = self.tool_permissions[tool_name]

            # Step 2: Enforce policy based on permission level
            if permission_level == 0:
                logging.error(f"Critical Security Alert: Blocked dangerous tool invocation: {tool_name}")
                return False, "Shield Engaged: This tool is strictly forbidden for autonomous execution."

            elif permission_level == 1:
                logging.warning(f"Security Notice: Tool '{tool_name}' requires human-in-the-loop approval.")
                # In a real production system, this triggers a pause and sends an alert to an admin dashboard
                return False, "Approval Required: High-risk action paused pending human authorization."

            elif permission_level == 2:
                logging.info(f"Tool execution authorized: {tool_name}")
                return True, "Tool execution approved for autonomous processing."

            else:
                return False, "Fail-Closed Active: Unknown permission state."

        except Exception as e:
            # Enforcing Fail-Closed in case of unexpected exceptions during tool governance
            logging.error(f"Internal tool governance exception: {str(e)}")
            return False, "Fail-Closed Active: Tool execution halted proactively for system safety."

# === Secure Test Environment for Lesson 4 ===
if __name__ == "__main__":
    governance = AgenticToolGovernance()

    # Test Case 1: Safe automated tool
    print("--- Tool Governance Test 1 ---")
    safe, msg = governance.validate_tool_execution("read_public_documents", {"query": "AI trends 2026"})
    print(f"Status: {safe} | Message: {msg}\n")

    # Test Case 2: High-risk tool requiring human-in-the-loop approval
    print("--- Tool Governance Test 2 ---")
    safe, msg = governance.validate_tool_execution("transfer_funds", {"amount": 5000, "target": "account_xyz"})
    print(f"Status: {safe} | Message: {msg}\n")

    # Test Case 3: Destructive tool that must be blocked completely
    print("--- Tool Governance Test 3 ---")
    safe, msg = governance.validate_tool_execution("delete_database", {"db_name": "production_users"})
    print(f"Status: {safe} | Message: {msg}\n")