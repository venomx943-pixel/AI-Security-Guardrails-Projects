import re
import logging
from typing import Tuple

logging.basicConfig(level=format('format', '%(asctime)s - [%(levelname)s] - %(message)s'), level=logging.INFO)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class OutputGuardrail:
    def __init__(self):
        # Regular expressions to detect sensitive data leaks in AI responses
        self.sensitive_patterns = {
            "API_KEY": r"(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})",
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            "INTERNAL_SECRET": r"internal_secret_[a-zA-Z0-9_]+"
        }

    def validate_output(self, ai_response: str) -> Tuple[bool, str]:
        """
        Scans AI-generated output for any accidental or malicious data leakage 
        before it reaches the user, enforcing the Fail-Closed security principle.
        """
        try:
            # Step 1: Ensure the response is not empty or abnormally massive
            if not ai_response or len(ai_response) > 20000:
                logging.warning("Output Security Alert: Response size violation or empty content.")
                return False, "System Notice: Response blocked due to structural safety limits."

            # Step 2: Scan for sensitive patterns (API keys, secrets, PII)
            for label, pattern in self.sensitive_patterns.items():
                if re.search(pattern, ai_response):
                    logging.error(f"Critical Security Alert: Data leakage detected! Type: {label}")
                    # Fail-Closed: Never expose the raw leaking response to the user
                    return False, "Security Shield Engaged: Output blocked to prevent data exfiltration."

            # Step 3: If clean, the output is safe to release
            return True, ai_response

        except Exception as e:
            # Enforcing Fail-Closed in case of unexpected execution failures
            logging.error(f"Internal output inspection exception: {str(e)}")
            return False, "Fail-Closed Active: Response withheld proactively for system safety."

# === Secure Test Environment ===
if __name__ == "__main__":
    guardrail = OutputGuardrail()

    # Test Case 1: Safe and clean AI response
    print("--- Output Test 1 ---")
    response_1 = "Hello! I can help you write secure Python scripts following best practices."
    safe, result = guardrail.validate_output(response_1)
    print(f"Status: {safe} | Result: {result}\n")

    # Test Case 2: Dangerous AI response leaking an API key
    print("--- Output Test 2 ---")
    response_2 = "Sure, here is your secret token: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz."
    safe, result = guardrail.validate_output(response_2)
    print(f"Status: {safe} | Result: {result}\n")