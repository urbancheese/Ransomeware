## Ransomware Simulation Code

**Overview:**
- Educational and research-oriented ransomware simulation.
- Demonstrates core ransomware functionalities and system modifications.
- Intended for use in controlled environments only.

**Key Features:**

- **Encryption Mechanism:**
  - **Algorithm:** AES in CTR (Counter) mode.
  - **Key Generation:** 256-bit random key.
  - **Nonce:** Randomly generated for each encryption.
  - **File Encryption:** Encrypts all files, excluding specific types and filenames, appends `.urban` extension.

- **System Modifications:**
  - **Task Manager Lock:** Disables access via Windows Registry modification.
  - **Command Prompt Lock:** Disables access via Windows Registry modification.
  - **Windows Defender:** Disables real-time monitoring and protection using PowerShell.

- **Persistence:**
  - **Startup Entry:** Adds entry to Windows Registry for startup execution.

- **Decryption Instructions:**
  - **Ransom Note:** Deletes most Desktop files, places a ransom note with decryption instructions.

- **Sandbox and Anti-Debugging Detection:**
  - **Sandbox Detection:** Checks for known sandbox artifacts.
  - **Blacklisted Processes:** Detects common security tools.

- **Network Interaction:**
  - **Decryption Key Transmission:** Sends key to a Discord webhook URL.

- **Timer-Based Execution:**
  - **Delay:** Introduces a 10-second delay before execution.
  - **Timer:** Runs operations over a specified duration.

**Usage Instructions:**
- Use in a controlled, isolated environment for educational purposes only.
- Modify placeholders (e.g., webhook URL, Bitcoin address) as needed.
- Follow legal and ethical standards.

**Ethical and Legal Warning:**
- Creating, distributing, or using ransomware is illegal and unethical.
- Code is for educational purposes in a controlled environment.
- Misuse can lead to severe legal consequences. Always focus on ethical practices.
