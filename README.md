# MalCode-TTP-Atlas

**A comprehensive, source-code-based atlas of real-world malware tactics, techniques, and procedures (TTPs) mapped to the MITRE ATT&CK framework.**

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📖 Overview

MalCode-TTP-Atlas is a curated collection of **46 detailed malware analysis reports** extracted from real malware source code. Each report documents a specific attack technique with:

- 🔍 **Source Code Snippets** - Actual malware implementation (C/C++/Python)
- 🎯 **MITRE ATT&CK Mapping** - Precise technique classification
- 📡 **Detection Signatures** - Sysmon events, YARA rules, behavioral indicators
- 🛡️ **Mitigation Guidance** - Defensive recommendations and countermeasures
- 🧬 **Technical Analysis** - Function-level breakdown of malware behavior

This project bridges the gap between theoretical ATT&CK descriptions and real-world malware implementations, providing security researchers, threat hunters, and detection engineers with actionable intelligence derived from actual malicious code.

---

## 📂 Repository Structure

```
MalCode-TTP-Atlas/
├── c2_exfiltration_code_examples/       # Command & Control / Exfiltration (T1041, T1071)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_rBot_NetDevil_Binary_Upload_Raw_Sockets.md
│   ├── 02_Zeus_Botnet_RC4_Encrypted_HTTP_POST_Data_Exfiltration.md
│   └── 03_Win32_SpyBot_Reverse_HTTP_Server_File_Exfiltration.md
│
├── credential_theft_code_examples/      # Credential Access (T1555, T1539)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_Sin_Stealer_Chrome_Credential_Cookie_Theft_DPAPI.md
│   ├── 02_Sin_Stealer_Discord_Token_LevelDB_Extraction.md
│   └── 03_PryntStealer_Telegram_Session_tdata_Directory_Harvesting.md
│
├── defense_impairment_code_examples/   # Defense Evasion (T1562)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_IWorm_WarGames_Antivirus_Process_Termination.md
│   ├── 02_Win32_Plague_Windows_Firewall_Registry_Service_Disabling.md
│   └── 03_Reptile_DBot_Multi_Product_AV_Service_Stopping_Registry_Disabling.md
│
├── encryption_code_examples/            # Impact - Data Encrypted for Impact (T1486)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_Conti_Ransomware_v3_ChaCha20_Hybrid_Encryption.md
│   ├── 02_Jigsaw_Ransomware_AES256_Recursive_Encryption.md
│   ├── 03_SkynetLocker_Ransomware_AES_RSA_Parallel_Encryption.md
│   ├── 04_SintaLocker_CryPy_Python_AES_C2_Integration.md
│   └── 05_Hidden-tear_Educational_AES256_Ransomware_POC.md
│
├── file_collection_code_examples/       # Collection (T1005, T1083)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_AngstStealer_FileZilla_XML_Credential_Extraction.md
│   ├── 02_PredatorTheStealer_Multi_Wallet_Cryptocurrency_Harvesting.md
│   └── 03_Zeus_Zbot_Automated_Wildcard_File_Search_Recursive_Harvesting.md
│
├── injection_code_examples/             # Defense Evasion / Privilege Escalation (T1055)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_RedLine_Stealer_Process_Hollowing_RunPE.md
│   ├── 02_TinyNuke_Browser_Process_Hollowing_Manual_PE_Mapping.md
│   ├── 03_Zeus_Zbot_Remote_PE_Injection_Relocation_Fixup.md
│   ├── 04_Buhtrap_Classic_DLL_Injection_CreateRemoteThread.md
│   ├── 05_Zeus_Zbot_Mass_Process_Enumeration_User_Context_Filtering.md
│   ├── 06_Rovnix_Bootkit_Kernel_Mode_APC_Queue_Injection.md
│   └── 07_BlackLotus_UEFI_Bootkit_Section_Mapping_Injection.md
│
├── persistence_code_examples/           # Persistence (T1547, T1053)
│   ├── 00_EXECUTIVE_SUMMARY.md
│   ├── 01_xTBot_Windows_Scheduled_Task_XML_Registration.md
│   ├── 02_XBot_Windows_Service_Creation_Modification_Fallback.md
│   ├── 03_xTBot_Multi_Location_Registry_Run_Key_Redundant_Autostart.md
│   ├── ... (9 total reports)
│
└── task_code_examples/                  # Execution (T1053)
    ├── 00_EXECUTIVE_SUMMARY.md
    ├── 01_Gh0st_RAT_Remote_Code_Execution_Thread_Injection.md
    ├── 02_Zeus_Zbot_Command_Shell_Execution_STARTUPINFO_Hidden.md
    ├── ... (13 total reports)
```

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | # Reports | Examples |
|--------|-----------|-----------|----------|
| **Persistence** | T1547.001 (Registry Run Keys) | 3 | xTBot, SdBot multi-location persistence |
| | T1053.005 (Scheduled Tasks) | 6 | Gh0st RAT, Win32.Pinch task creation |
| | T1543.003 (Windows Service) | 2 | XBot service creation with fallback |
| **Defense Evasion** | T1562.001 (Impair Defenses: AV) | 3 | IWorm.WarGames, Reptile/DBot AV termination |
| | T1562.004 (Impair Defenses: Firewall) | 1 | Win32.Plague dual-method firewall disabling |
| | T1055 (Process Injection) | 7 | RedLine, TinyNuke, BlackLotus injection variants |
| **Credential Access** | T1555.003 (Browser Credentials) | 1 | Sin Stealer Chrome DPAPI decryption |
| | T1539 (Steal Web Session Cookies) | 2 | Discord token, Telegram session theft |
| **Collection** | T1005 (Local Data Staging) | 3 | FileZilla, cryptocurrency wallet harvesting |
| **Exfiltration** | T1041 (C2 Channel Exfiltration) | 3 | Zeus RC4 HTTP POST, rBot raw sockets |
| **Impact** | T1486 (Data Encrypted for Impact) | 5 | Conti, Jigsaw, SkynetLocker ransomware |

**Total Coverage:** 46 reports across 8 ATT&CK tactics, 15+ techniques

---

## 🔬 What Makes This Different?

### Traditional ATT&CK Resources:
- ❌ High-level technique descriptions
- ❌ Theoretical attack patterns
- ❌ Limited implementation details

### MalCode-TTP-Atlas:
- ✅ **Real malware source code** (not simulated)
- ✅ **Function-level analysis** with line-by-line explanations
- ✅ **Complete detection signatures** (Sysmon, YARA, behavioral)
- ✅ **Malware family comparisons** (e.g., Zeus vs. rBot C2 approaches)
- ✅ **Evasion technique documentation** (anti-AV, anti-sandbox)
- ✅ **Defensive recommendations** tailored to specific implementations

---

## 🚀 Use Cases

### 🔍 **Threat Hunters**
- Study real-world attacker tradecraft
- Build detection rules from actual malware behavior
- Understand evasion techniques used in the wild

### 🛡️ **Detection Engineers**
- Create high-fidelity Sysmon/EDR rules
- Develop YARA signatures from source-level patterns
- Test behavioral detection logic against known implementations

### 📚 **Security Researchers**
- Compare malware family evolution (Zeus → IcedID → Emotet)
- Analyze code reuse across malware variants
- Research novel persistence/injection techniques

### 🎓 **Educators & Students**
- Teach offensive security with real examples
- Demonstrate MITRE ATT&CK mapping in practice
- Lab exercises with authentic malware techniques

### 🧪 **Red Teams**
- Study adversary techniques for emulation
- Understand defender blind spots
- Develop realistic attack scenarios

---

## 📋 Report Format

Each analysis follows a standardized structure (600-1,200 words):

```markdown
# [Malware Family] - [Specific Technique]

**Repository:** `source-repository-name`  
**File:** `relative/path/to/source/file.cpp`  
**Language:** C/C++/Python  
**MITRE ATT&CK:** T1XXX.YYY (Technique Name)

## Overview
[150-300 word executive summary of the technique]

## Code Snippet & Analysis
[1-3 code blocks with inline technical explanations]

## Detection and Evasion
- Sysmon Event IDs and filters
- YARA signatures
- Behavioral indicators
- Evasion techniques employed

## Mitigation
[3-4 defensive recommendations]
```

---

## 🔗 Source Code References

This project analyzes malware from the following public repositories:

- **theZoo** - Malware research collection ([GitHub](https://github.com/ytisf/theZoo))
- **Malware-Collection** - Historical malware samples ([GitHub](https://github.com/Da2dalus/Malware-Collection))
- **MalwareSourceCode** - Curated malware source archive

**Note:** File paths in reports are relative to their source repositories. To access the original code:

```bash
# Example: rBot NetDevil report references:
# Repository: theZoo-master
# File: malware/Source/Original/rBot0.3.3_May2004/rBot0.3.3_May2004/rBot 0.3.3 - May 2004/netdevil.cpp

# Full path would be:
theZoo-master/malware/Source/Original/rBot0.3.3_May2004/rBot0.3.3_May2004/rBot 0.3.3 - May 2004/netdevil.cpp
```

⚠️ **Legal Disclaimer:** This project analyzes malware for educational and defensive purposes only. Do not use these techniques for malicious purposes. The source repositories are archived for research and should only be accessed in isolated, sandboxed environments.

---

## 📊 Statistics

- **Total Reports:** 46 individual analyses + 8 category summaries (54 files)
- **Malware Families:** 25+ distinct families (Zeus, Conti, Gh0st, BlackLotus, RedLine, etc.)
- **Code Languages:** C/C++ (80%), Python (15%), Other (5%)
- **Average Report Length:** 750 words (range: 589-1,453 words)
- **Detection Signatures:** 35+ YARA rules, 50+ Sysmon filters
- **Total Word Count:** ~40,000 words of technical analysis

---

## 🛠️ How to Use This Repository

### 1️⃣ **Browse by ATT&CK Tactic**
Navigate to the relevant `*_code_examples/` directory and read the `00_EXECUTIVE_SUMMARY.md` for an overview.

### 2️⃣ **Study Specific Techniques**
Each numbered report (e.g., `01_RedLine_Stealer_Process_Hollowing_RunPE.md`) contains:
- Complete code snippets
- Step-by-step technical breakdown
- Detection signatures ready to deploy

### 3️⃣ **Build Detection Rules**
Extract Sysmon XML filters and YARA rules directly from reports for immediate deployment.

### 4️⃣ **Cross-Reference Source Code**
Use the repository and file path metadata to locate the original malware source code for deeper analysis.

### 5️⃣ **Compare Implementations**
Read multiple reports within the same category to understand how different malware families implement the same technique (e.g., process injection variants).

---

## 🤝 Contributing

Contributions are welcome! If you'd like to add new malware analysis reports:

1. **Fork this repository**
2. **Follow the standardized format** (see existing reports)
3. **Ensure technical accuracy** (code must be from real malware)
4. **Include detection signatures** (Sysmon/YARA/behavioral)
5. **Map to MITRE ATT&CK** (verify technique ID)
6. **Submit a pull request**

### Quality Standards:
- ✅ 600-1,200 word target length
- ✅ Complete code snippets (not pseudocode)
- ✅ Inline technical explanations
- ✅ At least one detection signature
- ✅ Verified MITRE ATT&CK mapping

---

## 📚 Related Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [YARA Documentation](https://yara.readthedocs.io/)
- [theZoo Malware Repository](https://github.com/ytisf/theZoo)
- [Malware Bazaar](https://bazaar.abuse.ch/)

---

## ⚖️ Legal & Ethical Use

This project is intended for:
- ✅ Security research and education
- ✅ Defensive cybersecurity operations
- ✅ Threat intelligence development
- ✅ Academic study

**Prohibited uses:**
- ❌ Developing malware
- ❌ Conducting unauthorized attacks
- ❌ Violating computer crime laws
- ❌ Bypassing security controls without authorization

The maintainers of this repository do not condone illegal activities. All malware analysis is performed for defensive and educational purposes in accordance with applicable laws and ethical guidelines.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Note:** The analyzed malware source code is not included in this repository. References are provided to public archives for research purposes only.

---

## 📧 Contact

- **GitHub Issues:** For bug reports, questions, or feature requests
- **Contributions:** Submit pull requests following the contribution guidelines above

---

**⭐ Star this repository if you find it useful for security research!**

---

*Last Updated: November 2025*  
*Version: 1.0*  
*Total Reports: 46*
