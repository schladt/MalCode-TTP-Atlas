#!/usr/bin/env python3
"""
Simple Malware Archive Extractor
A lightweight script to extract password-protected archives using system tools.

This script uses command-line tools (unzip, 7z) which are more reliable
for handling various archive formats and password protection schemes.
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Optional
import shlex
import re


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('malware_extraction_simple.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SimpleMalwareExtractor:
    """Extract password-protected malware archives using system tools."""
    
    def __init__(self, base_path: str, extract_to: str = None):
        """
        Initialize the extractor.
        
        Args:
            base_path: Root path to search for archives
            extract_to: Base directory for extractions (if None, extracts in-place)
        """
        self.base_path = Path(base_path)
        self.extract_in_place = extract_to is None
        self.extract_to = Path(extract_to) if extract_to else None
        
        if not self.extract_in_place:
            self.extract_to.mkdir(exist_ok=True)
        
        # Common passwords to try (order matters - most common first)
        self.common_passwords = [
            "infected",     # Most common in theZoo and vx-underground
            "malware", 
            "password",
            "123456",
            "thezoo",
            "virus",
            "vxunderground",
            None            # Try no password (for non-protected archives)
        ]
        
        # Check available tools
        self.has_unzip = self._check_command("unzip")
        self.has_7z = self._check_command("7z") or self._check_command("7za")
        
        if not self.has_unzip:
            logger.warning("unzip not found - ZIP files may not extract properly")
        if not self.has_7z:
            logger.warning("7z not found - 7Z files cannot be extracted")
        
        # Statistics
        self.stats = {
            'found': 0,
            'extracted': 0,
            'failed': 0,
            'skipped': 0
        }
    
    def _check_command(self, command: str) -> bool:
        """Check if a command is available."""
        try:
            subprocess.run([command, "--help"], 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, 
                          check=False)
            return True
        except FileNotFoundError:
            return False
    
    def find_archives(self) -> List[Path]:
        """Find all supported archive files."""
        archives = []
        
        # Always search for zip files
        archives.extend(self.base_path.rglob("*.zip"))
        archives.extend(self.base_path.rglob("*.ZIP"))
        
        # Search for 7z files if 7z is available
        if self.has_7z:
            archives.extend(self.base_path.rglob("*.7z"))
            archives.extend(self.base_path.rglob("*.7Z"))
        
        logger.info(f"Found {len(archives)} archives to process")
        return sorted(archives)
    
    def find_password_in_directory(self, archive_path: Path) -> Optional[str]:
        """Look for password files in the same directory as the archive."""
        directory = archive_path.parent
        
        # Common password file patterns
        password_patterns = [
            f"{archive_path.stem}.pass",
            f"{archive_path.stem}.txt", 
            "password.txt",
            "pass.txt",
            "README.txt",
            "readme.txt",
            "README.md",
            "readme.md"
        ]
        
        for pattern in password_patterns:
            password_file = directory / pattern
            if password_file.exists() and password_file.is_file():
                try:
                    content = password_file.read_text(encoding='utf-8', errors='ignore').strip()
                    # Clean up the password (remove whitespace, common prefixes)
                    content = re.sub(r'^password[:\s]*', '', content, flags=re.IGNORECASE)
                    content = re.sub(r'^pass[:\s]*', '', content, flags=re.IGNORECASE)
                    if content:
                        logger.debug(f"Found password in {password_file}: {content}")
                        return content
                except Exception as e:
                    logger.warning(f"Error reading {password_file}: {e}")
                    continue
        
        return None
    
    def extract_zip_with_unzip(self, archive_path: Path, password: str, extract_dir: Path) -> bool:
        """Extract ZIP file using unzip command."""
        try:
            if password is None:
                # Try extraction without password
                cmd = [
                    "unzip", 
                    "-q",           # Quiet mode
                    "-o",           # Overwrite files
                    str(archive_path),
                    "-d", str(extract_dir)
                ]
            else:
                cmd = [
                    "unzip", 
                    "-P", password,  # Password
                    "-q",           # Quiet mode
                    "-o",           # Overwrite files
                    str(archive_path),
                    "-d", str(extract_dir)
                ]
            
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300)
            
            if result.returncode == 0:
                return True
            else:
                logger.debug(f"unzip failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout extracting {archive_path}")
            return False
        except Exception as e:
            logger.error(f"Error running unzip: {e}")
            return False
    
    def extract_7z_with_7z(self, archive_path: Path, password: str, extract_dir: Path) -> bool:
        """Extract 7Z file using 7z command."""
        try:
            # Try 7z first, then 7za
            cmd_base = ["7z"] if self._check_command("7z") else ["7za"]
            
            if password is None:
                # Try extraction without password
                cmd = cmd_base + [
                    "x",                    # Extract
                    "-y",                   # Yes to all prompts
                    str(archive_path),
                    f"-o{extract_dir}"      # Output directory
                ]
            else:
                cmd = cmd_base + [
                    "x",                    # Extract
                    f"-p{password}",        # Password  
                    "-y",                   # Yes to all prompts
                    str(archive_path),
                    f"-o{extract_dir}"      # Output directory
                ]
            
            result = subprocess.run(cmd,
                                  capture_output=True,
                                  text=True,
                                  timeout=300)
            
            if result.returncode == 0:
                return True
            else:
                logger.debug(f"7z failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout extracting {archive_path}")
            return False
        except Exception as e:
            logger.error(f"Error running 7z: {e}")
            return False
    
    def test_password(self, archive_path: Path, password: str) -> bool:
        """Test if a password works for the archive."""
        try:
            if archive_path.suffix.lower() == '.zip' and self.has_unzip:
                # Test with unzip -t (test integrity)
                if password is None:
                    cmd = ["unzip", "-t", str(archive_path)]
                else:
                    cmd = ["unzip", "-t", "-P", password, str(archive_path)]
                result = subprocess.run(cmd, 
                                      capture_output=True, 
                                      timeout=30)
                return result.returncode == 0
                
            elif archive_path.suffix.lower() == '.7z' and self.has_7z:
                # Test with 7z t (test integrity)
                cmd_base = ["7z"] if self._check_command("7z") else ["7za"]
                if password is None:
                    cmd = cmd_base + ["t", str(archive_path)]
                else:
                    cmd = cmd_base + ["t", f"-p{password}", str(archive_path)]
                result = subprocess.run(cmd,
                                      capture_output=True,
                                      timeout=30)
                return result.returncode == 0
                
        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout testing password for {archive_path}")
            return False
        except Exception:
            return False
        
        return False
    
    def try_passwords(self, archive_path: Path) -> Optional[str]:
        """Try different passwords to find the correct one."""
        # First try to find password in directory
        found_password = self.find_password_in_directory(archive_path)
        if found_password:
            passwords_to_try = [found_password] + self.common_passwords
        else:
            passwords_to_try = self.common_passwords
        
        # Remove duplicates while preserving order
        seen = set()
        unique_passwords = []
        for pwd in passwords_to_try:
            if pwd not in seen:
                unique_passwords.append(pwd)
                seen.add(pwd)
        
        for password in unique_passwords:
            if self.test_password(archive_path, password):
                pwd_display = "no password" if password is None else password
                logger.info(f"Correct password found for {archive_path.name}: {pwd_display}")
                return password
        
        return None
    
    def extract_archive(self, archive_path: Path, password: str) -> bool:
        """Extract an archive with the given password."""
        # Determine extraction directory
        if self.extract_in_place:
            # Extract to the same directory as the archive
            extract_dir = archive_path.parent / archive_path.stem
        else:
            # Extract to specified extraction directory, preserving structure
            relative_path = archive_path.relative_to(self.base_path)
            extract_dir = self.extract_to / relative_path.parent / archive_path.stem
        
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        success = False
        
        if archive_path.suffix.lower() == '.zip':
            success = self.extract_zip_with_unzip(archive_path, password, extract_dir)
        elif archive_path.suffix.lower() == '.7z':
            success = self.extract_7z_with_7z(archive_path, password, extract_dir)
        
        if success:
            logger.info(f"Successfully extracted {archive_path.name} to {extract_dir}")
        else:
            # Clean up failed extraction directory
            try:
                if extract_dir.exists() and not any(extract_dir.iterdir()):
                    extract_dir.rmdir()
            except:
                pass
        
        return success
    
    def process_archive(self, archive_path: Path) -> bool:
        """Process a single archive: find password and extract."""
        logger.info(f"Processing: {archive_path}")
        self.stats['found'] += 1
        
        # Check if already extracted
        if self.extract_in_place:
            extract_dir = archive_path.parent / archive_path.stem
        else:
            relative_path = archive_path.relative_to(self.base_path)
            extract_dir = self.extract_to / relative_path.parent / archive_path.stem
        
        if extract_dir.exists() and any(extract_dir.iterdir()):
            logger.info(f"Already extracted: {archive_path.name}")
            self.stats['skipped'] += 1
            return True
        
        # Try to find the correct password
        password = self.try_passwords(archive_path)
        
        if password is None:
            logger.error(f"Could not find password for: {archive_path}")
            self.stats['failed'] += 1
            return False
        
        # Extract the archive
        if self.extract_archive(archive_path, password):
            self.stats['extracted'] += 1
            return True
        else:
            self.stats['failed'] += 1
            return False
    
    def extract_all(self, limit: int = None) -> None:
        """Extract all found archives."""
        archives = self.find_archives()
        
        if limit:
            archives = archives[:limit]
            logger.info(f"Processing only first {limit} archives for testing")
        
        logger.info(f"Starting extraction of {len(archives)} archives...")
        logger.warning("WARNING: Processing live malware samples!")
        logger.warning("Ensure you are running in an isolated environment!")
        
        for i, archive in enumerate(archives, 1):
            logger.info(f"Progress: {i}/{len(archives)}")
            try:
                self.process_archive(archive)
            except KeyboardInterrupt:
                logger.info("Extraction interrupted by user")
                break
            except Exception as e:
                logger.error(f"Unexpected error processing {archive}: {e}")
                self.stats['failed'] += 1
        
        # Print final statistics
        logger.info("=== EXTRACTION COMPLETE ===")
        logger.info(f"Archives found: {self.stats['found']}")
        logger.info(f"Successfully extracted: {self.stats['extracted']}")
        logger.info(f"Already extracted (skipped): {self.stats['skipped']}")
        logger.info(f"Failed: {self.stats['failed']}")
        if not self.extract_in_place and self.extract_to:
            logger.info(f"Extraction directory: {self.extract_to}")
        else:
            logger.info("Files extracted in-place (same directory as archives)")


def main():
    """Main function with command line argument parsing."""
    parser = argparse.ArgumentParser(
        description="Extract password-protected malware archives using system tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: This script processes live malware samples!
- Run only in isolated virtual machines
- Disable network connectivity  
- Use proper malware analysis precautions

Requirements:
- unzip (for ZIP files)
- 7z or 7za (for 7Z files)

Examples:
  python simple_extractor.py                                    # Extract all archives in-place
  python simple_extractor.py -p /path/to/malware               # Extract from specific path in-place  
  python simple_extractor.py -e /path/to/extractions           # Specify extraction directory
  python simple_extractor.py --test 5                          # Test with only 5 archives
  python simple_extractor.py --dry-run                         # Show what would be processed
  python simple_extractor.py -p ./MalwareSourceCode            # Extract vx-underground samples
        """
    )
    
    parser.add_argument('-p', '--path',
                       default='.',
                       help='Path to search for archives (default: current directory)')
    
    parser.add_argument('-e', '--extract-to',
                       help='Base directory for extractions (default: extract in-place)')
    
    parser.add_argument('--in-place', action='store_true',
                       help='Extract files in the same directory as archives (default behavior)')
    
    parser.add_argument('--test', type=int, metavar='N',
                       help='Test mode: process only first N archives')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without extracting')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate paths
    base_path = Path(args.path)
    if not base_path.exists():
        logger.error(f"Path does not exist: {base_path}")
        sys.exit(1)
    
    # Safety warnings
    print("=" * 60)
    print("SIMPLE MALWARE EXTRACTION TOOL")
    print("=" * 60)
    print("⚠️  WARNING: This tool processes LIVE MALWARE samples!")
    print("⚠️  Ensure you are running in an ISOLATED environment!")
    print("⚠️  Disable network connectivity before proceeding!")
    print("=" * 60)
    
    if not args.dry_run:
        response = input("Do you understand the risks and want to proceed? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            sys.exit(0)
    
    try:
        extractor = SimpleMalwareExtractor(
            base_path=str(base_path),
            extract_to=args.extract_to
        )
        
        if args.dry_run:
            archives = extractor.find_archives()
            print(f"\nDRY RUN: Would process {len(archives)} archives:")
            for archive in archives[:10]:  # Show first 10
                print(f"  {archive}")
            if len(archives) > 10:
                print(f"  ... and {len(archives) - 10} more")
        else:
            extractor.extract_all(limit=args.test)
            
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()