#!/usr/bin/env python3.12

import argparse
import subprocess
from pathlib import Path
import sys
import shutil

# --- Modified Constants ---
VENV_DIRNAME = ".venv"
REQUIRED_PYTHON = "python3.12"
ESPHOME_VERSION = "2026.6.2"
# --------------------------

def find_project_root(start: Path) -> Path:
    current = start.resolve()
    for parent in [current] + list(current.parents):
        if (parent / "secrets.yaml").exists():
            return parent
    print("Error: Could not find secrets.yaml in any parent directory.")
    sys.exit(1)


def ensure_venv(project_root: Path, reinstall: bool = False):
    venv_path = project_root / VENV_DIRNAME
    venv_python = venv_path / "bin" / "python"

    if reinstall and venv_path.exists():
        print(f"Removing existing venv at {venv_path}...")
        shutil.rmtree(venv_path)

    if not venv_path.exists():
        # Check if python3.12 is installed on the system
        if not shutil.which(REQUIRED_PYTHON):
            print(f"Error: {REQUIRED_PYTHON} not found in PATH. Please install it first.")
            sys.exit(1)

        print(f"Creating virtual environment using {REQUIRED_PYTHON}...")
        subprocess.run(
            [REQUIRED_PYTHON, "-m", "venv", str(venv_path)],
            check=True
        )

        print(f"Upgrading pip and installing ESPHome {ESPHOME_VERSION}...")
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
            check=True
        )
        # Modified to use explicit version pinning
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", f"esphome=={ESPHOME_VERSION}"],
            check=True
        )

    return venv_python


def main():
    parser = argparse.ArgumentParser(
        description="ESPHome build & upload wrapper (venv-based)"
    )

    parser.add_argument("yaml", help="Path to YAML file")
    parser.add_argument("--device-id", required=True, help="Device ID")
    parser.add_argument("--compile-only", action="store_true", help="Only compile")
    parser.add_argument("--clean", action="store_true", help="Clean build files first")
    parser.add_argument("--reinstall", action="store_true", help="Recreate venv")

    args = parser.parse_args()

    script_dir = Path(__file__).parent
    project_root = find_project_root(script_dir)

    yaml_path = Path(args.yaml).resolve()

    if not yaml_path.exists():
        print(f"YAML file not found: {yaml_path}")
        sys.exit(1)

    try:
        yaml_relative = yaml_path.relative_to(project_root)
    except ValueError:
        print("Error: YAML file must be inside the project directory.")
        sys.exit(1)

    # Setup venv
    venv_python = ensure_venv(project_root, reinstall=args.reinstall)

    # Ensure secrets.yaml available locally
    yaml_dir = yaml_path.parent
    root_secrets = project_root / "secrets.yaml"
    local_secrets = yaml_dir / "secrets.yaml"
    secrets_created = False

    try:
        # Symlink/Copy management
        if not local_secrets.exists():
            try:
                # Use absolute path for symlink source to avoid broken links
                local_secrets.symlink_to(root_secrets.absolute())
            except Exception:
                shutil.copy2(root_secrets, local_secrets)
            secrets_created = True

        # Optional clean
        if args.clean:
            clean_cmd = [
                str(venv_python),
                "-m", "esphome",
                "clean",
                str(yaml_relative),
            ]
            print("Cleaning build...")
            subprocess.run(clean_cmd, check=True, cwd=project_root)

        # Build / Run
        command = [
            str(venv_python),
            "-m", "esphome",
            "-s", "device_id", args.device_id,
            "compile" if args.compile_only else "run",
            str(yaml_relative),
        ]

        print("\nProject root:", project_root)
        print("Running command:")
        print(" ".join(command))
        print()

        subprocess.run(command, check=True, cwd=project_root)

    finally:
        # Clean up the temporary secrets file if we created it
        if secrets_created and local_secrets.exists():
            try:
                local_secrets.unlink()
            except Exception:
                pass


if __name__ == "__main__":
    main()