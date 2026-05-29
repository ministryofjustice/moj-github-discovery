import os


# Setup Base Directories for Script Outputs
def base_directory_setup():
    """Configure base directories for outputs and internal files."""

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    # Configure base Output Directories
    base_output_dir = os.path.join(project_root, "output")
    base_internal_dir = os.path.join(project_root, "internal")

    # Ensure base output directories exist
    for directory in (base_output_dir, base_internal_dir):
        os.makedirs(directory, exist_ok=True)

    return base_output_dir, base_internal_dir
