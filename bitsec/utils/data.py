import os
import pydantic
import random
import tempfile
import subprocess
import bittensor as bt
import wandb
from typing import List, Tuple
from bitsec.protocol import PredictionResponse
from bitsec.utils.llm import chat_completion
from bitsec.utils.logging import shorten_to_filename

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'samples')
VULNERABILITIES_DIR = 'vulnerabilities'
SECURE_CODE_DIR = 'clean-codebases'

def verify_solidity_compilation(code: str) -> bool:
    """
    Verify that the Solidity code compiles using Foundry.
    
    Args:
        code (str): The Solidity code to verify
        
    Returns:
        bool: True if compilation succeeds, False otherwise
        
    Raises:
        ForgeNotInstalledError: If Forge toolchain is not found in system PATH
    """
    # Check for basic Solidity syntax
    strip_indentation = lambda s: '\n'.join([line.strip() for line in s.split('\n') if line.strip()])
    if not strip_indentation(code).startswith("// SPDX-License-Identifier: MIT\npragma solidity"):
        bt.logging.error("Code does not start with SPDX-License-Identifier: MIT\npragma solidity")
        return False
   
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a basic Foundry project structure
        os.makedirs(os.path.join(tmpdir, "src"))
        contract_path = os.path.join(tmpdir, "src", "Contract.sol")
        
        # Write the code to a temporary file
        with open(contract_path, 'w') as f:
            f.write(code)
            
        try:
            # Initialize Foundry project
            init_result = subprocess.run(["forge", "init", "--no-commit", "--force"], cwd=tmpdir, capture_output=True)
            init_result.check_returncode()  # This will raise CalledProcessError if forge init fails
            
            # Try to compile
            build_result = subprocess.run(["forge", "build"], cwd=tmpdir, capture_output=True)
            build_result.check_returncode()  # This will raise CalledProcessError if forge build fails
            return True
        except subprocess.CalledProcessError as e:
            bt.logging.error(f"Compilation failed: {e.stderr.decode()}")
            return False

def _get_all_filenames(directory: str, extension: str) -> List[str]:
    """
    Get all filenames with the given extension from the selected directory.

    Args:
        directory (str): The directory to get the filenames from
        extension (str): The extension of the files to get. Eg '.sol' or '.md'
        
    Returns:
        List[str]: List of filenames with the given extension in the selected directory
    """
    return [os.path.join(SAMPLE_DIR, directory, f) for f in os.listdir(os.path.join(SAMPLE_DIR, directory)) if f.endswith(extension)]

def _get_random_filename(directory: str, extension: str) -> str:
    """
    Get a random filename with the given extension from the selected directory.

    Args:
        extension (str): The extension of the files to get. Eg '.sol' or '.md'

    Returns:
        str: The filename of the random file with the given extension in the selected directory.
    """
    files = _get_all_filenames(directory, extension)
    if not files:
        raise ValueError(f"No files found with extension {extension} in directory {directory}")
    return random.choice(files)

def get_all_vulnerability_and_secure_filenames() -> Tuple[List[str], List[str]]:
    """
    Get filenames of all vulnerability and secure code sample files.
    
    Returns:
        Tuple[List[str], List[str]]: Lists of vulnerability and secure file paths
    """
    vuln_filenames = _get_all_filenames(VULNERABILITIES_DIR, '.md')
    secure_filenames = _get_all_filenames(SECURE_CODE_DIR, '.sol')
    return vuln_filenames, secure_filenames

def create_challenge(vulnerable: bool, secure_filename: str | None = None, vulnerability_filename: str | None = None) -> Tuple[str, PredictionResponse]:
    """
    Create a challenge 
    
    Args:
        vulnerable (bool): Whether to create a vulnerable or secure challenge
        secure_filename (str | None): Path to the source file, optional
        vulnerability_filename (str | None): Path to the vulnerability description, optional
        
    Returns:
        Tuple[str, PredictionResponse]: Generated code and expected response
    """
    if secure_filename is None:
        # use random sample codebase
        secure_filename = _get_random_filename(SECURE_CODE_DIR, '.sol')
    bt.logging.info(f"creating challenge: vulnerable: {vulnerable}, secure code: {shorten_to_filename(secure_filename)}")
    clean_code = open(secure_filename, 'r').read()
        
    if not vulnerable:
        return clean_code, PredictionResponse(prediction=False, vulnerabilities=[])
    
    if vulnerability_filename is None:
        # use random sample vulnerability
        vulnerability_filename = _get_random_filename(VULNERABILITIES_DIR, '.md')

    bt.logging.info(f"\tvulnerability: {shorten_to_filename(vulnerability_filename)}")
    vulnerability_description = open(vulnerability_filename, 'r').read()
    wandb.log({"created challenge, vulnerability description": vulnerability_description})
    
    # Create a prompt to inject the vulnerability
    prompt = f"""You are a smart contract security expert. Your task is to modify the given smart contract code to inject a vulnerability.

Here is the vulnerability description:
{vulnerability_description}

Here is the clean code:
{clean_code}

Instructions:
1. Modify the code to inject the vulnerability described above.
2. Make the changes look natural, as if a developer made them without realizing the security implications!!
3. Return ONLY the modified code and vulnerability description, no explanations

Modified code:"""

    # Pydantic model to parse the LLM response
    class NewlyVulnerableCode(pydantic.BaseModel):
        code: str
        vulnerability_info: PredictionResponse

    try:
        # Use the LLM to inject the vulnerability
        response = chat_completion(
            prompt,
            max_tokens=10000,
            temperature=1.0,
            response_format=NewlyVulnerableCode
        )
        
        modified_code = response.code
        vulnerability_info = response.vulnerability_info
        bt.logging.info(f"llm returned vulnerability prediction: {vulnerability_info}")
        # TODO 3. make sure challenge codebase can compile, has labeled vuln
        # 4.a miner submits wrong vuln
        # 4.b miner submits right vuln
        # 5. graded correctly
        # TODO expand more codebases
        # TODO expand more vulnerabilities
        ## add layers of noise to make challenge harder
        return modified_code, vulnerability_info
    except Exception as e:
        bt.logging.error(f"Failed to inject vulnerability: {e}")
