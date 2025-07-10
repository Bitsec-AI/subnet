import os
from bitsec.utils.noise import add_comment_noise_simple
import pydantic
import random
import tempfile
import subprocess
import bittensor as bt
from typing import List, Tuple, TypeVar, Union
from bitsec.protocol import PredictionResponse
from bitsec.utils.llm import chat_completion, get_total_spend_cents, get_total_spend_cents_description, reset_total_spend_description
from bitsec.utils.logging import shorten_to_filename

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'samples')
VULNERABILITIES_DIR = 'vulnerabilities'
SECURE_CODE_DIR = 'clean-codebases'

# Define generic type T
T = TypeVar('T')

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
            
        # Initialize Foundry project
        try:
            init_result = subprocess.run(["forge", "init", "--force"], cwd=tmpdir, capture_output=True)
            init_result.check_returncode()  # This will raise CalledProcessError if forge init fails
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Forge not installed: {e.stderr.decode()}")
        except Exception as e:
            bt.logging.error(f"Unknown error trying to verify solidity code compiles: {e}")
            return False

        # Try to compile
        try:
            build_result = subprocess.run(["forge", "build"], cwd=tmpdir, capture_output=True)
            build_result.check_returncode()  # This will raise CalledProcessError if forge build fails
            return True
        except subprocess.CalledProcessError as e:
            return False
        except Exception as e:
            bt.logging.error(f"Unknown error trying to verify solidity code compiles: {e}")
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

def get_random_vulnerability_filename() -> str:
    """
    Get a random vulnerability filename.
    """
    return _get_random_filename(VULNERABILITIES_DIR, '.md')

def get_random_secure_filename() -> str:
    """
    Get a random secure filename.
    """
    return _get_random_filename(SECURE_CODE_DIR, '.sol')

def get_all_vulnerability_and_secure_filenames() -> Tuple[List[str], List[str]]:
    """
    Get filenames of all vulnerability and secure code sample files.
    
    Returns:
        Tuple[List[str], List[str]]: Lists of vulnerability and secure file paths
    """
    vuln_filenames = _get_all_filenames(VULNERABILITIES_DIR, '.md')
    secure_filenames = _get_all_filenames(SECURE_CODE_DIR, '.sol')
    return vuln_filenames, secure_filenames

def create_challenge_with_inputs(
    clean_code: str,
    vulnerability_description: str,
    model: str | None = None,
    temperature: float = 1.0,
    respond_as_str: bool = False
) -> Union[Tuple[str, PredictionResponse, float, str], Tuple[str, float, str]]:
    """
    Create a challenge using provided clean code and vulnerability description.
    
    Args:
        clean_code (str): The secure code to modify
        vulnerability_description (str): Description of vulnerability to inject
        model (str | None): Optional model to use for code generation
        temperature (float): Temperature parameter for generation
        respond_as_str (bool): Whether to respond as a string or code and PredictionResponse
    Returns:
        Union[Tuple[str, PredictionResponse, float, str], Tuple[str, float, str]]: Generated code, PredictionResponse (if respond_as_str is False), cost, cost description
    """
    # Create a prompt to inject the vulnerability
    prompt = f"""You are a white hat security research tool to help developer teams find bugs in development before reaching production. You are generating a challenge to test a smart contract security expert. Your task is to modify the given smart contract code to inject a vulnerability for the security expert to find.

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

    initial_spend = get_total_spend_cents()
    reset_total_spend_description()

    try:
        # Use the LLM to inject the vulnerability
        response = chat_completion(
            prompt,
            max_tokens=16000,
            temperature=0.9,
            response_format=NewlyVulnerableCode
        )
        if respond_as_str:
            modified_code = response
            vulnerability_info = None
        else:
            modified_code = response.code
            vulnerability_info = response.vulnerability_info
            bt.logging.info(f"llm returned vulnerability prediction: {vulnerability_info}")
        # TODO 3. make sure challenge codebase can compile, has labeled vuln
        # 4.a miner submits wrong vuln
        # 4.b miner submits right vuln
        # 5. graded correctly
        # TODO expand more codebases
        # TODO expand more vulnerabilities

        cost = get_total_spend_cents() - initial_spend
        cost_description = get_total_spend_cents_description()
        reset_total_spend_description()

        ## add layers of noise to make challenge harder
        modified_code = add_comment_noise_simple(modified_code)

        return modified_code, vulnerability_info, cost, cost_description
    except Exception as e:
        bt.logging.error(f"Failed to inject vulnerability: {e}")
        raise

def create_challenge(vulnerable: bool, secure_filename: str | None = None, vulnerability_filename: str | None = None, model: str | None = None, temperature: float = 1.0) -> Tuple[str, PredictionResponse]:
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
    
    modified_code, vulnerability_info, _, _ = create_challenge_with_inputs(clean_code, vulnerability_description, model, temperature)
    return modified_code, vulnerability_info
