import pytest
import os
from flaky import flaky
from unittest.mock import patch, MagicMock
from bitsec.utils.llm import chat_completion
from bitsec.protocol import PredictionResponse, Vulnerability, LineRange
from typing import Any
from unittest.mock import patch, MagicMock
from bitsec.miner.prompt import analyze_code, VULN_PROMPT_TEMPLATE, VALIDATE_CODE_PROMPT_TEMPLATE, PredictionResponse
import openai
import bittensor as bt


# Not used yet
SPEND_MONEY = os.environ.get("SPEND_MONEY", False)
if SPEND_MONEY:
    bt.logging.set_debug()

TEST_RESPONSE = "Test response"


def test_analyze_code_prompt_selection_no_validation(
    sample_code: str
) -> None:
    """Test that correct prompt template is used when no analysis_to_validate is provided.
    
    Args:
        sample_code: Sample code to analyze
    """
    with patch('bitsec.miner.prompt.chat_completion') as mock_chat:
        analyze_code(sample_code, analysis_to_validate=None)
        
        # Verify the VULN_PROMPT_TEMPLATE was used (initial analysis)
        call_args = mock_chat.call_args[1]
        expected_prompt = VULN_PROMPT_TEMPLATE.format(code=sample_code)
        assert call_args['prompt'] == expected_prompt

def test_analyze_code_prompt_selection_with_validation(
    sample_code: str,
    sample_prediction_response: PredictionResponse
) -> None:
    """Test that correct prompt template is used when analysis_to_validate is provided.
    
    Args:
        sample_code: Sample code to analyze
        sample_prediction_response: Sample prediction response to validate
    """
    with patch('bitsec.miner.prompt.chat_completion') as mock_chat:
        analyze_code(sample_code, analysis_to_validate=sample_prediction_response)
        
        # Verify the VALIDATE_CODE_PROMPT_TEMPLATE was used (validation)
        call_args = mock_chat.call_args[1]
        expected_prompt = VALIDATE_CODE_PROMPT_TEMPLATE.format(
            code=sample_code,
            analysis=sample_prediction_response
        )
        assert call_args['prompt'] == expected_prompt


def test_analyze_code_initial_analysis(
    mock_chat_completion: MagicMock,
    sample_code: str
) -> None:
    """Test analyze_code when performing initial vulnerability analysis.
    
    Args:
        mock_chat_completion: Mocked chat_completion function
        sample_code: Sample code to analyze
    """
    with patch('bitsec.miner.prompt.chat_completion', mock_chat_completion):
        analyze_code(sample_code)
        
        # Verify chat_completion was called with correct parameters
        mock_chat_completion.assert_called_once()
        call_args = mock_chat_completion.call_args[1]
        
        assert call_args['prompt'] == VULN_PROMPT_TEMPLATE.format(code=sample_code)
        assert call_args['response_format'] == PredictionResponse
        assert call_args['max_tokens'] == 4000

def test_analyze_code_validation(
    mock_chat_completion: MagicMock,
    sample_code: str,
    sample_prediction_response: PredictionResponse
) -> None:
    """Test analyze_code when validating an existing analysis.
    
    Args:
        mock_chat_completion: Mocked chat_completion function
        sample_code: Sample code to analyze
        sample_prediction_response: Sample prediction response to validate
    """
    with patch('bitsec.miner.prompt.chat_completion', mock_chat_completion):
        analyze_code(sample_code, analysis_to_validate=sample_prediction_response)
        
        # Verify chat_completion was called with correct parameters
        mock_chat_completion.assert_called_once()
        call_args = mock_chat_completion.call_args[1]
        
        assert call_args['prompt'] == VALIDATE_CODE_PROMPT_TEMPLATE.format(
            code=sample_code,
            analysis=sample_prediction_response
        )
        assert call_args['response_format'] == PredictionResponse
        assert call_args['max_tokens'] == 4000

def test_analyze_code_with_model_and_temperature(
    mock_chat_completion: MagicMock,
    sample_code: str
) -> None:
    """Test analyze_code with custom model and temperature parameters.
    
    Args:
        mock_chat_completion: Mocked chat_completion function
        sample_code: Sample code to analyze
    """
    model = "gpt-4"
    temperature = 0.7
    
    with patch('bitsec.miner.prompt.chat_completion', mock_chat_completion):
        analyze_code(
            sample_code,
            model=model,
            temperature=temperature
        )
        
        # Verify chat_completion was called with correct parameters
        mock_chat_completion.assert_called_once()
        call_args = mock_chat_completion.call_args[1]
        
        assert call_args['model'] == model
        assert call_args['temperature'] == temperature

def test_analyze_code_returns_prediction_response(
    mock_chat_completion: MagicMock,
    sample_code: str,
    sample_prediction_response: PredictionResponse
) -> None:
    """Test that analyze_code returns the PredictionResponse from chat_completion.
    
    Args:
        mock_chat_completion: Mocked chat_completion function
        sample_code: Sample code to analyze
        sample_prediction_response: Expected prediction response
    """
    mock_chat_completion.return_value = sample_prediction_response
    
    with patch('bitsec.miner.prompt.chat_completion', mock_chat_completion):
        result = analyze_code(sample_code)
        
        assert isinstance(result, PredictionResponse)
        assert result == sample_prediction_response

@pytest.fixture
def mock_chat_completion() -> MagicMock:
    """Create a mock for the chat_completion function.
    
    Returns:
        MagicMock: Mocked chat_completion function
    """
    return MagicMock()

@pytest.fixture
def sample_code() -> str:
    """Provide sample code for testing.
    
    Returns:
        str: Sample code snippet
    """
    return "contract Test { function vulnerable() public {} }"

@pytest.fixture
def sample_prediction_response() -> PredictionResponse:
    """Create a sample PredictionResponse object.
    
    Returns:
        PredictionResponse: Sample prediction response
    """
    return PredictionResponse.from_tuple([True, []])

# Not used
@pytest.fixture
def mock_openai_response():
    """Create a mock OpenAI API response."""
    message = MagicMock()
    message.content = TEST_RESPONSE
    message.parsed = None
    message.refusal = None
    
    response = MagicMock()
    response.choices = [MagicMock(message=message)]
    return response
