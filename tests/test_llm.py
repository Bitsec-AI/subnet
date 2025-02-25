from pydantic import BaseModel
import pytest
import os
from flaky import flaky
from unittest.mock import patch, MagicMock
from bitsec.utils.llm import chat_completion, get_token_cost
import openai
import bittensor as bt
from bitsec.utils.data import create_challenge

SPEND_MONEY = os.environ.get("SPEND_MONEY", False)
if SPEND_MONEY:
    bt.logging.set_debug()

TEST_RESPONSE = "Test response"

@flaky(max_runs=3)
def test_chat_completion_response_format():
    """Test response with specific format type."""
    if not SPEND_MONEY:
        return
    
    # Make a simple object
    class TestResponse(BaseModel):
        can_answer: bool
        city_name: str
    
    prompt = "What is the capital of France? Answer with an empty string if you don't know."
    result = chat_completion(prompt, response_format=TestResponse)
    assert isinstance(result, TestResponse)
    assert result.can_answer == True
    assert result.city_name == "Paris"

    prompt = "What is the capital of the moon? Answer with an empty string if you don't know."
    result = chat_completion(prompt, response_format=TestResponse)
    assert isinstance(result, TestResponse)
    assert result.can_answer == False
    assert result.city_name == ""

def test_chat_completion_basic(mock_openai_response):
    """Test basic text response from chat completion."""
    with patch('bitsec.utils.llm.client.beta.chat.completions.parse', return_value=mock_openai_response):
        result = chat_completion("Test prompt")
        assert result == TEST_RESPONSE

def test_chat_completion_empty_response():
    """Test handling of empty response."""
    empty_response = MagicMock()
    empty_response.choices = []
    
    with patch('bitsec.utils.llm.client.beta.chat.completions.parse', return_value=empty_response):
        with pytest.raises(ValueError, match="AI returned empty or invalid response"):
            chat_completion("Test prompt")

def test_chat_completion_retry():
    """Test retry mechanism for rate limits."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content=TEST_RESPONSE, refusal=None))]
    
    with patch('bitsec.utils.llm.client.beta.chat.completions.parse') as mock_parse:
        mock_parse.side_effect = [
            openai.RateLimitError(
                message="Rate limit exceeded",
                response=MagicMock(status_code=429),
                body={"error": {"message": "Rate limit exceeded"}}
            ),
            mock_response
        ]
        result = chat_completion("Test prompt")
        assert result == TEST_RESPONSE
        assert mock_parse.call_count == 2, f"Expected 2 calls to parse, got {mock_parse.call_count}"

def test_chat_completion_refused():
    """Test handling of refused prompts."""
    mock_response = MagicMock()
    message = MagicMock()
    message.refusal = "Content policy violation"
    mock_response.choices = [MagicMock(message=message)]
    
    with patch('bitsec.utils.llm.client.beta.chat.completions.parse', return_value=mock_response):
        with pytest.raises(ValueError, match="Prompt was refused"):
            chat_completion("Test prompt")

def test_get_token_cost():
    """Test basic token cost calculation."""
    response = MagicMock()
    response.model = "testing"
    response.usage = MagicMock(
        prompt_tokens=1000,
        completion_tokens=1000,
        total_tokens=2000,
        prompt_tokens_details=MagicMock(cached_tokens=0),
        completion_tokens_details=MagicMock(
            reasoning_tokens=0,
            accepted_prediction_tokens=0,
            rejected_prediction_tokens=0
        )
    )

    fee, description = get_token_cost(response)
    # Using 1000 tokens to make math cleaner: 1000 * (1/1M) * 100 = 0.1
    assert fee == 0.2  # 0.1 for input + 0.1 for output
    assert "Input: ¢0.1" in description
    assert "Output: ¢0.1" in description

def test_get_token_cost_with_cached():
    """Test token cost with cached tokens."""
    response = MagicMock()
    response.model = "testing"
    response.usage = MagicMock(
        prompt_tokens=1000,
        completion_tokens=1000,
        total_tokens=2000,
        prompt_tokens_details=MagicMock(cached_tokens=500),
        completion_tokens_details=MagicMock(
            reasoning_tokens=0,
            accepted_prediction_tokens=0,
            rejected_prediction_tokens=0
        )
    )

    fee, description = get_token_cost(response)
    # 500 uncached + 500 cached + 1000 output, each at 0.1 per 1000 tokens
    assert fee == 0.2
    assert "Input: ¢0.1" in description
    assert "(cached: ¢0.1)" in description
    assert "Output: ¢0.1" in description

def test_get_token_cost_invalid_model():
    """Test invalid model handling."""
    response = MagicMock()
    response.model = "invalid-model"
    response.usage = MagicMock(
        prompt_tokens=1000,
        completion_tokens=1000,
        total_tokens=2000,
        prompt_tokens_details=MagicMock(cached_tokens=0)
    )

    with pytest.raises(ValueError, match="Model invalid-model not found in cost dictionary"):
        get_token_cost(response)

def test_get_token_cost_no_usage():
    """Test missing usage data handling."""
    response = MagicMock()
    response.model = "testing"
    response.usage = None

    with pytest.raises(ValueError, match="No usage data"):
        get_token_cost(response)

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
