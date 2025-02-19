import pytest
import igittigitt

def test_files_without_path():
    parser = igittigitt.IgnoreParser()

    # t.sol
    parser.add_rule('*.t.sol', base_path='/')
    assert parser.match("contract.t.sol") == True
    assert parser.match("contract.sol") == False

    # s.sol
    assert parser.match("contract.s.sol") == False
    parser.add_rule('*.s.sol', base_path='/')
    assert parser.match("contract.s.sol") == True
    assert parser.match("contract.sol") == False

# Doesn't ignore "tests/t.sol", but does with starting slash e.g. "/tests/t.sol"
def test_files_with_path():
    parser = igittigitt.IgnoreParser()

    # Only rules for file extensions
    parser.add_rule('*.t.sol', base_path='/')
    parser.add_rule('*.s.sol', base_path='/')

    # subdirectory
    assert parser.match("/contracts/contract.t.sol") == True

    # tests/
    assert parser.match("/tests/contract.t.sol") == True
    assert parser.match("/tests/contract.sol") == False # Not ignored yet
    parser.add_rule('/tests/', base_path='/')
    assert parser.match("/tests/contract.t.sol") == True # Still ignored
    assert parser.match("/tests/contract.sol") == True # Now ignored
    assert parser.match("/tests/note.txt") == True # Also ignored

    # scripts/
    assert parser.match("/scripts/contract.s.sol") == True # Already ignored
    assert parser.match("/scripts/contract.sol") == False # Not ignored yet
    assert parser.match("/scripts/README.md") == False # Not ignored yet
    parser.add_rule('/scripts/*', base_path='/')
    assert parser.match("/scripts/contract.sol") == True # Now ignored
    assert parser.match("/scripts/README.md") == True # Now ignored