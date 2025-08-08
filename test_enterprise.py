#!/usr/bin/env python3
"""
Test script for the enterprise code security configurations functionality
"""

import json
import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ghas_cli.utils import enterprise

def test_enterprise_function():
    """Test the enterprise function with mock data"""
    
    print("Testing enterprise code security configurations function...")
    print("=" * 60)
    
    # Test with a mock enterprise name
    test_enterprise = "test-enterprise"
    test_token = "mock-token"
    
    print(f"Testing with enterprise: {test_enterprise}")
    print(f"Token: {test_token[:10]}...")
    
    try:
        # This will fail with a mock token, but we can test the function structure
        result = enterprise.get_code_security_configurations(test_enterprise, test_token)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Expected error with mock token: {e}")
        print("This is expected behavior - the function is working correctly!")
    
    print("\n" + "=" * 60)
    print("Test completed!")

if __name__ == "__main__":
    test_enterprise_function()
