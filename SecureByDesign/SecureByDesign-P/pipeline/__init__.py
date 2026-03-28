"""
SecureByDesign Pipeline Module
Public API surface — Person B imports from here.

Usage:
    from pipeline.inference import analyze_dfd
    result = analyze_dfd(dfd_json_dict, security_context_string)
"""
from pipeline.inference import analyze_dfd

__all__ = ['analyze_dfd']
