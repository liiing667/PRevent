# The diff-processing implementation lives in src/scan/patch_utils.py.
# This module re-exports it so existing `src.utils.diffs` imports keep working.
from src.scan.patch_utils import (
    process_diff,
    remove_comments,
    get_additions_with_line_numbers,
    preserve_strings,
    get_comment_patterns,
    remove_comment_patterns,
    restore_strings,
)

__all__ = [
    'process_diff',
    'remove_comments',
    'get_additions_with_line_numbers',
    'preserve_strings',
    'get_comment_patterns',
    'remove_comment_patterns',
    'restore_strings',
]
