"""Tests for the core RBAC visibility rule (pure function).

Only two roles exist: admin (bypasses everything) and std_user (everyone
else), who may call any tagged tool except ones tagged "admin".
"""

from __future__ import annotations

from mcp_prompt_validator.skills.registry import tool_permitted


def test_admin_sees_everything():
    assert tool_permitted({"admin"}, is_admin=True)
    assert tool_permitted(set(), is_admin=True)


def test_std_user_sees_non_admin_tools():
    assert tool_permitted({"validator"}, is_admin=False)
    assert tool_permitted({"public"}, is_admin=False)


def test_std_user_denied_admin_tool():
    assert not tool_permitted({"admin"}, is_admin=False)


def test_untagged_tool_denied_by_default():
    assert not tool_permitted(set(), is_admin=False)
