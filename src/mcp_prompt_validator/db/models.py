"""ORM models: the RBAC + permanent-token + audit schema.

Design
------
* Role     -> exactly two fixed rows: "admin" (bypasses all tool gating) and
              "std_user" (may call any tool not tagged "admin" — see
              `skills/registry.py::tool_permitted`). No per-role permission
              editing; `is_admin` is the only thing that differentiates roles.
* User     -> a person/service account bound to exactly one role.
* ApiToken -> a PERMANENT per-user bearer credential. Only the SHA-256 hash is
              stored. `expires_at IS NULL` => never expires (permanent); a
              non-null `revoked_at` disables it immediately.
* Skill    -> an admin-authored Markdown "skill" document served over MCP
              (`list_skills`/`get_skill`), scoped per user the same way as
              PromptTemplate: owned by one user, or global to everyone.
* AuditLog -> append-only record of validation runs and access decisions for
              traceability.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

# JSONB on Postgres; falls back to a generic JSON on other dialects (SQLite tests).
from sqlalchemy import JSON

JSON_TYPE = JSONB().with_variant(JSON(), "sqlite")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    # Admin bypasses all tool gating; every other role is a plain std_user.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Dashboard login credential. NULL => the user cannot sign in to the dashboard
    # (e.g. service accounts that only ever use an MCP bearer token).
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Name of a PromptTemplate every prompt from this user MUST conform to.
    # NULL => conformance is opt-in, checked only when the caller passes
    # `template_name`. When set, the server injects it on every validation call
    # so a client cannot bypass the policy by omitting the argument. Stored as a
    # name (not an FK) because template names are unique per owner, not globally
    # — it is resolved through `prompts.service.get_for_user` at validation time.
    required_template: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    role: Mapped["Role"] = relationship(back_populates="users")
    tokens: Mapped[list["ApiToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class ApiToken(Base):
    """A permanent (or optionally expiring) per-user bearer token.

    The plaintext token is shown exactly once, at creation. We persist only:
      * `token_hash`  -> SHA-256 of the full token (constant-time compared).
      * `prefix`      -> the leading, non-secret characters, for display/lookup UX.
    """

    __tablename__ = "api_tokens"
    __table_args__ = (Index("ix_api_tokens_hash", "token_hash", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="default")
    token_hash: Mapped[str] = mapped_column(String(64))
    prefix: Mapped[str] = mapped_column(String(32))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # NULL == permanent (never expires).
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Non-NULL == revoked; the verifier rejects immediately.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="tokens")

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class PromptTemplate(Base):
    """A reusable, Jinja2-renderable prompt template.

    Scope:
      * owner_user_id set, is_global=False -> private to that user;
      * is_global=True                     -> available to ALL users
                                              (regardless of owner_user_id).
    A user "sees" a template if it is their own OR global, and enabled.
    """

    __tablename__ = "prompt_templates"
    __table_args__ = (
        Index("ix_prompt_templates_owner", "owner_user_id"),
        Index("ix_prompt_templates_name", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    is_global: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner: Mapped["User | None"] = relationship()


class Skill(Base):
    """An admin-authored, Markdown "skill" document served to MCP clients.

    Distinct from `skills/registry.py::TOOL_TAGS` (which tags Python-defined MCP
    *tools* for RBAC). A `Skill` row is pure content — name, one-line
    `description` (used for discovery in `list_skills`), and a Markdown `body`
    (the full instructions, returned by `get_skill`) — editable in the
    dashboard with no code changes.

    Scope mirrors `PromptTemplate` exactly:
      * owner_user_id set, is_global=False -> private to that user;
      * is_global=True                     -> available to ALL users
                                              (regardless of owner_user_id).
    A user "sees" a skill if it is their own OR global, and enabled. `name` is
    therefore NOT globally unique — two users may each own a "code-review"
    skill; uniqueness is enforced per (name, owner) in the service layer.
    """

    __tablename__ = "skills"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    owner_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    is_global: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    owner: Mapped["User | None"] = relationship()


class JwtGrant(Base):
    """Record of an issued JWT (auth_mode="jwt").

    JWTs are self-contained, so we do not store the token. We track the `jti`
    (JWT ID) so an admin can list issued grants and revoke one: a non-null
    `revoked_at` lands the jti on the denylist that the verifier checks.
    """

    __tablename__ = "jwt_grants"
    __table_args__ = (Index("ix_jwt_grants_jti", "jti", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), default="default")

    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship()

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    token_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. tool.call / access.deny
    tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)  # allow/deny/block...
    detail: Mapped[dict] = mapped_column(JSON_TYPE, default=dict)
