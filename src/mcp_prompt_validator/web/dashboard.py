"""Dashboard routes: login + pages + JSON APIs for skills and prompts.

Endpoints are defined as closures over `settings` so they share the templates
engine and the login verifier. HTML pages redirect to login when unauthenticated;
API endpoints return 401 JSON.
"""

from __future__ import annotations

import inspect
import pathlib

from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from ..config import Settings
from ..logging_setup import get_logger
from ..prompts import service as prompt_service
from ..rbac import service as rbac_service
from ..skillset import service as skill_service

log = get_logger(__name__)
_TEMPLATES_DIR = pathlib.Path(__file__).parent / "templates"


def build_dashboard_routes(settings: Settings) -> list[Route]:
    base = settings.dashboard_path.rstrip("/") or "/admin"
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Starlette >= 0.29 takes (request, name, context); older releases took
    # (name, context). Pick the right call once, by signature — NOT by catching
    # TypeError around the render. Template rendering raises TypeError of its own
    # (e.g. `| tojson` on an undefined variable), and retrying such a failure
    # with the legacy signature buries the real cause under a misleading
    # "unhashable type: 'dict'" from Jinja's template cache.
    _wants_request = (
        list(inspect.signature(templates.TemplateResponse).parameters)[:1] == ["request"]
    )

    def render(request, name: str, ctx: dict | None = None):
        context = {
            "request": request,
            "base": base,
            "mcp_path": settings.mcp_path,
            # Full endpoint the client config must point at, e.g.
            # "http://localhost:8000/mcp" — used to render a ready-to-paste
            # connection block when a token is issued.
            "mcp_url": settings.resource_server_url.rstrip("/") + settings.mcp_path,
            "auth_mode": settings.auth_mode,
            "admin_user": request.session.get("admin_user"),
            "admin_role": request.session.get("admin_role"),
            **(ctx or {}),
        }
        if _wants_request:
            return templates.TemplateResponse(request, name, context)
        return templates.TemplateResponse(name, context)

    def current_admin(request) -> str | None:
        return request.session.get("admin_user")

    def login_redirect(request):
        return RedirectResponse(url=f"{base}/login", status_code=303)

    async def require_api(request):
        """Return (username, None) or (None, JSONResponse 401)."""
        user = current_admin(request)
        if not user:
            return None, JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        return user, None

    # --- auth --------------------------------------------------------------
    async def login_page(request):
        if current_admin(request):
            return RedirectResponse(url=base, status_code=303)
        return render(request, "login.html", {"error": request.query_params.get("error")})

    async def login_submit(request):
        form = await request.form()
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""
        if not username or not password:
            return RedirectResponse(
                url=f"{base}/login?error=Username+and+password+required", status_code=303
            )
        result = await rbac_service.verify_dashboard_login(username, password)
        if result is None:
            log.info("dashboard: rejected login for %r (bad credentials or not admin)", username)
            return RedirectResponse(
                url=f"{base}/login?error=Invalid+username+or+password", status_code=303
            )
        request.session["admin_user"] = result["username"]
        request.session["admin_role"] = result["role"]
        return RedirectResponse(url=base, status_code=303)

    async def logout(request):
        request.session.clear()
        return RedirectResponse(url=f"{base}/login", status_code=303)

    # --- pages -------------------------------------------------------------
    async def overview(request):
        if not current_admin(request):
            return login_redirect(request)
        users = await rbac_service.list_users()
        prompts = await prompt_service.list_all()
        skills = await skill_service.list_all()
        stats = {
            "users": len(users),
            "prompts": len(prompts),
            "global_prompts": sum(1 for p in prompts if p["is_global"]),
            "skills": len(skills),
            "global_skills": sum(1 for s in skills if s["is_global"]),
        }
        return render(request, "overview.html", {"active": "overview", "stats": stats})

    async def users_page(request):
        if not current_admin(request):
            return login_redirect(request)
        users = await rbac_service.list_users()
        roles = await rbac_service.list_roles()
        # Offered as required-template choices; per-user visibility is re-checked
        # server-side in set_required_template.
        prompts = await prompt_service.list_all()
        return render(
            request,
            "users.html",
            {
                "active": "users",
                "users": users,
                "roles": roles,
                "templates": [
                    {"name": p["name"], "owner": p["owner"], "is_global": p["is_global"]}
                    for p in prompts
                    if p["enabled"]
                ],
            },
        )

    async def prompts_page(request):
        if not current_admin(request):
            return login_redirect(request)
        prompts = await prompt_service.list_all()
        users = await rbac_service.list_users()
        return render(
            request,
            "prompts.html",
            {"active": "prompts", "prompts": prompts, "users": users},
        )

    async def skills_page(request):
        if not current_admin(request):
            return login_redirect(request)
        skills = await skill_service.list_all()
        users = await rbac_service.list_users()
        return render(
            request, "skills.html", {"active": "skills", "skills": skills, "users": users}
        )

    # --- JSON APIs ---------------------------------------------------------
    async def api_create_user(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await rbac_service.create_user(
            data.get("username"),
            data.get("role"),
            data.get("email") or None,
            data.get("password") or None,
        )
        await _audit(user, "dashboard.create_user", {"username": data.get("username")})
        return JSONResponse(result)

    async def api_set_password(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await rbac_service.set_password(data.get("username"), data.get("password") or "")
        await _audit(user, "dashboard.set_password", {"username": data.get("username")})
        return JSONResponse(result)

    async def api_set_required_template(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        username = data.get("username")
        template = data.get("template") or None
        result = await rbac_service.set_required_template(username, template)
        await _audit(
            user,
            "dashboard.set_required_template",
            {"username": username, "template": template},
        )
        return JSONResponse(result)

    async def api_issue_token(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        username = data.get("username")
        if settings.auth_mode == "jwt":
            from ..auth.jwt_service import issue_for_user

            result = await issue_for_user(username, name="dashboard")
        else:
            result = await rbac_service.mint_opaque_token(username, token_name="dashboard")
        await _audit(user, "dashboard.issue_token", {"username": username, "mode": settings.auth_mode})
        return JSONResponse(result)

    async def api_prompt_create(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await prompt_service.create(
            name=data.get("name", "").strip(),
            body=data.get("body", ""),
            description=data.get("description", ""),
            owner_username=(data.get("owner") or None),
            is_global=bool(data.get("is_global")),
            enabled=bool(data.get("enabled", True)),
        )
        await _audit(user, "dashboard.prompt_create", {"name": data.get("name")})
        return JSONResponse(result)

    async def api_prompt_toggle(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        tid, field, value = data.get("id"), data.get("field"), bool(data.get("value"))
        if field == "is_global":
            result = await prompt_service.set_global(tid, value)
        elif field == "enabled":
            result = await prompt_service.set_enabled(tid, value)
        else:
            return JSONResponse({"ok": False, "error": "field must be is_global|enabled"}, 400)
        await _audit(user, "dashboard.prompt_toggle", {"id": tid, "field": field, "value": value})
        return JSONResponse(result)

    async def api_prompt_delete(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await prompt_service.delete(data.get("id"))
        await _audit(user, "dashboard.prompt_delete", {"id": data.get("id")})
        return JSONResponse(result)

    async def api_skill_create(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await skill_service.create(
            name=(data.get("name") or "").strip(),
            description=data.get("description", ""),
            body=data.get("body", ""),
            owner_username=(data.get("owner") or None),
            is_global=bool(data.get("is_global")),
            enabled=bool(data.get("enabled", True)),
        )
        await _audit(
            user,
            "dashboard.skill_create",
            {
                "name": data.get("name"),
                "owner": data.get("owner"),
                "is_global": bool(data.get("is_global")),
            },
        )
        return JSONResponse(result)

    async def api_skill_update(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        sid = data.get("id")
        fields = {k: data[k] for k in ("description", "body") if k in data}
        result = await skill_service.update(sid, **fields)
        await _audit(user, "dashboard.skill_update", {"id": sid})
        return JSONResponse(result)

    async def api_skill_toggle(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        sid, field, value = data.get("id"), data.get("field", "enabled"), bool(data.get("value"))
        if field == "is_global":
            result = await skill_service.set_global(sid, value)
        elif field == "enabled":
            result = await skill_service.set_enabled(sid, value)
        else:
            return JSONResponse({"ok": False, "error": "field must be is_global|enabled"}, 400)
        await _audit(user, "dashboard.skill_toggle", {"id": sid, "field": field, "value": value})
        return JSONResponse(result)

    async def api_skill_delete(request):
        user, err = await require_api(request)
        if err:
            return err
        data = await request.json()
        result = await skill_service.delete(data.get("id"))
        await _audit(user, "dashboard.skill_delete", {"id": data.get("id")})
        return JSONResponse(result)

    return [
        Route(f"{base}/login", login_page, methods=["GET"]),
        Route(f"{base}/login", login_submit, methods=["POST"]),
        Route(f"{base}/logout", logout, methods=["GET"]),
        Route(base, overview, methods=["GET"]),
        Route(f"{base}/users", users_page, methods=["GET"]),
        Route(f"{base}/prompts", prompts_page, methods=["GET"]),
        Route(f"{base}/skills", skills_page, methods=["GET"]),
        Route(f"{base}/api/users", api_create_user, methods=["POST"]),
        Route(f"{base}/api/users/password", api_set_password, methods=["POST"]),
        Route(f"{base}/api/users/token", api_issue_token, methods=["POST"]),
        Route(f"{base}/api/users/template", api_set_required_template, methods=["POST"]),
        Route(f"{base}/api/prompts", api_prompt_create, methods=["POST"]),
        Route(f"{base}/api/prompts/toggle", api_prompt_toggle, methods=["POST"]),
        Route(f"{base}/api/prompts/delete", api_prompt_delete, methods=["POST"]),
        Route(f"{base}/api/skills", api_skill_create, methods=["POST"]),
        Route(f"{base}/api/skills/update", api_skill_update, methods=["POST"]),
        Route(f"{base}/api/skills/toggle", api_skill_toggle, methods=["POST"]),
        Route(f"{base}/api/skills/delete", api_skill_delete, methods=["POST"]),
    ]


async def _audit(username: str, action: str, detail: dict) -> None:
    from ..audit import record

    await record(action=action, username=username, decision="ok", detail=detail)
