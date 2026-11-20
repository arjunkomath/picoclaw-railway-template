import asyncio
import base64
import copy
import json
import os
import re
import secrets
import signal
import subprocess
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

# Fields holding credentials. PicoClaw (config v3) stores these in
# .security.yml instead of config.json.
SECRET_FIELDS = {
    "api_key", "token", "app_secret", "encrypt_key",
    "verification_token", "bot_token", "app_token",
    "channel_secret", "channel_access_token", "client_secret",
    "access_token", "auth_token",
}
SECRET_LIST_FIELDS = {"api_keys"}

# Placeholder PicoClaw writes into config.json where a secret lives in .security.yml.
NOT_HERE = "[NOT_HERE]"
CONFIG_VERSION = 3

# Channel keys that sit at the top level of a channel_list entry; everything
# else belongs under "settings" (mirrors BaseFieldNames in PicoClaw).
CHANNEL_BASE_FIELDS = {
    "enabled", "type", "allow_from", "reasoning_channel_id",
    "group_trigger", "typing", "placeholder",
}

CONFIG_DIR = Path(os.environ.get("PICOCLAW_HOME", Path.home() / ".picoclaw"))
CONFIG_PATH = CONFIG_DIR / "config.json"
SECURITY_PATH = CONFIG_DIR / ".security.yml"

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    print(f"Generated admin password: {ADMIN_PASSWORD}")


class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        if "Authorization" not in conn.headers:
            return None

        auth = conn.headers["Authorization"]
        try:
            scheme, credentials = auth.split()
            if scheme.lower() != "basic":
                return None
            decoded = base64.b64decode(credentials).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            raise AuthenticationError("Invalid credentials")

        username, _, password = decoded.partition(":")
        if secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD):
            return AuthCredentials(["authenticated"]), SimpleUser(username)

        raise AuthenticationError("Invalid credentials")


def require_auth(request: Request):
    if not request.user.is_authenticated:
        return PlainTextResponse(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="picoclaw"'},
        )
    return None


# ── Config storage (PicoClaw config v3: config.json + .security.yml) ──


def _write_private(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_config_file() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _read_security_file() -> dict:
    if not SECURITY_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(SECURITY_PATH.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _is_secret_value(v) -> bool:
    return isinstance(v, str) and v != "" and v != NOT_HERE


def _clean_secret_list(values) -> list:
    if not isinstance(values, list):
        return []
    return [v for v in values if _is_secret_value(v)]


def _model_keys(model_list) -> list[str]:
    """Keys PicoClaw uses for model_list entries in .security.yml ("<model_name>:<n>")."""
    counts: dict[str, int] = {}
    keys = []
    for m in model_list:
        name = m.get("model_name", "") if isinstance(m, dict) else ""
        idx = counts.get(name, 0)
        keys.append(f"{name}:{idx}")
        counts[name] = idx + 1
    return keys


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def _strip_placeholders(data):
    if isinstance(data, dict):
        return {k: ("" if v == NOT_HERE else _strip_placeholders(v)) for k, v in data.items()}
    if isinstance(data, list):
        return [_strip_placeholders(v) for v in data if v != NOT_HERE]
    return data


def migrate_legacy_channels(cfg: dict) -> bool:
    """Fold a stale v2-style "channels" block into "channel_list".

    Older versions of this template kept writing a flat "channels" block,
    which PicoClaw v3 rejects as an unknown field. Anything meaningful in it
    (enabled flag, allow list, credentials) is carried over.
    """
    stale = cfg.pop("channels", None)
    if stale is None:
        return False
    channel_list = cfg.setdefault("channel_list", {})
    if isinstance(stale, dict):
        for name, ch in stale.items():
            if not isinstance(ch, dict):
                continue
            meaningful = ch.get("enabled") or ch.get("allow_from") or any(
                _is_secret_value(ch.get(f)) for f in SECRET_FIELDS
            )
            if not meaningful:
                continue
            target = channel_list.setdefault(name, {})
            target.setdefault("type", name)
            settings = target.setdefault("settings", {})
            for k, v in ch.items():
                if k in CHANNEL_BASE_FIELDS:
                    target[k] = v
                elif v not in ("", None, [], {}):
                    settings[k] = v
    return True


def load_config() -> dict:
    """Return the effective config with secrets from .security.yml folded in."""
    view = _read_config_file()
    sec = _read_security_file()
    migrate_legacy_channels(view)

    # Model API keys: keys in .security.yml win; keys written inline into
    # config.json (by older template versions) are used when it has none.
    sec_models = sec.get("model_list") or {}
    model_list = view.get("model_list") or []
    for m, key in zip(model_list, _model_keys(model_list)):
        if not isinstance(m, dict):
            continue
        entry = sec_models.get(key) if isinstance(sec_models, dict) else None
        keys = _clean_secret_list(entry.get("api_keys")) if isinstance(entry, dict) else []
        if not keys:
            keys = _clean_secret_list(m.get("api_keys"))
        if not keys and _is_secret_value(m.get("api_key")):
            keys = [m["api_key"]]
        m.pop("api_key", None)
        m["api_keys"] = keys

    # Channel credentials live under channel_list.<name>.settings in .security.yml.
    sec_channels = sec.get("channel_list") or sec.get("channels") or {}
    channel_list = view.get("channel_list") or {}
    if isinstance(sec_channels, dict):
        for name, entry in sec_channels.items():
            ch = channel_list.get(name)
            if not isinstance(ch, dict) or not isinstance(entry, dict):
                continue
            sec_settings = entry.get("settings")
            if isinstance(sec_settings, dict) and sec_settings:
                settings = ch.get("settings") if isinstance(ch.get("settings"), dict) else {}
                ch["settings"] = _deep_merge(settings, sec_settings)

    # Web search tool keys (tools are inlined at the top level of .security.yml).
    sec_web = sec.get("web")
    if isinstance(sec_web, dict) and sec_web:
        tools = view.setdefault("tools", {})
        web = tools.setdefault("web", {})
        _deep_merge(web, sec_web)

    return _strip_placeholders(view)


def save_config(view: dict):
    """Persist the config, splitting credentials into .security.yml."""
    cfg = copy.deepcopy(view)
    sec = _read_security_file()

    migrate_legacy_channels(cfg)
    cfg["version"] = max(int(cfg.get("version") or 0), CONFIG_VERSION)

    # Models
    sec_models = {}
    model_list = cfg.get("model_list") or []
    for m, key in zip(model_list, _model_keys(model_list)):
        if not isinstance(m, dict):
            continue
        keys = _clean_secret_list(m.pop("api_keys", None))
        legacy = m.pop("api_key", None)
        if not keys and _is_secret_value(legacy):
            keys = [legacy]
        sec_models[key] = {"api_keys": keys} if keys else {}
    sec["model_list"] = sec_models

    # Channels
    sec_channels = sec.pop("channel_list", None) or sec.pop("channels", None) or {}
    sec.pop("channels", None)
    if not isinstance(sec_channels, dict):
        sec_channels = {}
    for name, ch in (cfg.get("channel_list") or {}).items():
        if not isinstance(ch, dict) or not isinstance(ch.get("settings"), dict):
            continue
        settings = ch["settings"]
        entry = sec_channels.get(name) if isinstance(sec_channels.get(name), dict) else {}
        sec_settings = entry.get("settings") if isinstance(entry.get("settings"), dict) else {}
        for field in [f for f in settings if f in SECRET_FIELDS]:
            value = settings.pop(field)
            if _is_secret_value(value):
                sec_settings[field] = value
            else:
                sec_settings.pop(field, None)
        entry["settings"] = sec_settings
        sec_channels[name] = entry
    sec["channel_list"] = sec_channels

    # Web search tools
    web = (cfg.get("tools") or {}).get("web") or {}
    sec_web = sec.get("web") if isinstance(sec.get("web"), dict) else {}
    for provider, pcfg in web.items():
        if not isinstance(pcfg, dict):
            continue
        sec_entry = sec_web.get(provider) if isinstance(sec_web.get(provider), dict) else {}
        for field in ("api_key", "api_keys"):
            if field not in pcfg:
                continue
            value = pcfg.pop(field)
            if field == "api_keys":
                value = _clean_secret_list(value)
            if value and (field == "api_keys" or _is_secret_value(value)):
                sec_entry[field] = value
            else:
                sec_entry.pop(field, None)
        if sec_entry:
            sec_web[provider] = sec_entry
        else:
            sec_web.pop(provider, None)
    if sec_web:
        sec["web"] = sec_web
    else:
        sec.pop("web", None)

    _write_private(SECURITY_PATH, yaml.safe_dump(sec, sort_keys=False, allow_unicode=True))
    _write_private(CONFIG_PATH, json.dumps(cfg, indent=2))


def _fix_legacy_fields(raw: dict) -> bool:
    """Rewrite fields older template versions wrote that PicoClaw now rejects."""
    brave = ((raw.get("tools") or {}).get("web") or {}).get("brave")
    if isinstance(brave, dict) and "api_key" in brave:
        key = brave.pop("api_key")
        if _is_secret_value(key) and not _clean_secret_list(brave.get("api_keys")):
            brave["api_keys"] = [key]
        return True
    return False


def normalize_config_on_startup():
    """Repair and migrate configs left behind by older versions of this template."""
    raw = _read_config_file()
    if not raw:
        return
    version = int(raw.get("version") or 0)
    if version < CONFIG_VERSION:
        # Let PicoClaw run its own schema migration (it backs up config.json
        # and moves credentials into .security.yml). Loading the config is
        # enough to trigger it; first drop fields its migration rejects.
        print(f"Migrating config.json from v{version} to v{CONFIG_VERSION}")
        if _fix_legacy_fields(raw):
            _write_private(CONFIG_PATH, json.dumps(raw, indent=2))
        try:
            subprocess.run(["picoclaw", "status"], capture_output=True, timeout=60)
        except Exception as e:
            print(f"Warning: could not run PicoClaw config migration: {e}")
        raw = _read_config_file()
        version = int(raw.get("version") or 0)
        if version < CONFIG_VERSION:
            print(f"Warning: config.json is still v{version}; check the gateway logs for config errors.")
            return
    if "channels" in raw or _fix_legacy_fields(raw):
        print("Migrating legacy template fields in config.json")
        save_config(load_config())


def has_model_key(config: dict) -> bool:
    return any(
        isinstance(m, dict) and _clean_secret_list(m.get("api_keys"))
        for m in config.get("model_list", [])
    )


PROVIDER_CATALOG = [
    {"provider": "openai",       "display": "OpenAI",        "api_base": "https://api.openai.com/v1",                         "seed_model": "gpt-5.4"},
    {"provider": "anthropic",    "display": "Anthropic",     "api_base": "https://api.anthropic.com/v1",                      "seed_model": "claude-sonnet-4-6"},
    {"provider": "openrouter",   "display": "OpenRouter",    "api_base": "https://openrouter.ai/api/v1",                      "seed_model": "auto"},
    {"provider": "deepseek",     "display": "DeepSeek",      "api_base": "https://api.deepseek.com/v1",                       "seed_model": "deepseek-chat"},
    {"provider": "gemini",       "display": "Google Gemini", "api_base": "https://generativelanguage.googleapis.com/v1beta",  "seed_model": "gemini-2.0-flash-exp"},
    {"provider": "groq",         "display": "Groq",          "api_base": "https://api.groq.com/openai/v1",                    "seed_model": "llama-3.3-70b-versatile"},
    {"provider": "mistral",      "display": "Mistral",       "api_base": "https://api.mistral.ai/v1",                         "seed_model": "mistral-small-latest"},
    {"provider": "moonshot",     "display": "Moonshot",      "api_base": "https://api.moonshot.cn/v1",                        "seed_model": "moonshot-v1-8k"},
    {"provider": "zhipu",        "display": "Zhipu (GLM)",   "api_base": "https://open.bigmodel.cn/api/paas/v4",              "seed_model": "glm-4.7"},
    {"provider": "qwen",         "display": "Qwen",          "api_base": "https://dashscope.aliyuncs.com/compatible-mode/v1", "seed_model": "qwen-plus"},
    {"provider": "minimax",      "display": "MiniMax",       "api_base": "https://api.minimaxi.com/v1",                       "seed_model": "MiniMax-M2.5"},
    {"provider": "nvidia",       "display": "NVIDIA",        "api_base": "https://integrate.api.nvidia.com/v1",               "seed_model": "nemotron-4-340b-instruct"},
    {"provider": "cerebras",     "display": "Cerebras",      "api_base": "https://api.cerebras.ai/v1",                        "seed_model": "llama-3.3-70b"},
    {"provider": "venice",       "display": "Venice",        "api_base": "https://api.venice.ai/api/v1",                      "seed_model": "venice-uncensored"},
    {"provider": "nearai",       "display": "NEAR AI",       "api_base": "https://cloud-api.near.ai/v1",                      "seed_model": "zai-org/GLM-5.1-FP8"},
    {"provider": "avian",        "display": "Avian",         "api_base": "https://api.avian.io/v1",                           "seed_model": "deepseek/deepseek-v3.2"},
    {"provider": "vivgrid",      "display": "Vivgrid",       "api_base": "https://api.vivgrid.com/v1",                        "seed_model": "auto"},
    {"provider": "volcengine",   "display": "VolcEngine",    "api_base": "https://ark.cn-beijing.volces.com/api/v3",          "seed_model": "doubao-pro-32k"},
    {"provider": "shengsuanyun", "display": "ShengSuanYun",  "api_base": "https://api.shengsuanyun.com/v1",                   "seed_model": "deepseek-v3"},
    {"provider": "longcat",      "display": "LongCat",       "api_base": "https://api.longcat.chat/openai",                   "seed_model": "LongCat-Flash-Thinking"},
    {"provider": "modelscope",   "display": "ModelScope",    "api_base": "https://api-inference.modelscope.cn/v1",            "seed_model": "Qwen/Qwen3-235B-A22B-Instruct-2507"},
    {"provider": "azure",        "display": "Azure OpenAI",  "api_base": "https://your-resource.openai.azure.com",            "seed_model": "my-gpt5-deployment"},
    {"provider": "ollama",       "display": "Ollama",        "api_base": "http://localhost:11434/v1",                         "seed_model": "llama3"},
    {"provider": "lmstudio",     "display": "LM Studio",     "api_base": "http://localhost:1234/v1",                          "seed_model": "openai/gpt-oss-20b"},
    {"provider": "vllm",         "display": "vLLM",          "api_base": "http://localhost:8000/v1",                          "seed_model": "custom-model"},
]


def _mask_str(v):
    if not isinstance(v, str) or not v:
        return v
    return v[:8] + "***" if len(v) > 8 else "***"


def mask_secrets(data, _path=""):
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and v:
                result[k] = _mask_str(v)
            elif k in SECRET_LIST_FIELDS and isinstance(v, list):
                result[k] = [_mask_str(x) for x in v]
            else:
                result[k] = mask_secrets(v, f"{_path}.{k}")
        return result
    if isinstance(data, list):
        return [mask_secrets(item, _path) for item in data]
    return data


def _build_model_lookup(model_list):
    return {m["model_name"]: m for m in model_list if isinstance(m, dict) and "model_name" in m}


def merge_secrets(new_data, existing_data):
    if isinstance(new_data, dict) and isinstance(existing_data, dict):
        result = {}
        for k, v in new_data.items():
            if k in SECRET_FIELDS and isinstance(v, str) and (v.endswith("***") or v == ""):
                result[k] = existing_data.get(k, "")
            elif k in SECRET_LIST_FIELDS and isinstance(v, list):
                existing_list = existing_data.get(k, []) or []
                merged = []
                for i, item in enumerate(v):
                    if isinstance(item, str) and item.endswith("***") and i < len(existing_list):
                        merged.append(existing_list[i])
                    elif isinstance(item, str) and item:
                        merged.append(item)
                result[k] = merged
            elif k == "model_list" and isinstance(v, list):
                existing_lookup = _build_model_lookup(existing_data.get("model_list", []))
                merged_list = []
                for item in v:
                    if isinstance(item, dict):
                        existing_item = existing_lookup.get(item.get("model_name"), {})
                        merged_list.append(merge_secrets(item, existing_item))
                    else:
                        merged_list.append(item)
                result[k] = merged_list
            else:
                result[k] = merge_secrets(v, existing_data.get(k, {}))
        return result
    return new_data


class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self.state = "stopped"
        self.logs: deque[str] = deque(maxlen=500)
        self.start_time: float | None = None
        self.restart_count = 0
        self._read_tasks: list[asyncio.Task] = []

    async def start(self):
        if self.process and self.process.returncode is None:
            return
        self.state = "starting"
        try:
            self.process = await asyncio.create_subprocess_exec(
                "picoclaw", "gateway", "--allow-empty",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            self.state = "running"
            self.start_time = time.time()
            task = asyncio.create_task(self._read_output(self.process))
            self._read_tasks.append(task)
        except Exception as e:
            self.state = "error"
            self.logs.append(f"Failed to start gateway: {e}")

    async def stop(self):
        if not self.process or self.process.returncode is not None:
            self.state = "stopped"
            return
        self.state = "stopping"
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        self.state = "stopped"
        self.start_time = None

    async def restart(self):
        await self.stop()
        self.restart_count += 1
        await self.start()

    async def _read_output(self, proc: asyncio.subprocess.Process):
        try:
            while proc.stdout:
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                cleaned = ANSI_ESCAPE.sub("", decoded)
                self.logs.append(cleaned)
            code = await proc.wait()
        except asyncio.CancelledError:
            return
        # Only flag an unexpected exit of the current process (not a stop/restart).
        if proc is self.process and self.state == "running":
            self.state = "error"
            self.start_time = None
            self.logs.append(f"Gateway exited with code {code}")

    def get_status(self) -> dict:
        pid = None
        if self.process and self.process.returncode is None:
            pid = self.process.pid
        uptime = None
        if self.start_time and self.state == "running":
            uptime = int(time.time() - self.start_time)
        return {
            "state": self.state,
            "pid": pid,
            "uptime": uptime,
            "restart_count": self.restart_count,
        }


gateway = GatewayManager()
config_lock = asyncio.Lock()


async def homepage(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    return templates.TemplateResponse(request, "index.html", {"provider_catalog": PROVIDER_CATALOG})


async def health(request: Request):
    return JSONResponse({"status": "ok", "gateway": gateway.state})


async def api_config_get(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    config = load_config()
    return JSONResponse(mask_secrets(config))


async def api_config_put(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Invalid config"}, status_code=400)

    try:
        restart = body.pop("_restartGateway", False)

        async with config_lock:
            existing = load_config()
            merged = merge_secrets(body, existing)
            save_config(merged)

        if restart:
            asyncio.create_task(gateway.restart())

        return JSONResponse({"ok": True, "restarting": restart})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_status(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err

    config = load_config()

    models = {}
    for m in config.get("model_list", []):
        if isinstance(m, dict) and "model_name" in m:
            models[m["model_name"]] = {"configured": bool(_clean_secret_list(m.get("api_keys")))}

    channels = {}
    for name, chan in sorted((config.get("channel_list") or {}).items()):
        if isinstance(chan, dict):
            channels[name] = {"enabled": bool(chan.get("enabled", False))}

    cron_dir = CONFIG_DIR / "cron"
    cron_jobs = []
    if cron_dir.exists():
        for f in cron_dir.glob("*.json"):
            try:
                cron_jobs.append(json.loads(f.read_text()))
            except Exception:
                pass

    return JSONResponse({
        "gateway": gateway.get_status(),
        "models": models,
        "channels": channels,
        "cron": {"count": len(cron_jobs), "jobs": cron_jobs},
    })


async def api_logs(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    return JSONResponse({"lines": list(gateway.logs)})


async def api_gateway_start(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.start())
    return JSONResponse({"ok": True})


async def api_gateway_stop(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.stop())
    return JSONResponse({"ok": True})


async def api_gateway_restart(request: Request):
    auth_err = require_auth(request)
    if auth_err:
        return auth_err
    asyncio.create_task(gateway.restart())
    return JSONResponse({"ok": True})


@asynccontextmanager
async def lifespan(app):
    try:
        normalize_config_on_startup()
    except Exception as e:
        print(f"Warning: could not normalize config: {e}")
    if has_model_key(load_config()):
        asyncio.create_task(gateway.start())
    try:
        yield
    finally:
        await gateway.stop()


routes = [
    Route("/", homepage),
    Route("/health", health),
    Route("/api/config", api_config_get, methods=["GET"]),
    Route("/api/config", api_config_put, methods=["PUT"]),
    Route("/api/status", api_status),
    Route("/api/logs", api_logs),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
]

app = Starlette(
    routes=routes,
    middleware=[Middleware(AuthenticationMiddleware, backend=BasicAuthBackend())],
    lifespan=lifespan,
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
    server = uvicorn.Server(config)

    def handle_signal():
        loop.create_task(gateway.stop())
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    loop.run_until_complete(server.serve())
