"""Small Telegram transport. Credentials are read without executing legacy code."""
import ast
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import urllib.error
import urllib.request


@dataclass
class Credentials:
    token: str = field(repr=False)
    chat_id: int
    user_id: int

    @property
    def bot_key(self):
        return hashlib.sha256(self.token.encode()).hexdigest()

    @property
    def identity(self):
        return dict(bot_key=self.bot_key, chat_id=self.chat_id, user_id=self.user_id)


def load_credentials(policy):
    token = os.environ.get("SOC_TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("SOC_TELEGRAM_CHAT_ID")
    if (not token or not chat) and policy.get('credentials_source'):
        values = {}
        tree = ast.parse(Path(policy["credentials_source"]).read_text())
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("TOKEN", "CHAT_ID"):
                        values[target.id] = node.value.value
        token = token or values.get("TOKEN")
        chat = chat or values.get("CHAT_ID")
    if not isinstance(token, str) or not token or not chat:
        raise ValueError("Telegram credentials missing")
    chat = int(chat)
    if chat <= 0:
        raise ValueError("This version requires a private Telegram chat")
    user = int(os.environ.get("SOC_TELEGRAM_USER_ID", str(chat)))
    if user != chat:
        raise ValueError("Approver must be the owner of the configured private chat")
    return Credentials(token, chat, user)


class TelegramError(RuntimeError):
    pass


@contextmanager
def bot_lock(bot_key):
    folder = Path(tempfile.gettempdir()) / f"soc-bot-{os.getuid()}"
    folder.mkdir(mode=0o700, exist_ok=True)
    stat = folder.lstat()
    if folder.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("Bot lock directory must be private and owned by this user")
    if len(bot_key) != 64 or any(c not in "0123456789abcdef" for c in bot_key):
        raise ValueError("Invalid bot lock identity")
    with (folder / (bot_key + ".lock")).open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TelegramError("Another pipeline process already owns polling for this bot") from None
        yield


class TelegramClient:
    def __init__(self, credentials):
        self.credentials = credentials

    def call(self, method, payload=None):
        if method not in {"getMe", "getChat", "getWebhookInfo", "getUpdates", "sendMessage", "answerCallbackQuery", "editMessageText"}:
            raise ValueError("Unsupported Telegram method")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self.credentials.token}/{method}",
            data=json.dumps(payload or {}).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                raw = response.read(1048577)
            if len(raw) > 1048576:
                raise TelegramError("Telegram response too large")
            body = json.loads(raw)
            if not body.get("ok"):
                raise TelegramError(f"Telegram {method} failed")
            return body["result"]
        except urllib.error.HTTPError as exc:
            # Never expose the URL: Telegram embeds bot credentials in it.
            raise TelegramError(f"Telegram {method}: HTTP {exc.code}") from None
        except (OSError, ValueError, KeyError):
            raise TelegramError(f"Telegram {method}: transport or response error") from None

    def check(self):
        me = self.call("getMe")
        chat = self.call("getChat", {"chat_id": self.credentials.chat_id})
        webhook = self.call("getWebhookInfo")
        if chat.get("type") != "private" or chat.get("id") != self.credentials.chat_id:
            raise TelegramError("Configured destination is not the expected private chat")
        if webhook.get("url"):
            raise TelegramError("Bot has an active webhook; polling has not been started")
        return {"bot_verified": bool(me.get("is_bot")), "private_chat_verified": True,
                "webhook_active": False}
