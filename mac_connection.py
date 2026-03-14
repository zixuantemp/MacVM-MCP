"""SSH connection manager for macOS target."""

import json
import os
import stat
import threading
from pathlib import Path
from typing import Optional, Tuple

import paramiko


class MacConnection:
    """Manages SSH connection to a macOS machine."""

    def __init__(self, config_path: str = "config.json"):
        self._lock = threading.RLock()
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

        config_path = os.path.expanduser(config_path)
        if not os.path.exists(config_path):
            # Fall back to environment variables
            self.config = {
                "ssh": {
                    "host": os.environ.get("MAC_SSH_HOST", ""),
                    "port": int(os.environ.get("MAC_SSH_PORT", "22")),
                    "username": os.environ.get("MAC_SSH_USER", ""),
                    "password": os.environ.get("MAC_SSH_PASSWORD", ""),
                    "key_file": os.environ.get("MAC_SSH_KEY", None),
                    "timeout": 30,
                },
                "remote_work_dir": os.environ.get("MAC_REMOTE_DIR", "/tmp/macmcp"),
                "local_work_dir": os.environ.get("MAC_LOCAL_DIR", "/home/kali/Desktop/analysis"),
            }
        else:
            with open(config_path) as f:
                self.config = json.load(f)

    @property
    def remote_work_dir(self) -> str:
        return self.config["remote_work_dir"]

    @property
    def local_work_dir(self) -> str:
        return self.config["local_work_dir"]

    def _get_client(self) -> paramiko.SSHClient:
        with self._lock:
            ssh_cfg = self.config["ssh"]
            if self._client is None or not self._is_connected():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connect_kwargs = {
                    "hostname": ssh_cfg["host"],
                    "port": ssh_cfg["port"],
                    "username": ssh_cfg["username"],
                    "timeout": ssh_cfg.get("timeout", 30),
                    "banner_timeout": 30,
                }
                # Prefer SSH agent (no credentials stored anywhere)
                agent = paramiko.Agent()
                agent_keys = agent.get_keys()
                if agent_keys:
                    connect_kwargs["pkey"] = agent_keys[0]
                else:
                    # Fall back to key file (passphrase read from env MAC_SSH_KEY_PASS)
                    if ssh_cfg.get("key_file"):
                        connect_kwargs["key_filename"] = os.path.expanduser(ssh_cfg["key_file"])
                    key_pass = os.environ.get("MAC_SSH_KEY_PASS") or ssh_cfg.get("key_passphrase")
                    if key_pass:
                        connect_kwargs["passphrase"] = key_pass
                    if ssh_cfg.get("password"):
                        connect_kwargs["password"] = os.environ.get("MAC_SSH_PASSWORD") or ssh_cfg["password"]
                client.connect(**connect_kwargs)
                self._client = client
                self._sftp = None  # reset sftp on new connection
            return self._client

    def _is_connected(self) -> bool:
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    def _get_sftp(self) -> paramiko.SFTPClient:
        with self._lock:
            if self._sftp is None or not self._is_connected():
                self._get_client()  # ensure connected
                self._sftp = self._client.open_sftp()
            return self._sftp

    def run(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """Run a command via SSH. Returns (exit_code, stdout, stderr)."""
        client = self._get_client()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return exit_code, out, err

    def run_sudo(self, command: str, password: str = "", timeout: int = 60) -> Tuple[int, str, str]:
        """Run command with sudo."""
        pwd = password or self.config["ssh"].get("password", "")
        full_cmd = f"echo '{pwd}' | sudo -S {command}"
        return self.run(full_cmd, timeout=timeout)

    def upload_file(self, local_path: str, remote_path: str) -> None:
        """Upload a file to the macOS machine."""
        sftp = self._get_sftp()
        local_path = os.path.expanduser(local_path)
        # Ensure remote directory exists
        remote_dir = str(Path(remote_path).parent)
        try:
            sftp.mkdir(remote_dir)
        except IOError:
            pass  # directory exists
        sftp.put(local_path, remote_path)

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download a file from the macOS machine."""
        sftp = self._get_sftp()
        local_path = os.path.expanduser(local_path)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        sftp.get(remote_path, local_path)

    def read_remote_file(self, remote_path: str, max_bytes: int = 1_000_000) -> str:
        """Read a text file from the remote machine."""
        sftp = self._get_sftp()
        with sftp.open(remote_path, "r") as f:
            return f.read(max_bytes).decode("utf-8", errors="replace")

    def ensure_work_dir(self) -> None:
        """Ensure the remote working directory exists."""
        self.run(f"mkdir -p {self.remote_work_dir}")

    def close(self) -> None:
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None


# Singleton instance
_connection: Optional[MacConnection] = None


def get_connection(config_path: str = "config.json") -> MacConnection:
    global _connection
    if _connection is None:
        _connection = MacConnection(config_path)
    return _connection
