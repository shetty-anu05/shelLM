"""
ssh_server.py - Real SSH Server for shelLM Honeypot
Listens on port 2222, accepts real SSH connections from network
Uses paramiko to handle SSH protocol
Includes hybrid rule-based + LLM-based prompt injection detection
"""

import os
import sys
import io
import socket
import threading
import paramiko
import argparse
import datetime

from pathlib import Path

from plyer import notification
from dotenv import load_dotenv

from session_manager import SessionManager
from llm_provider import LLMProvider
from logger import HoneypotLogger


load_dotenv()


HOST_KEY_PATH = "honeypot_host.key"


def get_or_create_host_key():

    if Path(HOST_KEY_PATH).exists():

        return paramiko.RSAKey(
            filename=HOST_KEY_PATH
        )

    key = paramiko.RSAKey.generate(
        2048
    )

    key.write_private_key_file(
        HOST_KEY_PATH
    )

    print(
        f"[*] Generated new host key -> "
        f"{HOST_KEY_PATH}"
    )

    return key


class HoneypotSSHInterface(
    paramiko.ServerInterface
):

    def __init__(self):

        self.event = threading.Event()
        self.username = None

    def check_channel_request(
        self,
        kind,
        chanid
    ):

        if kind == "session":

            return paramiko.OPEN_SUCCEEDED

        return (
            paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_auth_password(
        self,
        username,
        password
    ):

        ts = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        Path("logs").mkdir(
            exist_ok=True
        )

        with open(
            "logs/auth_attempts.log",
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                f"[{ts}] LOGIN ATTEMPT -> "
                f"user={username} "
                f"pass={password}\n"
            )

        print(
            f"[!] LOGIN ATTEMPT -> "
            f"user={username} "
            f"pass={password}"
        )

        self.username = username

        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(
        self,
        channel
    ):

        self.event.set()

        return True

    def check_channel_pty_request(
        self,
        channel,
        term,
        width,
        height,
        pixelwidth,
        pixelheight,
        modes
    ):

        return True


def send_windows_alert(
    risk,
    ip
):

    try:

        notification.notify(
            title="shelLM Security Alert",
            message=(
                f"Prompt injection detected!\n"
                f"Risk: {risk}\n"
                f"Source IP: {ip}"
            ),
            timeout=5
        )

    except Exception as e:

        print(
            f"[!] Windows notification failed: {e}"
        )


def log_prompt_injection(
    client_addr,
    username,
    risk,
    command
):

    Path("logs").mkdir(
        exist_ok=True
    )

    ts = datetime.datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(
        "logs/prompt_injections.log",
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            f"[{ts}] "
            f"IP={client_addr[0]} | "
            f"USER={username} | "
            f"RISK={risk} | "
            f"COMMAND={command}\n"
        )


def handle_client(
    client_socket,
    client_addr,
    args
):

    print(
        f"\n[+] New connection from "
        f"{client_addr[0]}:{client_addr[1]}"
    )

    transport = None

    try:

        Path("logs").mkdir(
            exist_ok=True
        )

        host_key = get_or_create_host_key()

        transport = paramiko.Transport(
            client_socket
        )

        transport.add_server_key(
            host_key
        )

        server_interface = (
            HoneypotSSHInterface()
        )

        transport.start_server(
            server=server_interface
        )

        channel = transport.accept(
            30
        )

        if channel is None:

            print(
                f"[-] No channel from "
                f"{client_addr[0]}"
            )

            return

        server_interface.event.wait(
            10
        )

        def send(msg):

            channel.send(msg)

        def readline():

            buf = ""

            while True:

                ch = channel.recv(
                    1
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                if not ch or ch == "\x03":

                    raise KeyboardInterrupt

                if ch in ("\r", "\n"):

                    send("\r\n")

                    return buf

                elif ch == "\x7f":

                    if buf:

                        buf = buf[:-1]

                        send(
                            "\b \b"
                        )

                elif ch == "\x04":

                    raise EOFError

                else:

                    buf += ch

                    send(ch)

        send(
            "Welcome to Ubuntu 22.04.3 LTS "
            "(GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        )

        send(
            " * Documentation:  "
            "https://help.ubuntu.com\r\n"
        )

        send(
            " * Management:     "
            "https://landscape.canonical.com\r\n"
        )

        send(
            " * Support:        "
            "https://ubuntu.com/pro\r\n"
        )

        send("\r\n")

        send(
            "Last login: "
            f"{datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} "
            "from 192.168.1.1\r\n"
        )

        personality_name = (
            args.personality
        )

        personality_path = (
            Path("personalities")
            / f"{personality_name}.yml"
        )

        if not personality_path.exists():

            personality_path = (
                Path("personalities")
                / "default_v1.yml"
            )

        import yaml

        with open(
            personality_path,
            encoding="utf-8"
        ) as pf:

            personality = yaml.safe_load(
                pf
            )

        session = SessionManager(
            personality=personality
        )

        provider = LLMProvider(
            provider=args.provider,
            model=args.model,
            personality=personality,
            trace=args.trace
        )

        logger = HoneypotLogger(
            session_id=session.session_id,
            trace=args.trace
        )

        ts = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        with open(
            "logs/connections.log",
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                f"[{ts}] CONNECTION from "
                f"{client_addr[0]}:{client_addr[1]} "
                f"user={server_interface.username}\n"
            )

        cwd = "/home/anvitha"

        while True:

            short = cwd.replace(
                "/home/anvitha",
                "~"
            )

            prompt = (
                f"anvitha@linux:{short}$ "
            )

            send(prompt)

            try:

                cmd = readline()

            except (
                EOFError,
                KeyboardInterrupt
            ):

                send(
                    "\r\nlogout\r\n"
                )

                break

            if not cmd.strip():

                continue

            if cmd.strip() in (
                "exit",
                "logout",
                "quit"
            ):

                send(
                    "logout\r\n"
                )

                break

            if cmd.strip() == "clear":

                send(
                    "\033[2J\033[H"
                )

                continue

            injection = (
                provider.detect_injection_with_llm(
                    cmd
                )
            )

            if injection["detected"]:

                risk = injection["risk"]

                print(
                    f"[!] PROMPT INJECTION DETECTED | "
                    f"Risk={risk} | "
                    f"IP={client_addr[0]} | "
                    f"Command={cmd}"
                )

                if injection.get("reason"):

                    print(
                        f"[!] Detection reason: "
                        f"{injection['reason']}"
                    )

                log_prompt_injection(
                    client_addr=client_addr,
                    username=server_interface.username,
                    risk=risk,
                    command=cmd
                )

                send_windows_alert(
                    risk=risk,
                    ip=client_addr[0]
                )

            response, new_cwd = provider.execute(
                command=cmd,
                cwd=cwd,
                session_history=session.get_history()
            )

            session.add_exchange(
                cmd,
                response
            )

            if new_cwd:

                cwd = new_cwd

            logger.log(
                cmd,
                response,
                cwd
            )

            response_ssh = response.replace(
                "\n",
                "\r\n"
            )

            send(
                response_ssh + "\r\n"
            )

    except Exception as e:

        print(
            f"[!] Error handling "
            f"{client_addr[0]}: {e}"
        )

        if args.trace:

            import traceback

            traceback.print_exc()

    finally:

        if transport:

            transport.close()

        client_socket.close()

        print(
            f"[-] Connection closed: "
            f"{client_addr[0]}"
        )


def start_ssh_server(args):

    Path("logs").mkdir(
        exist_ok=True
    )

    print(
        """
shelLM - Real SSH Honeypot Server
        """
    )

    print(
        f"[*] Provider   : "
        f"{args.provider}"
    )

    print(
        f"[*] Model      : "
        f"{args.model or 'auto'}"
    )

    print(
        f"[*] Personality: "
        f"{args.personality}"
    )

    print(
        f"[*] Port       : "
        f"{args.port}"
    )

    print(
        f"[*] Trace      : "
        f"{args.trace}"
    )

    print("-" * 55)

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind(
        ("0.0.0.0", args.port)
    )

    server_socket.listen(5)

    print(
        f"[*] SSH Honeypot listening on "
        f"0.0.0.0:{args.port}"
    )

    print(
        f"[*] Attackers can connect with: "
        f"ssh anvitha@YOUR_IP -p {args.port}"
    )

    print(
        "[*] Prompt injection detection: "
        "HYBRID LLM + RULE-BASED"
    )

    if args.provider == "ollama":

        print(
            f"[*] LLM injection detector: "
            f"{args.model or 'llama3.1:8b'}"
        )

    print(
        "[*] Windows security alerts: ENABLED"
    )

    print(
        "[*] Press Ctrl+C to stop\n"
    )

    try:

        while True:

            client_socket, client_addr = (
                server_socket.accept()
            )

            thread = threading.Thread(
                target=handle_client,
                args=(
                    client_socket,
                    client_addr,
                    args
                ),
                daemon=True
            )

            thread.start()

    except KeyboardInterrupt:

        print(
            "\n[*] Server stopped."
        )

    finally:

        server_socket.close()


def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "shelLM Real SSH Honeypot Server"
        )
    )

    parser.add_argument(
        "--provider",
        choices=[
            "openai",
            "ollama",
            "anthropic"
        ],
        default="ollama"
    )

    parser.add_argument(
        "--model",
        default=None
    )

    parser.add_argument(
        "--personality",
        default="default_v1"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=2222
    )

    parser.add_argument(
        "--trace",
        action="store_true"
    )

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()

    start_ssh_server(args)