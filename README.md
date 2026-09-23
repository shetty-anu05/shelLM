# ShelLM

## Hybrid Static + LLM-Powered Linux SSH Honeypot

ShelLM is a Linux SSH honeypot that simulates a realistic Linux terminal in a safe environment. It combines predefined static command responses with Large Language Model (LLM) generated responses to create a more flexible and realistic attacker environment.

The system uses a real SSH server implemented with Paramiko, records attacker activity, maintains session context, and provides a real-time monitoring dashboard.

ShelLM is designed for cybersecurity education, research, attacker behavior analysis, and honeypot experimentation.

---

# Features

* Hybrid static + LLM command handling
* Real SSH server using Paramiko
* Simulated Linux terminal environment
* Static responses for commonly used commands
* LLM-generated responses for unsupported or dynamic commands
* Ollama local LLM support
* Session memory for consistent simulated environment
* Simulated filesystem
* SSH login monitoring
* Account lockout mechanism
* Detailed command and activity logging
* Trace mode for monitoring static/LLM command routing
* Real-time Flask monitoring dashboard
* Windows desktop notifications
* Multiple terminal personalities
* Support for Ollama, OpenAI, and Anthropic providers

---

# How ShelLM Handles Commands

ShelLM uses two response mechanisms.

### 1. Static Command Handler

Frequently used Linux commands are handled using predefined responses.

Examples:

```text
pwd
whoami
ls
cd
uname
history
```

These commands return deterministic output without calling the LLM.

This makes common commands faster and ensures that important basic Linux behavior remains consistent between sessions.

### 2. LLM Command Handler

Commands that are not handled by the static command system are forwarded to the configured LLM.

For example:

```text
docker ps
strace ls
htop
top
nmap
netcat
python3 -c ...
```

When a command is forwarded to the LLM, ShelLM generates realistic simulated Linux terminal output.

Example trace:

```text
[TRACE] -> CMD: docker ps
[TRACE] -> Sending to LLM ollama/llama3.1:8b
[TRACE] <- LLM: CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES
```

Another example:

```text
[TRACE] -> CMD: strace ls
[TRACE] -> Sending to LLM ollama/llama3.1:8b
[TRACE] <- LLM: execve("/bin/ls", ["ls"], ...) = 0
```

The commands are simulated. They are not executed on the real host system.

---

# Architecture

```text
                    Attacker
                       │
                       │ SSH
                       ▼
              ┌─────────────────┐
              │  Paramiko SSH   │
              │     Server      │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Command Handler │
              └────────┬────────┘
                       │
              ┌────────┴─────────┐
              │                  │
              ▼                  ▼
      ┌──────────────┐    ┌──────────────┐
      │ Static       │    │ LLM Fallback │
      │ Commands     │    │              │
      └──────┬───────┘    └──────┬───────┘
             │                   │
             │                   ▼
             │            ┌──────────────┐
             │            │    Ollama    │
             │            │ llama3.1:8b  │
             │            └──────┬───────┘
             │                   │
             └─────────┬─────────┘
                       ▼
              Simulated Terminal
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Logging      Sessions    Dashboard
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/shetty-anu05/shellLM.git
cd shellLM
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create the environment file:

```powershell
copy .env_TEMPLATE .env
```

If using Ollama, install Ollama and pull the required model:

```bash
ollama pull llama3.1:8b
```

---

# Usage

## Start the SSH Honeypot

Run:

```bash
python ssh_server.py --provider ollama --model llama3.1:8b --trace
```

The server starts on port `2222`.

Example:

```text
[*] Provider   : ollama
[*] Model      : llama3.1:8b
[*] Personality: default_v1
[*] Port       : 2222
[*] Trace      : True
-------------------------------------------------------
[*] SSH Honeypot listening on 0.0.0.0:2222
```

Connect to the honeypot using:

```bash
ssh root@YOUR_IP -p 2222
```

---

# Trace Mode

Trace mode shows how ShelLM processes each command.

Example:

```text
[TRACE] -> CMD: pwd
[TRACE] <- STATIC: '/home/anvitha'
```

This indicates that `pwd` was handled by the static command system.

For an LLM command:

```text
[TRACE] -> CMD: docker ps
[TRACE] -> Sending to LLM ollama/llama3.1:8b
[TRACE] <- LLM: CONTAINER ID ...
```

This indicates that `docker ps` was forwarded to the LLM.

Trace mode therefore makes it possible to clearly identify which commands are handled statically and which commands use the LLM.

---

# Start the Dashboard

Run:

```bash
python dashboard.py
```

Open:

```text
http://localhost:5000
```

The dashboard provides real-time monitoring of honeypot activity, including attacker connections and executed commands.

---

# Local Honeypot

ShelLM can also be run using the local terminal simulation:

```bash
python LinuxSSHbot.py --provider ollama --model llama3.1:8b
```

With trace mode:

```bash
python LinuxSSHbot.py --provider ollama --model llama3.1:8b --trace
```

---

# Command-Line Options

| Option          | Description                                      |
| --------------- | ------------------------------------------------ |
| `--provider`    | LLM provider: `ollama`, `openai`, or `anthropic` |
| `--model`       | Model name, such as `llama3.1:8b`                |
| `--personality` | Select terminal personality                      |
| `--trace`       | Display command routing and LLM activity         |
| `--cleaned`     | Clear previous logs before starting              |

Example:

```bash
python ssh_server.py --provider ollama --model llama3.1:8b --personality default_v1 --trace
```

---

# Personalities

| Name         | Description                  |
| ------------ | ---------------------------- |
| `default_v1` | Ubuntu developer workstation |
| `Eman_v1`    | FinTech backend engineer     |
| `Muris_v1`   | DevOps engineer              |

Personalities control the type of simulated Linux environment and responses generated by the system.

---

# Example Commands

Common static commands:

```text
ls
ls -al
pwd
whoami
cd Desktop
history
uname -a
```

Commands suitable for LLM-based simulation:

```text
docker ps
strace ls
htop
top
nmap
netcat
python3 -c "..."
```

The exact routing depends on the command handlers implemented in the project.

---

# Logging and Monitoring

ShelLM records attacker activity for analysis.

The system can log:

* SSH connection attempts
* Login attempts
* Usernames
* Commands entered by attackers
* Static command responses
* LLM-generated responses
* Session activity
* Trace information

These logs can be used to study attacker behavior and command patterns.

---

# Project Structure

```text
shellLM/
│
├── LinuxSSHbot.py
├── ssh_server.py
├── dashboard.py
├── llm_provider.py
├── session_manager.py
├── logger.py
├── filesystem.py
├── requirements.txt
├── .env_TEMPLATE
│
├── personalities/
├── logs/
└── sessions/
```

---

# Technologies Used

* Python 3
* Paramiko
* Ollama
* Llama 3.1 8B
* Flask
* PyYAML
* python-dotenv
* win10toast-persist

---

# Security Design

ShelLM is designed as a simulation environment.

Commands entered by an attacker are not executed directly on the real host. Instead, the honeypot provides predefined or LLM-generated simulated responses.

This reduces the risk of exposing the underlying operating system while still allowing attacker behavior to be observed.

---

# Ethical Use

ShelLM is intended for educational, cybersecurity research, and authorized security testing purposes.

Only deploy the honeypot on systems that you own or have explicit permission to use.

Do not use the project to monitor or access systems without authorization.

See `EthicalConsiderations.md` for additional information.

---

# Author

**Anvitha Shetty**

B.Tech Computer Science Engineering

