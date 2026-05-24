# Build Your Own SSH

A simplified Secure Shell (SSH) implementation built completely from scratch using Python sockets and cryptographic primitives.

This project demonstrates how secure remote communication systems like SSH work internally by implementing:
- TCP socket communication
- AES-GCM encrypted messaging
- RSA-based key exchange
- Public-key authentication
- Remote shell command execution

---

# Project Overview

The goal of this project was to recreate the core mechanisms of SSH without using high-level SSH libraries such as Paramiko or AsyncSSH.

The implementation uses:
- Python socket programming for networking
- AES-GCM for symmetric encryption
- RSA-2048 for secure key exchange and authentication
- Digital signatures for identity verification
- subprocess module for remote command execution

---

# Features

 Phase 1 — Raw TCP Communication
- Implemented basic client-server communication using TCP sockets
- Verified plaintext visibility using Wireshark

 Phase 2 — AES-GCM Encryption
- Added AES-GCM encryption for secure communication
- Messages are encrypted before transmission
- Verified encrypted payloads in Wireshark

 Phase 3 — RSA Key Exchange
- Implemented RSA-2048 public/private keypair
- Securely exchanged AES session key using RSA-OAEP
- Removed hardcoded AES keys

 Phase 4 — Client Authentication
- Implemented challenge-response authentication
- Added RSA digital signatures using RSA-PSS
- Verified client identity using public-key cryptography

 
 Phase 5 — Remote Shell
- Implemented encrypted remote shell
- Client can execute commands remotely on server
- Supports commands like:
  - `pwd`
  - `ls`
  - `whoami`
  - `date`



