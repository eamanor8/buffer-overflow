# buffer-overflow
Used SEED Labs to bypass ASLR and craft exploits targeting vulnerable binaries in a sandboxed lab.

# Buffer Overflow Exploitation - SEED Labs

This project is a hands-on exploration of **buffer overflow vulnerabilities**, based on the SEED Labs' *Buffer Overflow Vulnerability Lab* designed by Wenliang Du. It walks through exploiting a vulnerable C program to gain unauthorized root access, bypassing modern countermeasures like StackGuard, non-executable stacks, and address space layout randomization (ASLR).

## 🔍 Overview

The goal of this lab was to:
- Understand stack memory layout and control flow manipulation
- Write shellcode and inject it via buffer overflow
- Bypass multiple security mechanisms in modern systems
- Successfully gain a root shell by exploiting a vulnerable Set-UID program

## 📁 Project Structure

```bash
.
├── stack.c                # Vulnerable program
├── exploit.c              # Exploit that generates malicious input (badfile)
├── badfile                # Payload input to exploit stack.c
├── call_shellcode.c       # Test for launching shell from injected code
├── dash_shell_test.c      # Code for testing dash shell privilege drop
├── exploit.py             # Python version of the exploit
├── Buffer_Overflow_Report.pdf # My detailed write-up documenting the exploitation steps
└── README.md              # You're here!
```

## 🧪 Lab Environment

The lab was performed in a **32-bit Ubuntu SEED VM**:
- Ubuntu 12.04 or 16.04 SEED VM
- GCC with appropriate flags:
  - `-z execstack` (allow executing code on the stack)
  - `-fno-stack-protector` (disable StackGuard)
- Address randomization disabled: `sudo sysctl -w kernel.randomize_va_space=0`
- `/bin/sh` symlink adjusted to point to `zsh` to bypass privilege drop: `sudo ln -sf /bin/zsh /bin/sh`


## 🚩 Key Tasks

### 1. Run Shellcode

- Crafted and tested a minimal shellcode that launches `/bin/sh`.
- Used `call_shellcode.c` to verify shellcode execution on the stack.

### 2. Exploit the Vulnerable Program

- Analyzed `stack.c`, which reads from `badfile` into an unbounded buffer.
- Overflowed the return address to redirect execution to the injected shellcode.

### 3. Bypass Shell Restrictions

- Used `setuid(0)` syscall in the shellcode to defeat `/bin/dash` restrictions that drop privileges.

### 4. Defeat ASLR

- Enabled address space layout randomization (ASLR).
- Applied a brute-force approach using a shell script to repeatedly run the exploit until the guessed address succeeded.

## 📄 Report

A full walkthrough with code snippets, screenshots, explanations, and lessons learned can be found in:

📘 `Buffer_Overflow_Report.pdf`

This includes:
- Vulnerability analysis
- Stack frame inspection
- Exploit development
- Countermeasure evaluation

## 📚 Credits

This lab is based on the [SEED Labs](https://seedsecuritylabs.org/) materials created by **Wenliang Du** and licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-nc-sa/4.0/).
