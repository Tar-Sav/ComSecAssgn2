<div align="center">

# 🛡️ RELEASE GUARD
### Signed Software Release Verification

**Trust the publisher. Verify the signature. Protect the release.**

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-Ed25519%20%7C%20SHA--256-6C5CE7?style=for-the-badge)
![Course](https://img.shields.io/badge/CIT4020-Computer%20Security-111827?style=for-the-badge)

*A Computer Security group project based on the fictional HarbourView Business Systems Ltd. scenario.*

</div>

---

## ✨ What is Release Guard?

**Release Guard** is a Python command-line application designed to check whether a software release is authentic and has remained unchanged since it was signed.

It brings together four security ideas:

- 🔑 **Ed25519 digital signatures** — verify the identity of the signing publisher.
- #️⃣ **SHA-256 hashing** — detect changes to release files.
- 🏢 **Trusted publisher registry** — check whether a publisher is recognized and enabled.
- 📋 **Security logging** — keep a record of signing and verification attempts.

> **Our objective:** Accept a release only when its publisher is trusted, its signature is valid, and its files pass the integrity checks.

## 🚀 At a glance

| Capability | Purpose |
|---|---|
| `setup` | Generate an Ed25519 key pair and register the publisher. |
| `sign` | Hash payload files, create a manifest, and sign it. |
| `verify` | Check publisher trust, signature validity, safe paths, and file integrity. |
| Activity log | Record signing and verification outcomes without storing secrets. |

## 🔄 How it works

```text
       ┌─────────────────────┐
       │        SETUP        │
       │ Generate key pair   │
       │ Register publisher │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │        SIGN         │
       │ Hash payload files  │
       │ Create manifest     │
       │ Sign manifest       │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │       VERIFY        │
       │ Validate manifest   │
       │ Check trusted ID    │
       │ Verify signature    │
       │ Check paths/hashes  │
       └──────────┬──────────┘
                  │
             ┌────┴────┐
             ▼         ▼
        ┌────────┐ ┌────────┐
        │ACCEPTED│ │REJECTED│
        └────────┘ └────────┘
```

A release is accepted only when every required verification step succeeds. Otherwise, it is rejected with a reason.

## 🔍 Verification checks

Release Guard is designed to perform these checks in order:

1. **Manifest validation** — confirm the manifest and signature exist and the manifest contains valid JSON and required fields.
2. **Publisher trust** — confirm the publisher exists in the trusted registry and is enabled.
3. **Signature verification** — verify the exact manifest bytes using the public key from the trusted registry.
4. **Path safety** — reject absolute paths and paths containing `..`.
5. **File integrity** — confirm listed files exist, no unexpected payload files are present, and SHA-256 hashes match.

### Possible verification outcomes

| Result | Meaning |
|---|---|
| `ACCEPTED` | All required checks passed. |
| `INVALID_MANIFEST` | The manifest is missing, unreadable, or invalid. |
| `UNKNOWN_PUBLISHER` | The publisher is not in the trusted registry. |
| `PUBLISHER_DISABLED` | The publisher exists but is disabled. |
| `BAD_SIGNATURE` | The signature could not be verified. |
| `UNSAFE_PATH` | A manifest path failed path-safety checks. |
| `MISSING_FILE` | A file listed in the manifest is missing. |
| `EXTRA_FILE` | An unexpected payload file was found. |
| `HASH_MISMATCH` | A file's current hash differs from the manifest. |

*Use the exact result names implemented in the final program.*

## 🖥️ Getting started

### 1. Requirements

- Python 3
- The `cryptography` package
- Kali Linux or Ubuntu, as required by the lab

Check your Python version:

```bash
python3 --version
```

### 2. Install dependencies

From the project directory:

```bash
python3 -m pip install -r requirements.txt
```

### 3. Run the application

The assignment requires three operations: `setup`, `sign`, and `verify`.

**Example commands — confirm the exact syntax against your completed `release_guard.py`:**

```bash
python3 release_guard.py setup
python3 release_guard.py sign <release-folder> --publisher <publisher-id>
python3 release_guard.py verify <release-folder>
```

If your team implemented different argument names or options, use the syntax supported by the final program.

## 📁 Project structure

This is a suggested layout. Update it to match the actual project:

```text
release-guard/
├── release_guard.py
├── requirements.txt
├── README.md
├── trusted_publishers.json
├── release_log.jsonl
├── keys/
│   ├── publisher_private.pem
│   └── publisher_public.pem
└── release_A/
    ├── manifest.json
    ├── signature.sig
    └── payload/
        ├── app.py
        ├── release_notes.txt
        └── config/
            └── settings.ini
```

### Sample training payload

| File | Sample content |
|---|---|
| `app.py` | `print("CIT4020 training release")` |
| `config/settings.ini` | `demo_only=true` |
| `release_notes.txt` | `HarbourView lab release 1.0` |

These are fictional training files for the lab.

## 🔐 Security principles

- **Protect private keys:** encrypt the private key and require a passphrase.
- **Keep secrets private:** never include private keys or passphrases in the source ZIP or Git repository.
- **Use the trusted registry:** do not trust a public key supplied by the release being verified.
- **Validate paths:** reject unsafe paths before accessing files.
- **Keep logs clean:** never record private keys or passphrases.
- **Do not confuse authenticity with safety:** a valid signature confirms the signing identity and integrity; it does not prove the software is harmless.

## 🧪 Testing

Run and record the required tests **T1–T10**. Mark a test as passed only after it has actually been executed and its output checked.

The demonstration should include:

- A clean release being accepted.
- A modified payload being rejected.
- An unknown publisher being rejected.
- A disabled publisher being rejected.
- The activity log recording an attempt.

Use genuine screenshots from your team's own test environment.

## 📋 Activity logging

Each signing or verification attempt should append a record to `release_log.jsonl`.

Each record should include:

- UTC timestamp
- Operation (`sign` or `verify`)
- Release folder
- Publisher ID
- Result
- Reason

**Never log private keys or passphrases.**

## 👥 Group responsibilities

Add final names and update this table if the group's task allocation changes.

| Member | Main responsibility |
|---|---|
| Member 1 | Key setup, encrypted private key, trusted publisher registry |
| Member 2 | File hashing, manifest creation, digital signing |
| Member 3 | Release verification and rejection checks |
| Member 4 | Logging, README, requirements, report coordination, demo materials |

Every member should understand and be ready to explain their actual contribution during the live demonstration.

## 📦 Submission checklist

- [ ] Python source code is included.
- [ ] `requirements.txt` lists the dependencies actually used.
- [ ] README commands match the final implementation.
- [ ] Sample release files are included.
- [ ] T1–T10 have genuine recorded outcomes.
- [ ] Report includes design, risk analysis, test evidence, reflection, and contributions.
- [ ] Screenshots show genuine test output.
- [ ] Demonstration video is 3–5 minutes long.
- [ ] Private keys, passphrases, and other secrets are excluded from the ZIP.
- [ ] AI-use declaration is complete and truthful.

## ⚠️ Academic project note

This repository is an academic lab project for CIT4020 Computer Security. The group must review, test, and understand the final implementation. Do not present placeholder commands, untested behavior, or example output as confirmed results.

---

<div align="center">

**CIT4020 • COMPUTER SECURITY**

*Verify before you trust.*

</div>
