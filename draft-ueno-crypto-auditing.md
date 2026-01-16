---
title: "Cryptographic Auditing Event Format and Probes"
abbrev: "Crypto Auditing"
category: info

docname: draft-ueno-crypto-auditing-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "SAAG"
keyword:
 - cryptography
 - auditing
 - monitoring
 - logging
 - USDT
venue:
  group: SAAG
  type: Working Group
  mail: saag@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/saag/
  github: ueno/draft-ueno-crypto-auditing
  latest: https://example.com/LATEST

author:
 -
    fullname: Daiki Ueno
    organization: Red Hat, Inc.
    email: dueno@redhat.com

normative:
  RFC7049:
  RFC8610:
  RFC8446:

informative:
  RFC9147:
  FIPS186-4:
    title: "Digital Signature Standard (DSS)"
    target: https://csrc.nist.gov/publications/detail/fips/186/4/final
    date: 2013-07
  SP800-90A:
    title: "Recommendation for Random Number Generation Using Deterministic Random Bit Generators"
    target: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
    date: 2015-06
  USDT:
    title: "User-space probes for BPF"
    target: https://lwn.net/Articles/753601/
    date: 2018-03
  CRYPTO-POLICIES:
    title: "Fedora Crypto Policies"
    target: https://gitlab.com/redhat-crypto/fedora-crypto-policies/
    date: 2024

...

--- abstract

This document specifies an event logging format and probe interface for auditing cryptographic operations performed by applications and libraries. The format is designed to capture events at multiple abstraction levels, from low-level cryptographic primitives to high-level protocol operations such as TLS handshakes. The specification includes USDT (user statically defined tracepoints) probe definitions for instrumentation, a CBOR-based logging format for efficient storage, and a registry of event keys for common cryptographic protocols including TLS and SSH.

--- middle

# Introduction

As security research advances, cryptographic algorithms and protocols that were once considered secure may become vulnerable to new attacks. System and organizational administrators need mechanisms to audit the actual usage of cryptographic operations to ensure compliance with security policies and to identify uses of deprecated or weak algorithms.

While operating systems may provide system-wide mechanisms to enforce cryptographic policies (such as {{CRYPTO-POLICIES}}), administrators may relax these policies to support legacy applications. Additionally, applications can bypass system policies or use cryptography in ways not covered by policy enforcement mechanisms.

This document specifies:

1. A USDT-based probe interface for instrumenting cryptographic libraries
2. An event logging format based on hierarchical contexts
3. A CBOR encoding for efficient storage and transmission
4. A registry of event keys for common cryptographic operations

The design goals include:

- **Multi-level abstraction**: Capture both high-level events (e.g., TLS handshake) and low-level primitives (e.g., signature verification)
- **Contextual organization**: Group related events hierarchically
- **Performance**: Minimize overhead in monitored applications
- **Privacy**: Avoid capturing sensitive cryptographic material
- **Stability**: Provide a stable interface that libraries can implement without frequent changes

## Use Cases

### Aggregated Statistics on TLS Cipher Suites

Distribution maintainers and standards bodies need data on actual cryptographic algorithm usage to make informed decisions about deprecating weak algorithms. Anonymized, aggregated statistics on TLS versions, cipher suites, key sizes, and other handshake parameters help assess the impact of tightening security defaults.

### Identifying Specific Uses of Weak Algorithms

Security researchers periodically discover new attacks on cryptographic algorithms. For example, chosen-prefix collision attacks on SHA-1 make it unsuitable for digital signatures. However, completely disabling SHA-1 is impractical since it is widely used for non-cryptographic purposes (e.g., as a fingerprint for TLS certificates).

Administrators need to identify which processes use weak algorithms in security-critical contexts (such as signature verification) so they can migrate to stronger alternatives and verify that migration is complete.

### Compliance Monitoring

Organizations may be required by law or standards to ensure their systems use only approved cryptographic algorithms. Runtime monitoring allows administrators to identify processes that use non-compliant algorithms, potentially in violation of configured policies.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# USDT Probe Interface

Programs being traced (typically cryptographic libraries) define USDT (user statically defined tracepoints) probes to notify monitoring agents of cryptographic events. This section specifies the probe interface.

## Probe Definitions

Libraries define four types of probes using the following macros:

~~~c
/* Introduce a new context CONTEXT, derived from PARENT */
#define CRYPTO_AUDITING_NEW_CONTEXT(context, parent) \
    DTRACE_PROBE2(crypto_auditing, new_context, context, parent)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is in the size of
 * machine word
 */
#define CRYPTO_AUDITING_WORD_DATA(context, key_ptr, value_ptr) \
    DTRACE_PROBE3(crypto_auditing, word_data, context, \
                  key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. Both the key and value are
 * treated as a NUL-terminated string
 */
#define CRYPTO_AUDITING_STRING_DATA(context, key_ptr, value_ptr) \
    DTRACE_PROBE3(crypto_auditing, string_data, context, \
                  key_ptr, value_ptr)

/* Assert an event with KEY and VALUE. The key is treated as a
 * NUL-terminated string, while the value is explicitly sized
 * with VALUE_SIZE
 */
#define CRYPTO_AUDITING_BLOB_DATA(context, key_ptr, \
                                   value_ptr, value_size) \
    DTRACE_PROBE4(crypto_auditing, blob_data, context, \
                  key_ptr, value_ptr, value_size)
~~~

The `context` parameter can be any object with the size of a machine word (a pointer or `long`, i.e., a 64-bit integer on 64-bit systems).

## Example Usage

The following example demonstrates how a TLS library might instrument a client handshake:

~~~c
/* Start TLS client handshake */
CRYPTO_AUDITING_NEW_CONTEXT(context, NULL);

/* Indicate that this context is about TLS client handshake */
CRYPTO_AUDITING_STRING_DATA(context, "name",
                             "tls::handshake_client");

/* Indicate that TLS 1.3 is selected */
CRYPTO_AUDITING_WORD_DATA(context, "tls::protocol_version", 0x0304);
~~~

## Protocol Semantics

The four probe types have the following semantics:

- `new_context(context, parent)`: Introduce a new context under a given parent. If `parent` is NULL or 0, the context has no parent.
- `word_data(context, key, value)`: Emit an event with a machine-word-sized value
- `string_data(context, key, value)`: Emit an event with a NUL-terminated string value
- `blob_data(context, key, value, value_size)`: Emit an event with a binary blob of specified size

## Design Rationale

### Stability

The probe interface is designed to be stable across library versions. By using generic key-value pairs rather than implementation-specific parameters, libraries can evolve their internal representations without breaking the probe interface. Only the set of emitted keys and their semantics need to be coordinated, which can be done through the event registry ({{event-registry}}).

### Performance Considerations

String keys provide flexibility but require BPF programs to access userspace memory using `bpf_probe_read_user_str`. If this overhead proves excessive in practice, future versions might define integer codepoints for common keys while maintaining backward compatibility through a mapping table.

# Event Logging Format

## Overview

The logging format is a stream of structured event entries organized hierarchically by context. Events are classified into two categories:

- **Context mapping events**: Establish parent-child relationships between contexts
- **Data events**: Represent actual cryptographic events as key-value pairs

Contexts are identified by unique 16-byte values included in all events. This allows events from multiple processes or concurrent operations to be interleaved in the log stream while remaining separable for analysis.

## Conceptual Model

The following JSON representation illustrates the conceptual structure of events for a TLS client handshake that includes digital signature verification (actual logs use a binary CBOR format):

~~~json
[
    {
        "type": "new_context",
        "context": "00..01",
        "parent": "00..00"
    },
    {
        "type": "string_data",
        "context": "00..01",
        "name": "tls::handshake_client"
    },
    {
        "type": "word_data",
        "context": "00..01",
        "tls::protocol_version": 0x0304
    },
    {
        "type": "new_context",
        "context": "00..02",
        "parent": "00..01"
    },
    {
        "type": "string_data",
        "context": "00..02",
        "name": "tls::certificate_verify"
    },
    {
        "type": "word_data",
        "context": "00..02",
        "tls::signature_algorithm": 0x0804
    },
    {
        "type": "word_data",
        "context": "00..02",
        "pk::bits": 3072
    }
]
~~~

This can be conceptually represented as a tree:

- `tls::handshake_client` (00..01)
  - `tls::protocol_version` = 0x0304
  - `tls::certificate_verify` (00..02)
    - `tls::signature_algorithm` = 0x0804
    - `pk::bits` = 3072

## Context ID Construction

For security and privacy reasons, context IDs MUST be constructed to be indistinguishable from the internal state of target programs (e.g., PID or memory address), even though such information MAY be used as input to the construction algorithm.

The RECOMMENDED construction algorithm is:

1. The monitoring agent initializes an AES encryption key at startup
2. An 8-byte context identifier and an 8-byte PID/TGID of the target program are concatenated to form a 16-byte input (one AES block)
3. The 16-byte input is encrypted using AES-ECB with the key from step 1

This approach is inspired by record number encryption in QUIC and DTLS 1.3 {{RFC9147}}. With AES-NI instruction support, this procedure requires approximately 15 CPU cycles.

Agents MAY periodically rotate the encryption key.

## Event Sequence Compression

When multiple events are emitted within a single context in a short time window, the same context ID would be written repeatedly. To reduce storage overhead, implementations MAY compress subsequent events sharing the same context ID:

~~~json
[
    {
        "context": "00..01",
        "events": [
            {
                "type": "new_context",
                "parent": "00..00"
            },
            {
                "type": "string_data",
                "name": "tls::handshake_client"
            },
            {
                "type": "word_data",
                "tls::protocol_version": 0x0304
            }
        ]
    },
    {
        "context": "00..02",
        "events": [
            {
                "type": "new_context",
                "parent": "00..01"
            },
            {
                "type": "string_data",
                "name": "tls::certificate_verify"
            },
            {
                "type": "word_data",
                "tls::signature_algorithm": 0x0804
            },
            {
                "type": "word_data",
                "pk::bits": 3072
            }
        ]
    }
]
~~~

This compression preserves the same semantics as the uncompressed form.

## CBOR Encoding

The RECOMMENDED storage format uses CBOR {{RFC7049}} (Concise Binary Object Representation). The following CDDL {{RFC8610}} (Concise Data Definition Language) specification defines the format:

~~~cddl
LogEntry = EventGroup

EventGroup = {
  context: ContextID
  start: time
  end: time
  events: [+ Event]
}

Event = NewContext / Data

ContextID = bstr .size 16

NewContext = {
  NewContext: {
    parent: ContextID
  }
}

Data = {
  Data: {
    key: tstr
    value: uint .size 8 / tstr / bstr
  }
}
~~~

The log consists of a series of `EventGroup` objects. Each group contains events that occurred within a time window from `start` to `end`. Timestamps are represented as monotonic durations from the kernel boot time. `ContextID` is the encrypted 16-byte context identifier.

# Event Key Registry {#event-registry}

## Key Naming Convention

Event keys follow one of two patterns:

- **Generic keys**: Consist of alphanumeric characters and underscores
- **Scoped keys**: Have a namespace prefix ending with "::"

In ABNF notation:

~~~abnf
name = ALPHA *(ALPHA / DIGIT / "_")
generic_key = name
scoped_key = name "::" name
~~~

Keys also determine value types. For example, `name` takes a string value, while `tls::protocol_version` takes a 16-bit unsigned integer.

## Generic Keys

| Key    | Value Type | Description                                           |
|--------|------------|-------------------------------------------------------|
| `name` | string     | The name of the current context (from table below)    |

## TLS Context Names

| Name                        | Description                                                      |
|-----------------------------|------------------------------------------------------------------|
| `tls::handshake_client`     | TLS handshake for client                                         |
| `tls::handshake_server`     | TLS handshake for server                                         |
| `tls::certificate_sign`     | Digital signature created using certificate in TLS handshake     |
| `tls::certificate_verify`   | Digital signature verified using certificate in TLS handshake    |
| `tls::key_exchange`         | Shared secret derivation in TLS handshake                        |

## TLS Event Keys

| Key                                | Value Type     | Description                                                                          |
|------------------------------------|----------------|--------------------------------------------------------------------------------------|
| `tls::protocol_version`            | uint16         | Negotiated TLS version                                                               |
| `tls::ciphersuite`                 | uint16         | Negotiated ciphersuite (IANA TLS Cipher Suite registry)                              |
| `tls::signature_algorithm`         | uint16         | Signature algorithm used (IANA TLS SignatureScheme registry)                         |
| `tls::key_exchange_algorithm`      | uint16         | Key exchange mode: ECDHE(0), DHE(1), PSK(2), ECDHE-PSK(3), DHE-PSK(4)               |
| `tls::group`                       | uint16         | Groups used in handshake (IANA TLS Supported Groups registry)                        |
| `tls::ext::extended_master_secret` | uint16         | Present when extended_master_secret extension is negotiated (value ignored)          |

## SSH Context Names

| Name                     | Description                            |
|--------------------------|----------------------------------------|
| `ssh::handshake_client`  | SSH handshake for client               |
| `ssh::handshake_server`  | SSH handshake for server               |
| `ssh::client_key`        | SSH client key signature/verification  |
| `ssh::server_key`        | SSH server key signature/verification  |
| `ssh::key_exchange`      | SSH key exchange                       |

## SSH Event Keys

All keys except `ssh::rsa_bits` have `string` type. Server and client values are distinguished by context.

| Key                             | Value Type | Description                                      | Example                    |
|---------------------------------|------------|--------------------------------------------------|----------------------------|
| `ssh::ident_string`             | string     | Software identification string                   | `SSH-2.0-OpenSSH_8.8`      |
| `ssh::peer_ident_string`        | string     | Peer software identification string              | `SSH-2.0-OpenSSH_8.8`      |
| `ssh::key_algorithm`            | string     | Key used in handshake/key ownership proof        | `ssh-ed25519`              |
| `ssh::rsa_bits`                 | uint16     | Key bits (RSA only)                              | 2048                       |
| `ssh::cert_signature_algorithm` | string     | If cert is used, signature algorithm of cert     | `ecdsa-sha2-nistp521`      |
| `ssh::kex_algorithm`            | string     | Negotiated key exchange algorithm                | `curve25519-sha256`        |
| `ssh::kex_group`                | string     | Group used for key exchange                      | moduli+bits or group name  |
| `ssh::c2s_cipher`               | string     | Client-to-server cipher algorithm                | `aes256-gcm@openssh.com`   |
| `ssh::s2c_cipher`               | string     | Server-to-client cipher algorithm                | `aes256-gcm@openssh.com`   |
| `ssh::c2s_mac`                  | string     | Client-to-server MAC (omitted for implicit)      | `umac-128-etm@openssh.com` |
| `ssh::s2c_mac`                  | string     | Server-to-client MAC (omitted for implicit)      | `umac-128-etm@openssh.com` |
| `ssh::c2s_compression`          | string     | Client-to-server compression (omitted for none)  | `zlib@openssh.com`         |
| `ssh::s2c_compression`          | string     | Server-to-client compression (omitted for none)  | `zlib@openssh.com`         |

### Example SSH Context Tree

~~~
- ssh::handshake_client
  - ssh::ident_string = SSH-2.0-OpenSSH_8.8
  - ssh::peer_ident_string = SSH-2.0-OpenSSH_8.8
  - ssh::key_exchange
    - ssh::kex_algorithm = curve25519-sha256
    - ssh::key_algorithm = ssh-ed25519
    - ssh::s2c_cipher = aes256-gcm@openssh.com
    - ssh::c2s_cipher = aes256-gcm@openssh.com
  - ssh::server_key
    - ssh::key_algorithm = ssh-ed25519
  - ssh::client_key
    - ssh::key_algorithm = ssh-ed25519
~~~

## Generic Public Key Cryptography Context Names

These contexts are used when a public key operation cannot be determined from the outer context. If the operation is obvious from the parent context (e.g., `tls::certificate_verify` implies verification), implementations MAY omit creating a new context.

| Name              | Description                     |
|-------------------|---------------------------------|
| `pk::sign`        | Digital signature created       |
| `pk::verify`      | Digital signature verified      |
| `pk::encrypt`     | Encryption performed            |
| `pk::decrypt`     | Decryption performed            |
| `pk::encapsulate` | Session key encapsulated        |
| `pk::decapsulate` | Session key decapsulated        |
| `pk::generate`    | Private key generated           |
| `pk::derive`      | Shared secret derived           |

## Generic Public Key Cryptography Event Keys

These keys can be attached to any context. They are useful when algorithm parameters cannot be determined from the outer context. If parameters are obvious from the parent context (e.g., `tls::signature_algorithm` is present), implementations MAY omit these events.

All keys except `pk::bits` and `pk::static` have `string` type. String values can be arbitrary; it is the responsibility of data consumers to correlate them.

| Key             | Value Type     | Description                                                                                      |
|-----------------|----------------|--------------------------------------------------------------------------------------------------|
| `pk::algorithm` | string         | Algorithm name                                                                                   |
| `pk::curve`     | string         | Elliptic curve name                                                                              |
| `pk::group`     | string         | FFDH group name                                                                                  |
| `pk::bits`      | uint16         | Key strength in bits                                                                             |
| `pk::hash`      | string         | Hash algorithm (for prehashed/parametrized schemes: ECDSA, RSA-PSS, RSA-OAEP)                    |
| `pk::static`    | uint16         | Present when `pk::derive` uses reused keys (value ignored)                                       |

# Security Considerations

## Privacy Protection

The logging format is designed to avoid capturing sensitive cryptographic material such as private keys, session keys, or plaintext data. Only algorithm identifiers, key sizes, and protocol parameters are logged.

However, implementations MUST ensure that:

1. Context IDs cannot be correlated with internal program state (PIDs, memory addresses) by external observers
2. Timestamps and event sequences do not leak sensitive information about user behavior
3. Aggregated statistics are properly anonymized before collection

## Context ID Security

The AES-ECB encryption of context IDs prevents external observers from:

- Determining the PID or TGID of monitored processes
- Correlating events across different monitoring sessions (if keys are rotated)
- Predicting future context IDs

Agents SHOULD rotate encryption keys periodically and SHOULD use cryptographically secure random number generators to create initial keys.

## Trust Model

The architecture assumes that monitored libraries and the monitoring agent are trustworthy. Malicious libraries could:

- Emit false events
- Omit security-relevant events
- Emit events designed to fingerprint or track users

Deployments requiring strong integrity guarantees SHOULD use additional mechanisms such as:

- SELinux or AppArmor policies restricting which processes can emit events
- Integrity measurement architecture (IMA) to verify monitored binaries
- Cryptographic signatures on log files

## Denial of Service

Malicious applications could attempt to overwhelm the monitoring agent by generating excessive probe events. Implementations SHOULD implement rate limiting and resource quotas to prevent denial of service.

# IANA Considerations

## Event Key Registry

IANA is requested to create a new registry titled "Cryptographic Auditing Event Keys" under a new "Cryptographic Auditing" category.

The registry should track:

- Key name (e.g., `tls::protocol_version`)
- Value type (uint16, uint32, string, bstr)
- Description
- Reference

Initial entries are defined in {{event-registry}}.

Registration policy: Specification Required (RFC 8126)

## CBOR Tags

This document does not define new CBOR tags. Future extensions MAY request CBOR tag allocations if specialized encoding is needed for specific event types.

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the cryptographic library maintainers who provided feedback on the probe interface design, including developers from GnuTLS, OpenSSL, and OpenSSH projects.

The context-based event organization was inspired by distributed tracing systems used in microservices architectures and by the contextual logging proposal (KEP-3077) for Kubernetes.

# Examples
{:numbered="false"}

## Complete TLS 1.3 Handshake Example

The following shows a complete event log for a TLS 1.3 client handshake with ECDHE key exchange and RSA-PSS signature verification:

~~~json
[
    {
        "context": "a1b2c3d4e5f6...",
        "start": 1234567890,
        "end": 1234567895,
        "events": [
            {
                "type": "new_context",
                "parent": "000000000000..."
            },
            {
                "type": "string_data",
                "name": "tls::handshake_client"
            },
            {
                "type": "word_data",
                "tls::protocol_version": 0x0304
            },
            {
                "type": "word_data",
                "tls::ciphersuite": 0x1301
            }
        ]
    },
    {
        "context": "f6e5d4c3b2a1...",
        "start": 1234567891,
        "end": 1234567893,
        "events": [
            {
                "type": "new_context",
                "parent": "a1b2c3d4e5f6..."
            },
            {
                "type": "string_data",
                "name": "tls::key_exchange"
            },
            {
                "type": "word_data",
                "tls::group": 0x001d
            }
        ]
    },
    {
        "context": "123456789abc...",
        "start": 1234567892,
        "end": 1234567894,
        "events": [
            {
                "type": "new_context",
                "parent": "a1b2c3d4e5f6..."
            },
            {
                "type": "string_data",
                "name": "tls::certificate_verify"
            },
            {
                "type": "word_data",
                "tls::signature_algorithm": 0x0804
            },
            {
                "type": "word_data",
                "pk::bits": 3072
            }
        ]
    }
]
~~~

