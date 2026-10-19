# Finding guidance

Every report finding carries `rule_id`, `why_flagged`, `legitimate_uses`,
`investigation`, `confidence`, execution context and a stable evidence fingerprint.
The canonical built-in guidance lives in `sherlockscan/findings.py` and is reused
across all output formats. No detector runs a target function or validates a token.

| Rule family | Trigger | Legitimate uses | Investigation |
| --- | --- | --- | --- |
| EXEC | Dynamic code evaluation/compilation | Interpreters, generated kernels | Trace input source and validation |
| SHELL | Process or shell launch | Build tools, command wrappers | Review executable, shell option and arguments |
| PICKLE | Pickle-based object/model loading | Trusted model caches | Verify artifact origin and safer alternatives |
| TORCH | Explicitly unsafe or unresolved loader options | Legacy trusted checkpoints | Check PyTorch constraint, weights_only and pickle_module |
| NUMPY | Pickle enabled or unresolved | Trusted object arrays | Verify allow_pickle and array source |
| NETWORK | Networking import/call | API clients, dataset download | Inspect destination, data and execution context |
| ENV | Environment access | Application/cloud configuration | Trace values to consumers; no exfiltration is inferred |
| IMPORT | Capability import | Ordinary developer/scientific code | Inspect actual use and input provenance |
| PTH | Startup-executing import line | Editable installs, namespace support | Inspect hook and why startup execution is needed |
| SECRET | Configured credential-pattern match | Fixtures and examples | Verify privately, rotate if real |
| ENTROPY | High-entropy literal | Hashes, assets, datasets | Inspect content and use |
| KEYWORD | Configured source/decoded pattern | Comments and examples | Review actual behavior |
| DEPENDENCY | Declared dependency violates policy | Policy drift | Review full requirement, extras and markers |
| BUILD | Custom build settings | Extensions, generated source | Inspect backend before building |

Context classification distinguishes module import, function/method, setup/build,
tests/docs and Python startup. It describes syntax-level location, not guaranteed
runtime reachability. Class bodies, decorators and default argument expressions
can execute when their enclosing scope is evaluated. Aliases and simple local
shadowing are supported; complex rebinding may not be resolved correctly.

Secret findings omit credential-bearing snippets; ordinary snippets redact quoted
literals. Decoded payloads are matched in full within their byte budget and omitted
from display. Inspect local original source privately when detailed evidence is needed.
