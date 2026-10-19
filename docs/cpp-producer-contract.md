# Experimental C++ producer inspection

This contract applies to the opt-in `cpp-ged-origin-v2-diagnostic` and
`cpp_type_match` supported-subset proposal. Default GED, legacy `type_match`,
byte matching, Union and the existing Rust-Joern dependency pin are unchanged.
It is not official C++ admission policy or a compiler validation service.

## Language and declaration assertions

A producer can add `metadata.output_contract` to a function:

```json
{"version":"producer-language-v1", "surface":"c-like-pseudocode",
 "declarations":"partial", "dialect":"ghidra-c"}
```

`ProducerLanguageContract` validates this optional payload. `surface` is one of
`c`, `cpp`, `c-like-pseudocode`, `unknown`; `declarations` is `partial`,
`complete`, or `unknown`. Unknown versions, fields and values raise a transport
validation error rather than silently assuming a language. Legacy records
without the payload remain `unknown`. `complete` is a producer assertion, not
a certificate of valid source. The four native adapters label their current
text as C-like pseudocode with partial declarations; no tool is assumed to
produce complete C++ merely because names contain `::`.

These fields are additive metadata. The adapters do not change source strings,
variable lists, native PCs or line maps to satisfy the contract.

## Bounded defects and explicit uncertainty

The shared inspection reads the existing declaration grammar and detects only:

- Numeric literals used as qualified-name components, outside comments,
  strings and preprocessing directives.
- The explicit `[D] unsupported_Iop_…(...)` IR placeholder in executable text.
- Unambiguous repeated ordinary object/parameter bindings in one compound
  block. Only builtin/elaborated local declarations and simple formal
  declarators participate; custom-type ambiguity, prototypes, extern and type
  aliases do not establish a duplicate. Nested-block shadowing is preserved.

Inspection retains exact text SHA256, 1-based byte coordinates, the previous
binding's line, grammar error state, and the producer contract. It does not
rewrite expressions, invent declarations, rename aliases, delete effects or
use source/debug oracle information. Byte-offset coordinates avoid the
Tree-sitter 0.26 `Point.column` crash reported in
[py-tree-sitter #487](https://github.com/tree-sitter/py-tree-sitter/issues/487).

A finding yields `validity=invalid_source_output`. **No findings yields
`validity=not_established`**, including when the grammar reports no errors.
This is not a full C/C++ binding/type check, declaration completeness check,
ABI pseudocode semantics validator, or proof of CFG/execution parity.

## Consumers and denominator integrity

C++ GED inspects the same sanitized/preprocessed text handed to the CFG
frontend. A proven defect yields `invalid_producer_output` and no CFG. Parser
rejection remains `parser_failure` with either
`frontend_rejected_recognized_syntax` or `unresolved_syntax_or_dialect`; neither
means that the entire function is valid C++ or that the frontend is at fault.
A `matched` record means only CFG connection, with validity still explicit.
`source_eligible`, producer statuses and `paired` remain separate. The metric
remains paired-only diagnostic data and must not be presented as an official
rank or an improvement when an invalid producer is removed.

C++ types inspect raw recovered text after oracle eligibility has already been
established. A proven-invalid producer receives zero with
`producer_failure=invalid_producer_output`, retaining that function and every
oracle variable in the metric population. It is not an oracle abstention.
Unsupported oracle evidence remains a separate exclusion. Inspection faults,
unexpected parser exceptions and invalid transport contracts propagate as
failures instead of shrinking eligibility. The experimental type cache
version is 5; its result metadata includes the inspection evidence.

A future official policy still needs decisions on pseudocode dialects,
producer-owned declaration context, broad semantic validation and unsupported
C++ features. Do not admit every new native parse merely by updating the
Rust-Joern pin. No whitelist/blacklist of functions, addresses or sample IDs is
used by these checks.

See [C++ qualification gates](cpp-evaluation-qualification.md) for separate
source identity, instantiated/effect semantics, candidate adoption and compiler
qualification requirements.
