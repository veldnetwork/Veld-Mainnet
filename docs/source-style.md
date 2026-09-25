# Source formatting

Use `scripts/source-style.py` to check the tracked checkout. It stages candidate
files outside the repository and accepts them only after preservation checks.
Without `--apply`, differences cause a nonzero exit status and no source writes.
With `--apply`, no candidates are written if any checked file is rejected.

## Tools

Use Python 3.11 or later, Node.js 22, Git and a Clang compiler. Install formatting
dependencies in a disposable environment, not a production node installation:

```sh
python -m pip install --only-binary=:all: clang-format==18.1.8 ruff==0.11.13 tinycss2==1.5.1 webencodings==0.5.1
npm install --ignore-scripts --no-audit --no-fund --prefix ../veld-style-node prettier@3.5.3
python tests/source_style_tests.py
python scripts/source-style.py --output ../veld-style-results --prettier ../veld-style-node/node_modules/prettier
```

The output directory must be new and outside the checkout. Add `--apply` to
write checked candidates. `--clang`, `--clang-format` and `--ruff` accept explicit
tool paths. Use a fresh output directory for each run; receipts are not overwritten.

## Preservation checks

C++ formatting retains the ordered raw token stream, including comments and
literal spellings. Directive boundaries and function-like macro adjacency are
checked separately from ordinary whitespace. Includes and using declarations are not sorted. Comments,
string literals and generated cryptographic inputs are not rewritten.

Python formatting retains the AST, type comments, literal values and ordered
comments, including the statement attachment of type-ignore suppressions.
A docstring whose value would change through indentation is restored.
JavaScript formatting retains the parsed AST and ordered comments. JSON values
and object member order are checked separately.

HTML formatting retains markup events, attribute values and every literal
segment between markup tokens. This includes layout whitespace and embedded
scripts and styles. CSS formatting retains selectors, serialized declarations,
comments and nesting; it does not normalize numeric or color values.

## Files that must remain unchanged

The checker excludes provenance-pinned PQC inputs, generated and vendored code,
frozen fixtures, resource assets, third-party licenses, bundled dependencies,
and the separately checksummed hosted-wallet package. It records these files
without changing their bytes. Other material, including Markdown, shell,
PowerShell and packaging configuration, is inventoried but not automatically
rewritten. Executable-file modes are reviewed separately from text formatting.

New files under the repository's restricted source directories may need
`git add -f` with an explicit path. Do not broaden ignore rules for operational
artifacts or credentials just to make adding a source file easier.

## Scope of the evidence

A formatter receipt is not a successful build, a protocol-equivalence proof,
or a security review. Source line locations, preprocessor context and platform
behavior still require compilation and regression tests. Preserve the original
failure-path assertions when updating tests that inspect source text. Do not
change production behavior to satisfy a formatting test.
