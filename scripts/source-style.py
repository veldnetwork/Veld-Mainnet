#!/usr/bin/env python3
"""Check or format tracked source without changing parsed program content.

Pinned tools: clang-format 18.1.8, Ruff 0.11.13, Prettier 3.5.3,
and tinycss2 1.5.1. A separate Clang compiler supplies the raw C++ lexer.
Artifacts go outside the checkout. This is not a build or security audit.
"""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import csv
import fnmatch
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import subprocess
import tokenize

import tinycss2

ROOT = Path(__file__).resolve().parents[1]
CPP = {".c", ".cc", ".cpp", ".h", ".hpp"}
WEB = {".js", ".cjs", ".json", ".html"}
RAW_TOKEN = re.compile(r"^([a-zA-Z_]\w*) '(.*?)'\t.*?Loc=<([^\n]*?)>\n", re.M | re.S)
VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
DECLARATION_AT_RULES = {
    "font-face",
    "page",
    "counter-style",
    "property",
    "font-palette-values",
    "view-transition",
}


def command(args, *, data=None, cwd=ROOT):
    result = subprocess.run(args, input=data, cwd=cwd, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-4000:])
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def protected_paths():
    with (ROOT / "vendor/pqc/provenance/PQC_PROVENANCE.tsv").open() as stream:
        pinned = {row["path"] for row in csv.DictReader(stream, delimiter="\t")}
    manifest = ROOT / "website/hosted-wallet/asset-sha256.json"
    assets = json.loads(manifest.read_text())
    # The hosted package manifest authenticates assets independently of Git.
    pinned.add(str(manifest.relative_to(ROOT)))
    for name in assets:
        pinned.add("website/hosted-wallet/" + name)
    patterns = [
        line.strip()
        for line in (ROOT / ".clang-format-ignore").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return pinned, patterns


def exclusion(name, pinned, patterns):
    if name in pinned:
        return "authenticated or provenance-pinned input"
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
        return "vendored or generated formatter exclusion"
    if name.startswith(("vendor/", "third_party_licenses/", "resources/", "swap/jsdeps/")):
        return "third-party, generated or resource asset"
    if "fixtures" in Path(name).parts:
        return "frozen fixture"
    return ""


def cpp_tokens(path, compiler):
    output = command(
        [
            compiler,
            "-x",
            "c++",
            "-std=c++20",
            "-fsyntax-only",
            "-Xclang",
            "-dump-raw-tokens",
            str(path),
        ]
    ).stderr.decode()
    tokens, end = [], 0
    for match in RAW_TOKEN.finditer(output):
        if match.start() != end:
            raise ValueError("unparsed Clang raw-token output")
        end = match.end()
        kind, value, _ = match.groups()
        if kind == "unknown" and value.isspace():
            continue
        if kind == "unknown":
            raise ValueError("unrecognized non-whitespace C++ token")
        tokens.append((kind, value))
    if end != len(output):
        raise ValueError("unparsed Clang raw-token trailer")
    return tokens


def python_tree(data):
    tree = ast.parse(data, type_comments=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.TypeIgnore):
            node.lineno = 0
    return tree


def offsets(data):
    result = [0]
    for line in data.splitlines(keepends=True):
        result.append(result[-1] + len(line))
    return result


def python_format(before, name, ruff):
    after = command(
        [
            ruff,
            "format",
            "--isolated",
            "--line-length",
            "100",
            "--config",
            'format.quote-style="preserve"',
            "--stdin-filename",
            name,
            "-",
        ],
        data=before,
    ).stdout
    original, formatted = python_tree(before), python_tree(after)
    old_offsets, new_offsets = offsets(before), offsets(after)
    repairs = []
    # A formatter may reindent docstrings. Restore their literal values too.
    for left, right in zip(ast.walk(original), ast.walk(formatted)):
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            if left.value == right.value:
                continue
            if not isinstance(left.value, str) or not isinstance(right.value, str):
                raise ValueError("Python constant changed")
            literal = before[
                old_offsets[left.lineno - 1] + left.col_offset : old_offsets[left.end_lineno - 1]
                + left.end_col_offset
            ]
            repairs.append(
                (
                    new_offsets[right.lineno - 1] + right.col_offset,
                    new_offsets[right.end_lineno - 1] + right.end_col_offset,
                    literal,
                )
            )
    for start, end, literal in sorted(repairs, reverse=True):
        after = after[:start] + literal + after[end:]
    if ast.dump(original) != ast.dump(python_tree(after)):
        raise ValueError("Python AST or type comment changed")

    def comments(data):
        return [
            token.string
            for token in tokenize.tokenize(io.BytesIO(data).readline)
            if token.type == tokenize.COMMENT
        ]

    if comments(before) != comments(after):
        raise ValueError("Python comment sequence changed")
    return after


class Markup(HTMLParser):
    """Locate markup tokens so every intervening literal byte can be retained."""

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text, self.events, self.spans = text, [], []
        self.offsets = offsets(text)
        self.feed(text)
        self.close()

    def mark(self, event, length=None, ending=None):
        line, column = self.getpos()
        start = self.offsets[line - 1] + column
        end = start + length if length is not None else self.text.index(ending, start) + len(ending)
        self.events.append(event)
        self.spans.append((start, end))

    def handle_starttag(self, tag, attrs):
        self.mark(("start", tag, tuple(attrs)), len(self.get_starttag_text()))

    def handle_startendtag(self, tag, attrs):
        self.mark(
            ("start" if tag in VOID_TAGS else "empty", tag, tuple(attrs)),
            len(self.get_starttag_text()),
        )

    def handle_endtag(self, tag):
        self.mark(("end", tag), ending=">")

    def handle_comment(self, data):
        self.mark(("comment", data), ending="-->")

    def handle_decl(self, data):
        self.mark(("decl", data.lower()), ending=">")

    def reference(self, prefix, name, kind):
        line, column = self.getpos()
        start = self.offsets[line - 1] + column
        length = len(prefix) + len(name)
        if self.text[start + length :].startswith(";"):
            length += 1
        self.mark((kind, name), length)

    def handle_entityref(self, name):
        self.reference("&", name, "entity")

    def handle_charref(self, name):
        self.reference("&#", name, "charref")

    def handle_pi(self, data):
        self.mark(("pi", data), ending=">")

    def unknown_decl(self, data):
        raise ValueError("unsupported HTML declaration")

    def gaps(self):
        previous, result = 0, []
        for start, end in self.spans:
            if start < previous:
                raise ValueError("overlapping HTML spans")
            result.append(self.text[previous:start])
            previous = end
        result.append(self.text[previous:])
        return result


def html_format(before, after):
    original, formatted = Markup(before), Markup(after)
    if original.events != formatted.events:
        raise ValueError("HTML markup events or attributes changed")
    gaps, pieces = original.gaps(), []
    for index, (gap, (start, end)) in enumerate(zip(gaps, formatted.spans)):
        token = after[start:end]
        old_start, old_end = original.spans[index]
        old_token = before[old_start:old_end]
        # Keep void-element spelling as well as HTML parser semantics.
        if token.endswith("/>") and not old_token.endswith("/>"):
            token = token[:-2].rstrip() + ">"
        pieces.extend((gap, token))
    pieces.append(gaps[-1])
    result = "".join(pieces)
    checked = Markup(result)
    if original.events != checked.events or original.gaps() != checked.gaps():
        raise ValueError("HTML literal content changed")
    return result


def css_tree(nodes, indent=0):
    rendered, canonical = [], []
    prefix = " " * indent
    for node in nodes:
        if node.type == "whitespace":
            continue
        if node.type == "error":
            raise ValueError("CSS parse error: " + node.message)
        if node.type in {"comment", "declaration"}:
            value = node.serialize()
            rendered.append(prefix + value + (";" if node.type == "declaration" else ""))
            canonical.append((node.type, value))
        elif node.type == "qualified-rule":
            selector = tinycss2.serialize(node.prelude).strip()
            child, key = css_tree(
                tinycss2.parse_declaration_list(node.content, skip_whitespace=True), indent + 4
            )
            rendered.append(prefix + selector + " {\n" + child + "\n" + prefix + "}")
            canonical.append(("rule", selector, key))
        elif node.type == "at-rule":
            prelude = tinycss2.serialize(node.prelude).strip()
            heading = "@" + node.at_keyword + (" " + prelude if prelude else "")
            if node.content is None:
                rendered.append(prefix + heading + ";")
                canonical.append(("at", node.at_keyword, prelude, None))
                continue
            parser = (
                tinycss2.parse_declaration_list
                if node.lower_at_keyword in DECLARATION_AT_RULES
                else tinycss2.parse_rule_list
            )
            child, key = css_tree(parser(node.content, skip_whitespace=True), indent + 4)
            rendered.append(prefix + heading + " {\n" + child + "\n" + prefix + "}")
            canonical.append(("at", node.at_keyword, prelude, key))
        else:
            raise ValueError("unsupported CSS node: " + node.type)
    return "\n".join(rendered), canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="write only preservation-checked candidates"
    )
    parser.add_argument(
        "--output", required=True, type=Path, help="new evidence directory outside checkout"
    )
    parser.add_argument("--clang", default="clang++")
    parser.add_argument("--clang-format", default="clang-format")
    parser.add_argument("--ruff", default="ruff")
    parser.add_argument(
        "--prettier", required=True, type=Path, help="directory containing Prettier 3.5.3"
    )
    parser.add_argument("--jobs", type=int, default=2, choices=range(1, 9))
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("evidence must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=False)
    versions = {}
    for name, executable, expected in (
        ("clang-format", args.clang_format, "18.1.8"),
        ("ruff", args.ruff, "0.11.13"),
    ):
        version = command([executable, "--version"]).stdout.decode().strip()
        if expected not in version:
            parser.error(name + " must be version " + expected)
        versions[name] = version
    versions["clang"] = command([args.clang, "--version"]).stdout.decode().splitlines()[0]
    if tinycss2.__version__ != "1.5.1":
        parser.error("tinycss2 must be version 1.5.1")
    versions["tinycss2"] = tinycss2.__version__
    prettier = args.prettier.resolve()
    if json.loads((prettier / "package.json").read_text())["version"] != "3.5.3":
        parser.error("Prettier must be version 3.5.3")
    versions["prettier"] = "3.5.3"
    names = command(["git", "ls-files", "-z"]).stdout.decode().split("\0")[:-1]
    pinned, patterns = protected_paths()
    stage = output / "candidates"
    stage.mkdir()
    web_names = [
        name for name in names if Path(name).suffix in WEB and not exclusion(name, pinned, patterns)
    ]
    manifest = output / "web-inputs.json"
    manifest.write_text(json.dumps(web_names))
    command(
        [
            "node",
            str(ROOT / "scripts/source-style-web.cjs"),
            str(ROOT),
            str(stage),
            str(prettier),
            str(manifest),
        ]
    )

    def process(name):
        path = ROOT / name
        if path.is_symlink():
            return {"path": name, "status": "retained", "reason": "symbolic link"}
        before = path.read_bytes()
        result = {"path": name, "before_sha256": sha(before), "bytes": len(before)}
        reason = exclusion(name, pinned, patterns)
        if reason:
            return {**result, "status": "protected", "reason": reason, "after_sha256": sha(before)}
        suffix = path.suffix
        dest = stage / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if suffix in CPP:
                after = command(
                    [args.clang_format, "--style=file", "--assume-filename=" + str(path)],
                    data=before,
                ).stdout
                dest.write_bytes(after)
                original = cpp_tokens(path, args.clang)
                if original != cpp_tokens(dest, args.clang):
                    raise ValueError("C++ raw tokens or comments changed")
                result.update(gate="C++ raw tokens including comments", count=len(original))
            elif suffix == ".py":
                after = python_format(before, name, args.ruff)
                result["gate"] = "Python AST, type comments, literal values and comment sequence"
            elif suffix in WEB:
                after = dest.read_bytes()
                if suffix == ".html":
                    after = html_format(before.decode(), after.decode()).encode()
                    result["gate"] = "HTML markup events and every inter-markup literal byte"
                elif suffix == ".json":
                    if json.loads(before, object_pairs_hook=list) != json.loads(
                        after, object_pairs_hook=list
                    ):
                        raise ValueError("JSON values or member ordering changed")
                    result["gate"] = "JSON values and member order"
                else:
                    result["gate"] = "JavaScript AST and ordered comments"
            elif suffix == ".css":
                formatted, key = css_tree(
                    tinycss2.parse_stylesheet(before.decode(), skip_whitespace=True)
                )
                after = (formatted + "\n").encode()
                if (
                    key
                    != css_tree(tinycss2.parse_stylesheet(after.decode(), skip_whitespace=True))[1]
                ):
                    raise ValueError("CSS selector, declaration, comment or nesting changed")
                result["gate"] = "CSS selectors, declaration serialization, comments and nesting"
            else:
                return {
                    **result,
                    "status": "retained",
                    "reason": "non-formatter material; no byte edits",
                    "after_sha256": sha(before),
                }
            dest.write_bytes(after)
            result.update(
                status="formatted" if before != after else "unchanged", after_sha256=sha(after)
            )
            return result
        except Exception as error:
            return {**result, "status": "rejected", "reason": str(error)}

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(process, names))
    failures = [row for row in results if row["status"] == "rejected"]
    changed = [row for row in results if row["status"] == "formatted"]
    if args.apply and not failures:
        for row in changed:
            (ROOT / row["path"]).write_bytes((stage / row["path"]).read_bytes())
    receipt = {
        "source_commit": command(["git", "rev-parse", "HEAD"]).stdout.decode().strip(),
        "versions": versions,
        "applied": args.apply and not failures,
        "files": results,
    }
    (output / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"{len(names)} tracked files; {len(changed)} formatting changes; {len(failures)} rejected"
    )
    for row in failures:
        print(row["path"] + ": " + row["reason"])
    return int(bool(failures or (changed and not args.apply)))


if __name__ == "__main__":
    raise SystemExit(main())
