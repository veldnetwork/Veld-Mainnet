#!/usr/bin/env python3
"""Check guide structure, navigation targets, and mainnet documentation markers."""

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit
import datetime
import re


ROOT = Path(__file__).resolve().parents[1] / "website" / "how-to"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class Guide(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.stack = []
        self.ids = set()
        self.links = []
        self.canonical = None
        self.h1 = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag not in VOID:
            self.stack.append(tag)
        if "id" in attrs:
            assert attrs["id"] not in self.ids, f"{self.path}: duplicate ID"
            self.ids.add(attrs["id"])
        if tag == "h1":
            self.h1 += 1
        if tag == "a":
            self.links.append(attrs.get("href", ""))
            if attrs.get("target") == "_blank":
                assert "noopener" in attrs.get("rel", ""), self.path
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical = attrs.get("href")

    def handle_endtag(self, tag):
        assert self.stack and self.stack[-1] == tag, f"{self.path}: unbalanced {tag}"
        self.stack.pop()


def main():
    version_source = (ROOT.parents[1] / "include/core/version.h").read_text(encoding="utf-8")
    version = re.search(r'CLIENT_VERSION = "([0-9.]+)"', version_source).group(1)
    guides = {}
    for path in sorted(ROOT.rglob("index.html")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"testnet|regtest|faucet|2\.9\.\d", text, re.I), path
        review = re.search(r'<time datetime="(\d{4}-\d{2}-\d{2})">', text)
        assert review and "Veld Mainnet" in text, path
        datetime.date.fromisoformat(review.group(1))
        assert "Windows " + version in text, f"{path}: review client version is outdated"
        guide = Guide(path)
        guide.feed(text)
        guide.close()
        assert not guide.stack and guide.h1 == 1, path
        route = "/how-to/" + path.parent.relative_to(ROOT).as_posix().replace(".", "")
        route = route.rstrip("/") + "/"
        assert guide.canonical == "https://veld.network" + route, path
        guides[route] = guide
    assert len(guides) == 14, "Expected library and 13 guides"
    checked = 0
    for route, guide in guides.items():
        for href in guide.links:
            target = urlsplit(urljoin("https://veld.network" + route, href))
            assert target.scheme == "https", (guide.path, href)
            if target.netloc == "veld.network" and target.path.startswith("/how-to/"):
                assert target.path in guides, (guide.path, href)
                if target.fragment:
                    assert target.fragment in guides[target.path].ids, (guide.path, href)
                checked += 1
    print(f"PASS: {len(guides)} pages, {checked} guide links/anchors, balanced HTML, mainnet markers")


if __name__ == "__main__":
    main()
