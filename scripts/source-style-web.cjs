'use strict';

// Parse JavaScript before accepting layout changes. HTML's stricter literal
// preservation check and JSON value checks run in source-style.py.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const [root, stage, packagePath, manifest] = process.argv.slice(2);
if (!root || !stage || !packagePath || !manifest) {
    throw new Error('expected source root, candidate directory, Prettier directory and manifest');
}
const prettier = require(packagePath);
const babel = require(path.join(packagePath, 'plugins/babel.js'));
const locations = new Set([
    'start',
    'end',
    'loc',
    'range',
    'extra',
    'leadingComments',
    'trailingComments',
    'innerComments',
    'comments',
    'tokens',
]);

function structural(node) {
    if (Array.isArray(node)) return node.map(structural);
    if (node === null || typeof node !== 'object') return node;
    return Object.fromEntries(
        Object.entries(node)
            .filter(([key]) => !locations.has(key))
            .map(([key, value]) => [key, structural(value)]),
    );
}

async function main() {
    for (const name of JSON.parse(fs.readFileSync(manifest, 'utf8'))) {
        if (path.isAbsolute(name) || name.split('/').includes('..')) {
            throw new Error('unsafe source path');
        }
        const before = fs.readFileSync(path.join(root, name), 'utf8');
        const extension = path.extname(name);
        const parser = { '.js': 'babel', '.cjs': 'babel', '.json': 'json', '.html': 'html' }[
            extension
        ];
        const after = await prettier.format(before, {
            parser,
            printWidth: 100,
            tabWidth: extension === '.json' ? 2 : 4,
            useTabs: false,
            singleQuote: true,
            semi: true,
            trailingComma: 'all',
            endOfLine: 'lf',
            htmlWhitespaceSensitivity: 'strict',
            embeddedLanguageFormatting: 'off',
        });
        if (parser === 'babel') {
            const original = babel.parsers.babel.parse(before);
            const formatted = babel.parsers.babel.parse(after);
            assert.deepStrictEqual(structural(original), structural(formatted), name);
            assert.deepStrictEqual(
                original.comments.map(({ type, value }) => [type, value]),
                formatted.comments.map(({ type, value }) => [type, value]),
                name,
            );
        }
        const destination = path.join(stage, name);
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.writeFileSync(destination, after);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
