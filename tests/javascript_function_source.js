"use strict";
const vm = require("node:vm");

// Let the JavaScript parser distinguish braces in strings, regular expressions,
// templates and comments. Compilation never executes the inspected function.
function extractFunction(source, name) {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) throw new Error("invalid function name");
  const pattern = new RegExp("(^|\\n)[ \\t]*(?:async[ \\t]+)?function[ \\t]+" + name + "[ \\t]*\\(", "g");
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) throw new Error("expected exactly one function: " + name);
  const begin = matches[0].index + matches[0][1].length;
  for (let end = source.indexOf("}", begin); end !== -1; end = source.indexOf("}", end + 1)) {
    const candidate = source.slice(begin, end + 1);
    try { new vm.Script("(" + candidate + "\n)", {filename: name}); }
    catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      continue;
    }
    return candidate;
  }
  throw new Error("no complete function body: " + name);
}

module.exports = {extractFunction};
if (require.main === module) {
  const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
  const result = {};
  for (const name of input.names) result[name] = extractFunction(input.source, name);
  process.stdout.write(JSON.stringify(result));
}
