"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
let count = 0;
for (const name of ["ui_desktop.h"]) {
  const source = fs.readFileSync(path.join(__dirname, "../include/network", name), "utf8");
  for (const match of source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    if (!match[1].trim()) continue;
    // Parse only: never execute startup code or contact services.
    new vm.Script(match[1], {filename: name + ":script-" + (++count)});
  }
}
if (!count) throw new Error("no embedded scripts inspected");
console.log("PASS: parsed " + count + " embedded wallet JavaScript blocks without execution");
