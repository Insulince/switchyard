// Syntax-check the dashboard script embedded in index.html.
//
// The page is a build input -- go:embed pulls it into the binary -- so a
// mistake in it breaks nothing at compile time and surfaces only when
// somebody opens a browser. This is the cheapest way to find out sooner.
//
// vm.Script compiles without executing, so nothing in the page actually runs.
const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf8");
const blocks = [...html.matchAll(/<script>([^]*?)<\/script>/g)].map((m) => m[1]);

if (blocks.length === 0) {
  console.error("no <script> block found in index.html");
  process.exit(1);
}

try {
  new vm.Script(blocks.join("\n"), { filename: "index.html" });
} catch (e) {
  console.error("index.html script failed to parse:\n" + e.message);
  process.exit(1);
}

console.log("index.html script ok (" + blocks.length + " block(s))");
