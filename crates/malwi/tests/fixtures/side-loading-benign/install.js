const { execFileSync } = require("node:child_process");
const path = require("node:path");

const helper = path.join(__dirname, "configure.js");
execFileSync(process.execPath, [helper], { stdio: "inherit" });
