# Security

## Reporting

Open a normal issue for anything that is not itself exploitable when read. For a finding that makes `mcp-audit` report a false all-clear, a missed critical or a crash on hostile input, say so in the title.

Please include the smallest source file that reproduces it, the command you ran, and the output you got. It only reads files, so a self-contained snippet is usually enough — a whole repository rarely is.

## Scope

In scope: wrong verdicts (a clean grade over something dangerous, a critical over something safe), parser crashes, and anything that lets an audited tree influence the report or the harness beyond its own findings — benchmark corpus trust, path handling, output encoding.

Out of scope: the scanner does not sandbox or execute the code it reads, so a real vulnerability in an audited server is not a bug here unless this tool claims the server is clean.

## Credentials

`mcp-audit` flags credentials found in source, but it does not know whether they leaked. A token is only exposed if it was committed, pasted into a thread, or printed into a log — so treat it as compromised from that moment and rotate it, whatever the file now says.

Pasting a token into a chat also means the transcript holds it. Revoking the token at the issuer is the only step that actually closes it; editing the file afterwards is not enough.
