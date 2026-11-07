const s = new Server({ name: "x" }, { capabilities: { tools: { listChanged: true } } });
s.setRequestHandler("tools/list", async () => ({}));
s.setRequestHandler("tools/call", async () => ({}));
