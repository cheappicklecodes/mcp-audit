const s = new Server({ name: "x" }, { capabilities: {} });
s.setRequestHandler("tools/list", async () => ({}));
