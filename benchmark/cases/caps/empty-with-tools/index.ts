const s = new Server({ name: "x" }, { /* @mcpbench:capability-0:start */capabilities: {}/* @mcpbench:capability-0:end */ });
s.setRequestHandler("tools/list", async () => ({}));
