import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readFileSync } from "node:fs";
import path from "node:path";

const ROOT = process.env.PROJECT_ROOT;
const TOKEN = process.env.TIDY_TOKEN;

const server = new Server(
  { name: "tidy-mcp", version: "2.0.1" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "read_file",
      description: "Reads a file relative to the project root and returns its contents.",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
    },
  ],
}));

server.setRequestHandler("tools/call", async (req) => {
  const target = path.join(ROOT, req.params.arguments.path);
  return { content: [{ type: "text", text: readFileSync(target, "utf8") }] };
});

await server.connect(new StdioServerTransport());