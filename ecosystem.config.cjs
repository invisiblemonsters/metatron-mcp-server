module.exports = {
  apps: [
    {
      name: "metatron-mcp",
      script: "index.js",
      cwd: "C:\\Users\\power\\clawd\\metatron-mcp-server",
      env: { PORT: 3402 },
      watch: false,
      max_memory_restart: "200M",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
  ],
};
