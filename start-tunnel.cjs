const { execSync } = require('child_process');
const { spawn } = require('child_process');

const cfPath = require('path').join(process.env.USERPROFILE || '', 'AppData', 'Roaming', 'npm', 'cloudflared.cmd');
const child = spawn(cfPath, ['tunnel', '--url', 'http://localhost:3402'], {
  shell: true,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe']
});

child.stdout.on('data', d => process.stdout.write(d));
child.stderr.on('data', d => {
  const line = d.toString();
  process.stderr.write(d);
  // Extract and log the tunnel URL
  const match = line.match(/https:\/\/[^\s]+\.trycloudflare\.com/);
  if (match) {
    require('fs').writeFileSync(
      require('path').join(__dirname, 'tunnel-url.txt'),
      match[0]
    );
    console.log('\nTUNNEL URL:', match[0]);
  }
});

child.on('exit', (code) => {
  console.log('Tunnel exited with code', code);
  process.exit(code);
});
