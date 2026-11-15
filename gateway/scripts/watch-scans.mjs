// Small CLI client to watch real-time scan updates over WebSockets.
// Usage: npm run watch:scans -- <accessToken>
import { io } from 'socket.io-client';

const token = process.argv[2] || process.env.ACCESS_TOKEN;
const url = process.env.GATEWAY_URL || 'http://localhost:4000';

if (!token) {
  console.error('Usage: npm run watch:scans -- <accessToken>');
  process.exit(1);
}

const socket = io(url, { auth: { token } });

socket.on('connect', () => console.log(`Connected to ${url}. Waiting for scan updates... (Ctrl+C to quit)`));

socket.on('scan:update', (scan) => {
  const time = new Date().toLocaleTimeString();
  let line = `[${time}] ${scan.id}  ${scan.type.padEnd(5)}  ${scan.status.toUpperCase()}`;
  if (scan.status === 'done') line += `  ->  ${scan.verdict} (${scan.riskScore}/100)`;
  if (scan.error) line += `  (${scan.error})`;
  console.log(line);
  if (scan.status === 'done' && scan.explanation) console.log(`    ${scan.explanation}\n`);
});

socket.on('connect_error', (err) => {
  console.error('Connection failed:', err.message);
  process.exit(1);
});
