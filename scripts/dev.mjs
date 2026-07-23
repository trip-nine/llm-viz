import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
let hostname = 'localhost';
let port = '3002';
const passthrough = [];

for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--host' || arg === '--hostname' || arg === '-H') {
        hostname = args[index + 1] ?? hostname;
        index += 1;
    } else if (arg.startsWith('--host=')) {
        hostname = arg.slice(arg.indexOf('=') + 1);
    } else if (arg.startsWith('--hostname=')) {
        hostname = arg.slice(arg.indexOf('=') + 1);
    } else if (arg === '--port' || arg === '-p') {
        port = args[index + 1] ?? port;
        index += 1;
    } else if (arg.startsWith('--port=')) {
        port = arg.slice(arg.indexOf('=') + 1);
    } else if (arg !== '--strictPort') {
        passthrough.push(arg);
    }
}

const nextBin = fileURLToPath(new URL('../node_modules/next/dist/bin/next', import.meta.url));
const child = spawn(process.execPath, [nextBin, 'dev', '--hostname', hostname, '--port', port, ...passthrough], {
    stdio: 'inherit',
    env: process.env,
});

for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => child.kill(signal));
}

child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code ?? 1);
});
