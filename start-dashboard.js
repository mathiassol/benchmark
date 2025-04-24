const { spawn } = require('child_process');
const open = require('open');
const path = require('path');

console.log('Starting WASD Game Admin Dashboard...');


const managerPath = path.join(__dirname, 'server-manager.js');


const managerProcess = spawn('node', [managerPath], {
    stdio: 'inherit'
});

managerProcess.on('error', (err) => {
    console.error('Failed to start dashboard:', err);
});


setTimeout(() => {

    open('http://localhost:3001/admin')
        .catch(err => console.error('Failed to open browser:', err));
}, 1000);


console.log('Dashboard is running. Press Ctrl+C to stop.');
process.on('SIGINT', () => {
    console.log('Shutting down...');
    process.exit(0);
});