const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow;
let serverProcess;

app.on('ready', () => {
    // Create the Electron window
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile('logs.html');

    // Start the server.js process
    serverProcess = spawn('node', [path.join(__dirname, 'server.js')]);

    let logs = [];

    serverProcess.stdout.on('data', (data) => {
        const logMessage = data.toString();
        logs.push(logMessage); // Store logs
        if (mainWindow) {
            mainWindow.webContents.send('log-message', logMessage);
        }
    });

    serverProcess.stderr.on('data', (data) => {
        const logMessage = `ERROR: ${data.toString()}`;
        logs.push(logMessage); // Store logs
        if (mainWindow) {
            mainWindow.webContents.send('log-message', logMessage);
        }
    });

    ipcMain.on('get-logs', (event) => {
        event.reply('load-logs', logs); // Send stored logs to the renderer
    });

    serverProcess.on('close', (code) => {
        if (mainWindow) {
            mainWindow.webContents.send('log-message', `Server process exited with code ${code}`);
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
        if (serverProcess) {
            serverProcess.kill();
        }
    });
});

app.on('window-all-closed', () => {
    if (serverProcess) {
        serverProcess.kill();
    }
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

ipcMain.on('show-database', () => {
    if (mainWindow) {
        mainWindow.loadFile('database.html');
    }
});

ipcMain.on('show-logs', () => {
    if (mainWindow) {
        mainWindow.loadFile('logs.html');
    }
});

ipcMain.on('fetch-database', (event) => {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database(path.join(__dirname, 'wasd_game.db'));

    db.all('SELECT * FROM users', [], (err, rows) => {
        if (err) {
            console.error('Error fetching database:', err.message);
            event.reply('database-data', { error: err.message });
        } else {
            event.reply('database-data', rows);
        }
        db.close();
    });
});