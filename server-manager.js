const { spawn } = require('child_process');
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');


const managerApp = express();
const MANAGER_PORT = 3000;
const MAIN_SERVER_PORT = 3000;

managerApp.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  // Check if the connection is from localhost (127.0.0.1) or ::1 (IPv6 localhost)
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    next(); // Allow the request to proceed
  } else {
    res.status(403).send('Access denied: Dashboard is only accessible from the local machine');
  }
});


let db;
try {
    db = new sqlite3.Database('./wasd_game.db', (err) => {
        if (err) {
            console.error('Error connecting to database:', err.message);
        } else {
            console.log('Connected to the SQLite database from manager');
        }
    });
} catch (error) {
    console.error('Database connection error:', error);
}


managerApp.use(cors({
    origin: true,
    credentials: true
}));


managerApp.use(express.static(path.join(__dirname, './')));
managerApp.use(express.json());


let serverProcess = null;
let serverStatus = 'stopped';
let serverLogs = [];


// server-manager.js - Remove or modify the startServer function:

// Instead of starting a new server process, check if the server is already running
function checkServerStatus() {
  // Try to connect to the main server to see if it's running
  const http = require('http');
  const req = http.request({
    hostname: 'localhost',
    port: MAIN_SERVER_PORT,
    path: '/api/status', // You may need to create this endpoint in your main server
    method: 'GET'
  }, (res) => {
    serverStatus = 'running';
    console.log('Main server is running');
  });
  
  req.on('error', (e) => {
    serverStatus = 'stopped';
    console.log('Main server appears to be stopped');
  });
  
  req.end();
  
  return { success: true, message: 'Server status checked' };
}

// Replace the startServer route with:
managerApp.post('/api/manager/start', (req, res) => {
  // Inform the user that they need to start the main server separately
  res.json({ 
    success: false, 
    message: 'Please start the main server using "npm start" in a separate terminal'
  });
});


function stopServer() {
    if (!serverProcess) {
        return { success: false, message: 'Server is not running' };
    }

    try {
        serverProcess.kill();
        serverStatus = 'stopping';

      
        setTimeout(() => {
          
            if (serverProcess) {
                try {
                    process.kill(serverProcess.pid, 'SIGKILL');
                } catch (e) {
                  
                }
                serverProcess = null;
                serverStatus = 'stopped';
            }
        }, 3000);

        return { success: true, message: 'Server stopping...' };
    } catch (error) {
        console.error('Failed to stop server:', error);
        return { success: false, message: `Failed to stop server: ${error.message}` };
    }
}



managerApp.post('/api/manager/stop', (req, res) => {
    const result = stopServer();
    res.json(result);
});


managerApp.get('/api/manager/status', (req, res) => {
    res.json({
        status: serverStatus,
        isRunning: serverProcess !== null
    });
});


managerApp.get('/api/manager/logs', (req, res) => {
  
    res.json(serverLogs.slice(-100));
});



managerApp.get('/api/admin/users', (req, res) => {
    if (!db) {
        return res.status(500).json({ success: false, message: 'Database connection not available' });
    }

    db.all(`
        SELECT u.id, u.username, u.is_banned, u.machine_id, u.date_created,
               s.highScore
        FROM users u
        LEFT JOIN scores s ON u.id = s.user_id
        ORDER BY u.username
    `, [], (err, users) => {
        if (err) {
            console.error('Error fetching users:', err.message);
            return res.status(500).json({ success: false, message: 'Error fetching users' });
        }

        console.log(`Retrieved ${users ? users.length : 0} users from database`);
        res.json(users || []);
    });
});


managerApp.post('/api/admin/ban', (req, res) => {
    if (!db) {
        return res.status(500).json({ success: false, message: 'Database connection not available' });
    }

    const { username, reason } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }

  
    db.get('SELECT id, machine_id, is_banned FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            console.error('Error finding user to ban:', err.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

      
        db.run('UPDATE users SET is_banned = 1 WHERE id = ?', [user.id], (err) => {
            if (err) {
                console.error('Error banning user:', err.message);
                return res.status(500).json({ success: false, message: 'Error banning user' });
            }

          
            if (user.machine_id) {
                db.run('INSERT OR REPLACE INTO bans (machine_id, reason, admin_username) VALUES (?, ?, ?)',
                    [user.machine_id, reason || 'No reason provided', 'Admin via Dashboard'],
                    (err) => {
                        if (err) {
                            console.error('Error adding machine to ban list:', err.message);
                          
                        }
                        
                      
                        db.all('SELECT id, username FROM users WHERE machine_id = ? AND id != ? AND is_banned = 0', 
                            [user.machine_id, user.id], 
                            (err, relatedUsers) => {
                                if (err) {
                                    console.error('Error finding related accounts:', err.message);
                                    return res.json({ 
                                        success: true, 
                                        message: 'User banned successfully, but failed to check for related accounts' 
                                    });
                                }
                                
                                if (!relatedUsers || relatedUsers.length === 0) {
                                    return res.json({ 
                                        success: true, 
                                        message: 'User banned successfully. No other accounts found from this device.' 
                                    });
                                }
                                
                              
                                const userIds = relatedUsers.map(u => u.id);
                                db.run('UPDATE users SET is_banned = 1 WHERE id IN (' + userIds.map(() => '?').join(',') + ')', 
                                    userIds, 
                                    (err) => {
                                        if (err) {
                                            console.error('Error banning related accounts:', err.message);
                                            return res.json({ 
                                                success: true, 
                                                message: 'User banned successfully, but failed to ban related accounts' 
                                            });
                                        }
                                        
                                        const bannedUsernames = relatedUsers.map(u => u.username).join(', ');
                                        console.log(`${relatedUsers.length} related accounts banned along with ${username}: ${bannedUsernames}`);
                                        
                                        res.json({ 
                                            success: true, 
                                            message: `User banned successfully. Also banned ${relatedUsers.length} related account(s) from the same device: ${bannedUsernames}` 
                                        });
                                    });
                            });
                    }
                );
            } else {
                console.log(`User ${username} banned by admin via dashboard (no machine ID)`);
                res.json({ success: true, message: 'User banned successfully (no device ID available)' });
            }
        });
    });
});


managerApp.post('/api/admin/unban', (req, res) => {
    if (!db) {
        return res.status(500).json({ success: false, message: 'Database connection not available' });
    }

    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }

  
    db.get('SELECT id, machine_id FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            console.error('Error finding user to unban:', err.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

      
        db.run('UPDATE users SET is_banned = 0 WHERE id = ?', [user.id], (err) => {
            if (err) {
                console.error('Error unbanning user:', err.message);
                return res.status(500).json({ success: false, message: 'Error unbanning user' });
            }

          
            if (user.machine_id) {
                db.run('DELETE FROM bans WHERE machine_id = ?', [user.machine_id], (err) => {
                    if (err) {
                        console.error('Error removing machine from ban list:', err.message);
                      
                    }
                });
            }

            console.log(`User ${username} unbanned by admin via dashboard`);
            res.json({ success: true, message: 'User unbanned successfully' });
        });
    });
});


managerApp.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});


managerApp.get('/', (req, res) => {
    res.redirect('/admin');
});


process.on('SIGINT', () => {
    if (db) {
        db.close((err) => {
            if (err) {
                console.error(err.message);
            }
            console.log('Closed the database connection from manager');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});


managerApp.listen(MANAGER_PORT, '0.0.0.0', () => {
    console.log(`Server Manager running on http://localhost:${MANAGER_PORT}`);
    console.log('Use this dashboard to start and stop the main server');
});