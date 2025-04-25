const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const fs = require('fs');
const ip = require('ip');
const si = require('systeminformation');
const machineIdLib = require('node-machine-id');

const app = express();
const PORT = process.env.PORT || 3000;
const localIP = ip.address();

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, './')));

app.use(session({
    secret: 'wasd_game_secret_key',
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    }
}));

async function getMachineId(req) {
    try {
      
        if (req.headers['x-machine-id']) {
            console.log('Using machine ID from headers');
            return req.headers['x-machine-id'];
        }

      
        if (req.body && req.body.machineId) {
            console.log('Using machine ID from request body');
            return req.body.machineId;
        }

      
        try {
            const id = await machineIdLib.machineId();
            return id;
        } catch (err) {
            console.error('Error getting server machine ID:', err);
            return 'unknown-server-id';
        }
    } catch (error) {
        console.error('Error getting machine ID:', error);
        return 'unknown';
    }
}



try {
    if (fs.existsSync('./wasd_game.db')) {
        console.log('Database exists, will use existing database');
      
      
    }
} catch (err) {
    console.error('Error checking database file:', err);
}


let db;
try {
    db = new sqlite3.Database('./wasd_game.db', (err) => {
        if (err) {
            console.error('Error connecting to database:', err.message);
            return;
        }
        console.log('Connected to the SQLite database');

      
        db.run('PRAGMA foreign_keys = ON', (err) => {
            if (err) {
                console.error('Error enabling foreign keys:', err.message);
            }
        });

      
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                machine_id TEXT,
                is_banned INTEGER DEFAULT 0,
                date_created TEXT DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            } else {
                console.log('Users table ready');
            }
        });

      
        db.run(`
            CREATE TABLE IF NOT EXISTS scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                highScore REAL NOT NULL,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `, (err) => {
            if (err) {
                console.error('Error creating scores table:', err.message);
            } else {
                console.log('Scores table ready');
            }
        });

      
        db.run(`
            CREATE TABLE IF NOT EXISTS bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT NOT NULL UNIQUE,
                reason TEXT,
                admin_username TEXT,
                date_banned TEXT DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) {
                console.error('Error creating bans table:', err.message);
            } else {
                console.log('Bans table ready');
            }
        });
    });
} catch (error) {
    console.error('Database connection error:', error);
}


db.run(`CREATE TABLE IF NOT EXISTS registration_attempts (
    machine_id TEXT PRIMARY KEY,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attempt_count INTEGER DEFAULT 1
)`, err => {
    if (err) {
        console.error('Error creating registration_attempts table:', err.message);
    } else {
        console.log('Registration attempts table ready');
    }
});


async function checkBanStatus(req, res, next) {
    try {
      
        const machineId = await getMachineId(req);
        req.machineId = machineId;

        db.get('SELECT * FROM bans WHERE machine_id = ?', [machineId], (err, ban) => {
            if (err) {
                console.error('Error checking machine ban status:', err.message);
                next();
            } else if (ban) {
              
                if (req.path === '/api/login' || req.path === '/api/register') {
                    console.log(`Banned machine ${machineId} attempted to login/register - rejecting`);
                    return res.status(403).json({ 
                        success: false, 
                        message: 'Your device has been banned. You can still play as a guest.',
                        banned: true
                    });
                }
                
                req.session.isBanned = true;
                console.log(`Machine ID ${machineId} is banned - allowing partial access`);
            }

          
            if (req.session.userId) {
              
                db.get('SELECT is_banned FROM users WHERE id = ?', [req.session.userId], (err, user) => {
                    if (err) {
                        console.error('Error checking user ban status:', err.message);
                    } else if (user && user.is_banned === 1) {
                        req.session.isBanned = true;
                        console.log(`User ${req.session.username} is banned - allowing partial access`);
                    }
                    next();
                });
            } else {
                next();
            }
        });
    } catch (error) {
        console.error('Error in ban middleware:', error);
        next();
    }
}


app.use(checkBanStatus);


const isAuthenticated = (req, res, next) => {
    if (req.session.isAuthenticated && req.session.userId) {
        return next();
    }
    if (req.session.isGuest) {
        return next();
    }
    res.redirect('/login.html');
};


const isAdmin = (req, res, next) => {
    if (req.session.isAuthenticated && req.session.isAdmin) {
        return next();
    }
    res.status(403).json({ success: false, message: 'Admin access required' });
};


app.get('/', (req, res) => {
    if (req.session.isAuthenticated || req.session.isGuest) {
        res.sendFile(path.join(__dirname, 'game.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/login.html', (req, res) => {
  
    if (req.session.isAuthenticated) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});


// app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
//     res.sendFile(path.join(__dirname, 'admin.html'));
// });

// server.js - Add this middleware for admin routes
// Add this near your other middleware setup
const adminOnlyMiddleware = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  // Check if connection is from localhost
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    next(); // Allow the request to proceed
  } else {
    res.status(403).send('Access denied: Admin dashboard is only accessible from the local machine');
  }
};

// Add this to your routes section
// Admin dashboard routes
app.get('/admin', adminOnlyMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});



app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const machineId = await getMachineId(req);

  
    db.get('SELECT * FROM bans WHERE machine_id = ?', [machineId], async (err, ban) => {
        if (err) {
            console.error('Error checking ban status:', err.message);
        } else if (ban) {
            console.log(`Banned machine ${machineId} tried to register`);
          
        }

      
        if (!username || !password || username.length < 3 || password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Username must be at least 3 characters and password at least 6 characters'
            });
        }

        try {
          
            db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
                if (err) {
                    console.error('Error checking username:', err.message);
                    return res.status(500).json({ success: false, message: 'Server error' });
                }

                if (row) {
                  
                    return res.status(400).json({ success: false, message: 'Username already exists' });
                }

                try {
                  
                    const saltRounds = 10;
                    const hashedPassword = await bcrypt.hash(password, saltRounds);

                  
                    const isAdmin = username.toLowerCase() === 'admin' ? 1 : 0;
                  
                    const isBanned = ban ? 1 : 0;

                  
                    db.run('INSERT INTO users (username, password, machine_id, is_banned) VALUES (?, ?, ?, ?)',
                        [username, hashedPassword, machineId, isBanned],
                        function(err) {
                            if (err) {
                                console.error('Error creating user:', err.message);
                                return res.status(500).json({ success: false, message: 'Error creating user' });
                            }

                          
                            req.session.isAuthenticated = true;
                            req.session.userId = this.lastID;
                            req.session.username = username;
                            req.session.isAdmin = isAdmin === 1;
                            req.session.isBanned = isBanned === 1;
                            req.session.machineId = machineId;

                            console.log(`User registered: ${username}, ID: ${this.lastID}, Machine ID: ${machineId}, Admin: ${isAdmin}, Banned: ${isBanned}`);

                            return res.json({ success: true, message: 'Registration successful' });
                        }
                    );
                } catch (hashError) {
                    console.error('Password hashing error:', hashError);
                    return res.status(500).json({ success: false, message: 'Error processing password' });
                }
            });
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ success: false, message: 'Server error' });
        }
    });
});


app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const machineId = await getMachineId(req);

  
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

  
    db.get('SELECT id, username, password, is_banned FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Login error:', err.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }

      
        try {
            const match = await bcrypt.compare(password, user.password);

            if (match) {
              
                req.session.isAuthenticated = true;
                req.session.userId = user.id;
                req.session.username = username;
                req.session.isAdmin = username.toLowerCase() === 'admin';
                req.session.machineId = machineId;

              
                const isBanned = user.is_banned === 1;

                db.get('SELECT * FROM bans WHERE machine_id = ?', [machineId], (err, ban) => {
                    if (err) {
                        console.error('Error checking machine ban:', err.message);
                    }

                    const machineBanned = !!ban;
                    req.session.isBanned = isBanned || machineBanned;

                  
                    db.run('UPDATE users SET machine_id = ? WHERE id = ?', [machineId, user.id], (err) => {
                        if (err) {
                            console.error('Error updating machine ID:', err.message);
                        }
                    });

                    console.log(`User logged in: ${username}, ID: ${user.id}, Machine ID: ${machineId}, Banned: ${isBanned || machineBanned}`);
                    return res.json({ success: true, message: 'Login successful' });
                });
            } else {
                return res.status(400).json({ success: false, message: 'Invalid username or password' });
            }
        } catch (error) {
            console.error('Password comparison error:', error);
            return res.status(500).json({ success: false, message: 'Server error' });
        }
    });
});


app.get('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Error logging out' });
        }
        res.redirect('/login.html');
    });
});


app.get('/api/guest', (req, res) => {
  
    req.session.isGuest = true;
    req.session.isAuthenticated = false;
    req.session.username = 'Guest';
    
    console.log(`Guest session started, Machine ID: ${req.machineId}`);
    return res.json({ success: true, message: 'Guest mode activated' });
});


app.get('/api/user', (req, res) => {
    if (!req.session.isAuthenticated && !req.session.isGuest) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

  
    if (req.session.isGuest) {
        return res.json({
            username: 'Guest',
            isGuest: true,
            highScore: 0
        });
    }

  
    db.get('SELECT highScore FROM scores WHERE user_id = ? ORDER BY highScore DESC LIMIT 1',
        [req.session.userId],
        (err, row) => {
            if (err) {
                console.error('Error fetching user high score:', err.message);
              
                return res.json({
                    username: req.session.username,
                    userId: req.session.userId,
                    isAdmin: req.session.isAdmin || false,
                    isBanned: req.session.isBanned || false,
                    highScore: 0
                });
            }

            const highScore = row ? row.highScore : 0;

            res.json({
                username: req.session.username,
                userId: req.session.userId,
                isAdmin: req.session.isAdmin || false,
                isBanned: req.session.isBanned || false,
                highScore: highScore
            });
        }
    );
});


app.get('/api/scores', (req, res) => {
  
    db.all(`
        SELECT users.username, scores.highScore
        FROM scores
        JOIN users ON scores.user_id = users.id
        WHERE users.is_banned = 0
        ORDER BY scores.highScore DESC
        LIMIT 10
    `, [], (err, rows) => {
        if (err) {
            console.error('Error fetching leaderboard:', err.message);
            return res.status(500).json([]);
        }

        if (!rows || rows.length === 0) {
            console.log('No scores found in leaderboard');
        } else {
            console.log(`Fetched ${rows.length} scores for leaderboard`);
        }

        res.json(rows || []);
    });
});


app.post('/api/scores', (req, res) => {
  
    if (req.session.isGuest) {
        console.log(`Guest user achieved score: ${req.body.score} (not saved)`);
        return res.json({ success: true, highScore: req.body.score, message: 'Score not saved for guest users' });
    }

    if (!req.session.isAuthenticated || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const userId = req.session.userId;
    const { score } = req.body;

    if (score === undefined) {
        return res.status(400).json({ success: false, message: 'Score is required' });
    }

    console.log(`Saving score for user ${req.session.username} (ID: ${userId}): ${score}`);

  
    db.get('SELECT id, highScore FROM scores WHERE user_id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error checking existing score:', err.message);
          
            db.run('INSERT INTO scores (user_id, highScore) VALUES (?, ?)', [userId, score], function(err) {
                if (err) {
                    console.error('Error inserting new score after error:', err.message);
                    return res.status(500).json({ success: false, message: 'Error saving score' });
                }
                console.log(`Inserted new score for user ${req.session.username}: ${score}`);
                return res.json({ success: true, highScore: score });
            });
            return;
        }

        if (row) {
          
            if (score > row.highScore) {
                db.run('UPDATE scores SET highScore = ? WHERE id = ?', [score, row.id], function(err) {
                    if (err) {
                        console.error('Error updating score:', err.message);
                        return res.status(500).json({ success: false, message: 'Error updating score' });
                    }
                    console.log(`Updated score for user ${req.session.username}: ${score}`);
                    res.json({ success: true, highScore: score });
                });
            } else {
              
                console.log(`Score not higher than existing (${row.highScore}). Not updated.`);
                res.json({ success: true, highScore: row.highScore });
            }
        } else {
          
            db.run('INSERT INTO scores (user_id, highScore) VALUES (?, ?)', [userId, score], function(err) {
                if (err) {
                    console.error('Error inserting new score:', err.message);
                    return res.status(500).json({ success: false, message: 'Error saving score' });
                }
                console.log(`Inserted new score for user ${req.session.username}: ${score}`);
                res.json({ success: true, highScore: score });
            });
        }
    });
});

// Admin API endpoints - move these from server-manager.js to server.js
app.get('/api/admin/users', adminOnlyMiddleware, (req, res) => {
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

// Modified ban function in server.js
app.post('/api/admin/ban', adminOnlyMiddleware, (req, res) => {
    const { username, reason } = req.body;
    const adminUsername = req.session.username;

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
                    [user.machine_id, reason || 'No reason provided', adminUsername],
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
                console.log(`User ${username} banned by admin ${adminUsername} (no machine ID)`);
                res.json({ success: true, message: 'User banned successfully (no device ID available)' });
            }
        });
    });
});

// Admin: Unban a user
app.post('/api/admin/unban', adminOnlyMiddleware, (req, res) => {
    const { username } = req.body;
    const adminUsername = req.session.username;

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

            console.log(`User ${username} unbanned by admin ${adminUsername}`);
            res.json({ success: true, message: 'User unbanned successfully' });
        });
    });
});

// Add an API endpoint to handle user removal
app.post('/api/admin/remove', adminOnlyMiddleware, (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }

    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            console.error('Error finding user to remove:', err.message);
            return res.status(500).json({ success: false, message: 'Server error' });
        }

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        db.run('DELETE FROM users WHERE id = ?', [user.id], (err) => {
            if (err) {
                console.error('Error removing user:', err.message);
                return res.status(500).json({ success: false, message: 'Error removing user' });
            }

            console.log(`User "${username}" removed successfully`);
            res.json({ success: true, message: 'User removed successfully' });
        });
    });
});

// Debug endpoint to check tables
app.get('/api/debug/tables', (req, res) => {
  
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='scores'", [], (err, scoreTable) => {
        if (err) {
            console.error('Error checking if scores table exists:', err.message);
            return res.status(500).json({ error: 'Error checking tables' });
        }

        if (!scoreTable) {
            return res.json({
                error: 'Scores table does not exist',
                users: [],
                scores: [],
                bans: []
            });
        }

      
        db.all("PRAGMA table_info(scores)", [], (err, scoreColumns) => {
            if (err) {
                console.error('Error getting scores table info:', err.message);
                return res.status(500).json({ error: 'Error getting table info' });
            }

            const results = {
                users: [],
                scores: [],
                bans: [],
                tables: {
                    scores: scoreColumns
                }
            };

            db.all('SELECT id, username, is_banned, machine_id, date_created FROM users', [], (err, users) => {
                if (err) {
                    results.error = 'Error querying users table';
                    return res.json(results);
                }

                results.users = users || [];

                db.all('SELECT * FROM scores', [], (err, scores) => {
                    if (err) {
                        results.error = 'Error querying scores table';
                    } else {
                        results.scores = scores || [];
                    }

                    db.all('SELECT * FROM bans', [], (err, bans) => {
                        if (err) {
                            results.error = 'Error querying bans table';
                        } else {
                            results.bans = bans || [];
                        }
                        res.json(results);
                    });
                });
            });
        });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

// Close the database connection when the server closes
process.on('SIGINT', () => {
    if (db) {
        db.close((err) => {
            if (err) {
                console.error(err.message);
            }
            console.log('Closed the database connection');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
  
});

// Add a new route for guest mode
app.get('/guest', (req, res) => {
    res.sendFile(path.join(__dirname, 'guest.html'));
});

// Add API route to check if guest mode is available
app.get('/api/guest-available', async (req, res) => {
    try {
        const machineId = await getMachineId(req);
        
      
        db.get('SELECT * FROM bans WHERE machine_id = ?', [machineId], (err, ban) => {
            if (err) {
                console.error('Error checking machine ban status:', err.message);
                return res.status(500).json({ success: false, message: 'Error checking ban status' });
            }
            
          
            res.json({ 
                success: true, 
                isBanned: !!ban,
                message: ban ? 'You can play as guest, but you are banned from creating accounts' : 'Guest mode available'
            });
        });
    } catch (error) {
        console.error('Error checking guest availability:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Add a guest score API route (doesn't save to database, just returns the score)
app.post('/api/guest/score', (req, res) => {
    const { score } = req.body;
    
    if (score === undefined) {
        return res.status(400).json({ success: false, message: 'Score is required' });
    }
    
    console.log(`Guest score: ${score}`);
    res.json({ success: true, score });
});

// Start the server
try {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Access locally: http://localhost:${PORT}`);
        console.log(`Access from other devices: http://${localIP}:${PORT}`);
    });
} catch (error) {
    console.error('Error starting server:', error);
}
