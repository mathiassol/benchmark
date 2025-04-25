// start-dashboard.js
const open = require('open');

console.log('Opening WASD Game Admin Dashboard...');

// Open the admin dashboard
open('http://localhost:3000/admin')
  .catch(err => console.error('Failed to open browser:', err));

console.log('Navigate to http://localhost:3000/admin to access the dashboard');