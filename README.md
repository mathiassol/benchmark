# benchmark / acount management system
This program is not intended for pro use and is in generel a scrap project i made while bored in school. The program was made in 1 day so dont exspect any thing super fine tuned. with that here are all the tecnical aspects for who ever is reviewing my code:

ps: "the game is more of a placeholder"

## Core Gameplay
- **WASD Typing Game**: A fast-paced typing test focused on the W, A, S, D keys
- **Timed Challenge**: 5-second gameplay sessions
- **Score System**: Points gained for correct key presses and deducted for mistakes
- **Final Score Calculation**: Score divided by total time to get average performance

## User Management
- **User Accounts**: Registration and login system for tracking player progress
- **Session Management**: Keeps users logged in and redirects unauthorized users
- **High Score Tracking**: Stores each user's best performance
- **Logout Functionality**: Allows users to securely sign out

## Leaderboard System
- **Global Leaderboard**: Shows top performers across all players
- **Real-time Updates**: Leaderboard refreshes after each game
- **Visual Indicators**: Highlights the current user's position on the leaderboard
- **Manual Refresh**: Button to manually update leaderboard data

## UI/UX Features
- **Clean Interface**: Minimal, distraction-free gaming environment
- **Responsive Design**: Works on various screen sizes
- **Visual Feedback**: Shows the current expected key
- **Game Timer**: Countdown display during gameplay
- **Player Instructions**: Clear prompts to start and play the game
- **Highlighted User Score**: Shows player's score in gold on the leaderboard

## Admin Panel
- **User Management**: View, search, ban, and unban users
- **Ban System**: Admins can ban users with custom reasons
- **Server Controls**: Start and stop the game server from the admin interface
- **Server Status Monitoring**: Real-time status indicators
- **Server Logs**: View system logs directly in the admin interface
- **Search Functionality**: Filter users by username

## Security Features
- **Machine ID Tracking**: Associates accounts with physical devices
- **Banned User Handling**: Prevents banned users from appearing on leaderboard
- **Ban Notifications**: Informs users if their account is banned
- **Admin Authentication**: Secures admin functionality

## Technical Features
- **RESTful API**: Well-structured endpoints for game data and admin functions
- **Database Integration**: Stores user data, scores, and system logs
- **Server Management API**: Controls for starting/stopping the application
- **Debug Tools**: Optional debug mode for troubleshooting database issues
- **Automatic Refresh**: Polling for server status and log updates
