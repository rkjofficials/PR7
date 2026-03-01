# ⚔️ PR7 SOC (Security Operations Center) Dashboard

```text
..PPPP...RRRR....7777.
.P...P..R...R......7.
..PPPP...RRRR......7.
.P......R..R......7.
.P......R...R.....7.
```

A professional cybersecurity monitoring and control system for Android Termux that allows complete device management from a web interface without opening the Termux app.

---

## 🎯 Features

### 📊 **Dashboard** (Default Entry Point)
- **System Status Overview**: Hostname, uptime, active processes, network connections
- **Resource Utilization**: Real-time CPU, RAM, and Disk usage monitoring
- **Device Status**: Battery info, temperature sensors
- **Real-Time Performance Charts**:
  - CPU Usage (30-point history)
  - Memory Usage (30-point history)
  - Network Connections by status (ESTABLISHED, LISTEN, etc.)
- **Security Alerts & Warnings**:
  - Critical alerts (CPU >80%, RAM >85%, Disk >90%)
  - Warning alerts (CPU >60%, RAM >70%, Disk >80%)
  - High process count warnings
  - Elevated connection count alerts
- **Device Sensors**: Temperature and other sensor data

---

### ⚙️ **Processes Management**
- **Launch Processes/Scripts**: Execute background tasks (Python scripts, Node.js services, Bash scripts)
- **Process List**: View all running processes with status indicators
- **Process Control**:
  - Kill (terminate process)
  - Suspend (pause process)
  - Resume (unpause process)
- **Process Monitoring**: Real-time count and status updates

---

### 🌐 **Network Monitoring**
- View all active network connections
- Display: Local address, remote address, connection status, associated PID
- Monitor incoming and outgoing connections
- Identify listening ports and services

---

### 📂 **File Manager**
- Browse directories on the device
- Navigate folders with click actions
- Copy file paths to editor
- Support for any directory path

---

### 📝 **File Editor**
- Read file contents
- Edit and save files
- Delete files
- Full path support for any file access

---

### 💻 **Terminal Command Executor**
- Execute any shell command without opening Termux
- Live command output display
- Quick command shortcuts:
  - `whoami` - Current user
  - `pwd` - Current directory
  - `date` - System date/time
  - `df -h` - Disk space usage
  - `free -h` - Memory information
  - `uname -a` - System information

---

### 📦 **Package Manager**
- **Search Packages**: Find available packages in apt repository
- **View Installed**: List all installed packages with versions
- **Install Packages**: One-click installation with live progress
- **Remove Packages**: Uninstall packages with confirmation
- **Update Package List**: Refresh apt cache
- Installation/Removal output display

---

### 📋 **Activity Log**
- Complete audit trail of all actions
- Timestamp for each activity
- Action details and status (success/error)
- Real-time updates every 1 second
- Latest activities shown first

---

## 🚀 Installation & Usage

### Prerequisites
- Android device with Termux installed
- Python 3.7+
- Internet connection

### Setup

1. **Clone/Copy to Termux**:
   ```bash
   cd /data/data/com.termux/files/home
   git clone <repository> termux_monitor
   cd termux_monitor
   ```

2. **Grant Storage Permissions** (Required for Termux):
   ```bash
   # This grants access to external storage and system files
   termux-setup-storage
   # Accept the permission prompt on your device
   ```

3. **Install Dependencies**:
   ```bash
   pkg update
   pkg install python
   pip install -r requirements.txt
   ```

4. **Run the Dashboard**:
   ```bash
   python app.py
   ```

5. **Access the Dashboard**:
   - Open browser (Firefox, Chrome, etc.)
   - Navigate to: `http://localhost:8088`
   - Or from another device: `http://<YOUR_DEVICE_IP>:8088`

### 🔒 Permission Notes for Termux (Android 9 Non-Rooted)

**Important**: Android 9 non-rooted devices have sandbox restrictions. If you get errors:

1. **"Error 13: Permission Denied /" error**:
   - This is **normal and expected** on non-rooted Android
   - The app has restricted file system access for security
   
2. **What works** ✅:
   - Process monitoring (CPU, RAM, count)
   - Network monitoring (connections, ports)
   - File operations in home directory or `/sdcard/`
   - Basic device info (except full disk access)
   - System alerts and warnings

3. **What requires permissions** ❌:
   - Full disk access (can still read home directory)
   - System file reading
   - Root-level process control
   - Direct hardware access (battery, sensors need Termux API)

4. **Solutions**:
   - **Grant storage permissions**: `termux-setup-storage`
   - **Install Termux API** (for battery/sensor data):
     ```bash
     pkg install termux-api
     # Also install on device: download from F-Droid or Play Store
     ```
   - **Use only accessible paths**:
     - ✅ `~/` (home directory)
     - ✅ `/sdcard/` (external storage)
     - ✅ `/storage/` (media storage)
     - ❌ `/` (root - blocked by sandbox)
     - ❌ `/system/` (system files - blocked)

5. **Rooted Android Alternative**:
   - If you root your device later, the app will gain full access
   - Run with: `sudo python app.py` (after installing sudo)

---

## 📋 Requirements

**requirements.txt**:
- flask - Web framework
- psutil - System monitoring
- flask-socketio - WebSocket support (optional)
- eventlet - Async support (optional)

---

## 🎨 UI/UX Design

### Professional Cybersecurity Theme
- **Dark theme** with neon accents (hacker aesthetic)
- **Color Scheme**:
  - Primary: Neon Green (#00ff99)
  - Accent: Cyan (#00ffcc)
  - Critical: Red (#ff4444)
  - Warning: Orange (#ffaa44)
  - Success: Bright Green (#44ff44)

### Navigation
- **8 Main Tabs**:
  1. 📊 Dashboard
  2. ⚙️ Processes
  3. 🌐 Network
  4. 📂 File Manager
  5. 📝 File Editor
  6. 💻 Commands
  7. 📦 Packages
  8. 📋 Activity

---

## 🔐 Security Considerations

⚠️ **WARNING**: This dashboard provides full system control through a web interface. Use only on:
- **Local networks** (trusted environment)
- **Private networks** (VPN protected)
- **NOT** exposed to the internet without authentication

### Recommendations
1. Run on localhost only (default)
2. Use SSH tunneling for remote access
3. Add authentication layer (future enhancement)
4. Run on non-standard ports if exposed to network
5. Use HTTPS with SSL certificates

---

## 📊 API Endpoints Reference

### System Info
- `GET /device-info` - System information and resource usage
- `GET /system-alerts` - Security alerts and warnings
- `GET /battery` - Battery status
- `GET /sensor` - Device sensors
- `GET /open-ports` - Listening ports

### Process Management
- `GET /processes` - List all processes
- `POST /kill/<pid>` - Kill process
- `POST /suspend/<pid>` - Suspend process
- `POST /resume/<pid>` - Resume process
- `POST /start-process` - Start new process/script

### Network
- `GET /network` - Network connections
- `GET /packets` - Capture live packets (requires `tcpdump` installed)
  - query params: `count` (number of packets) and `filter` (tcpdump-style filter)
- `POST /run` - Execute shell command

### Files
- `POST /file-read` - Read file contents
- `POST /file-write` - Write file contents
- `POST /file-delete` - Delete file
- `POST /dir-list` - List directory

### Packages
- `GET /packages/installed` - Installed packages
- `POST /packages/search` - Search packages
- `POST /packages/install` - Install package
- `POST /packages/remove` - Remove package
- `POST /packages/update` - Update package list

### Logs
- `GET /activity-log` - Activity history

---

## 🧪 Packet Capture

The dashboard can capture a few network packets directly from the device using `tcpdump`.

1. **Install tcpdump** (not shipped with Termux by default):
   ```bash
   pkg install tcpdump      # preferred Termux command
   # or: apt update && apt install tcpdump
   ```
2. Open the **📡 Packets** tab in the web interface.
3. Enter the number of packets to grab (default 20) and an optional filter (e.g. `tcp`, `port 80`).
4. Click **Capture** and the raw packet output will appear.

If `tcpdump` is missing or permission is denied the UI will show an error message.


---

## 🛠️ Troubleshooting

### Port Already in Use
```bash
lsof -i :8080  # Find what's using port 8080
pkill -f "python app.py"  # Kill the process
```

### Permission Denied
- Ensure proper file permissions
- Run as current user (not root unless necessary)
- Check directory write permissions

### Connection Refused
- Verify server is running: `ps aux | grep python`
- Check if port 8080 is open: `netstat -tlnp | grep 8080`
- Try localhost vs device IP

---

## 🔮 Future Enhancements

- [ ] User authentication and API keys
- [ ] SSL/HTTPS support
- [ ] Dark/Light theme toggle
- [ ] Custom dashboard widgets
- [ ] SSH key management
- [ ] Cron job scheduling
- [ ] System backup/restore
- [ ] Network traffic analysis
- [ ] Process dependencies visualization
- [ ] Custom command shortcuts

---

## 📝 License

MIT License - Feel free to modify and distribute

---

## ⚡ Tips & Tricks

1. **Access from PC**: Find device IP with `ifconfig` and open `http://<IP>:8080` from PC
2. **Keep Running**: Use `nohup python app.py &` to keep running after terminal close
3. **Auto-start**: Add to `.bashrc` for automatic startup
4. **Quick Navigation**: Use keyboard shortcuts in File Manager
5. **Command History**: Activity log keeps records of all commands executed

---

**Made for cybersecurity professionals who need complete Termux control without opening the app! 🚀**
