from flask import Flask, render_template, jsonify, request
import psutil
import subprocess
import os
import json
import shutil
from datetime import datetime
from collections import deque

app = Flask(__name__)

# Activity log (last 100 entries)
activity_log = deque(maxlen=100)

def run_cmd_safe(cmd, timeout=10):
    """Execute command safely"""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, cwd=os.getcwd(), text=True, timeout=timeout)
        return output
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return str(e)

def log_activity(action, details, status='success'):
    """Log an activity to the activity log"""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'details': details,
        'status': status
    }
    activity_log.append(entry)
    print(f"[{entry['timestamp']}] {action}: {details} ({status})")
    return entry

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/processes')
def processes():
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
        try:
            procs.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return jsonify(procs)

@app.route('/network')
def network():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        conns.append({
            'fd': c.fd,
            'family': str(c.family),
            'type': str(c.type),
            'laddr': '%s:%s' % (c.laddr) if c.laddr else '',
            'raddr': '%s:%s' % (c.raddr) if c.raddr else '',
            'status': c.status,
            'pid': c.pid
        })
    return jsonify(conns)

@app.route('/battery')
def battery():
    """Get battery info from Termux API"""
    data = run_cmd_safe('termux-battery-stats')
    try:
        return jsonify(json.loads(data))
    except:
        return jsonify({'raw': data})

@app.route('/sensor')
def sensor():
    """Get sensor data from Termux API"""
    data = run_cmd_safe('termux-sensor -p')
    lines = data.split('\n')
    sensors = {}
    for line in lines:
        if ':' in line:
            k, v = line.split(':', 1)
            sensors[k.strip()] = v.strip()
    return jsonify(sensors)

@app.route('/device-info')
def device_info():
    """Get device information"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        
        info = {
            'hostname': run_cmd_safe('hostname').strip(),
            'uptime': run_cmd_safe('uptime').strip(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': cpu_percent,
            'memory': mem._asdict(),
            'disk': disk._asdict(),
            'load_avg': load_avg
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/system-alerts')
def get_system_alerts():
    """Get system security alerts and warnings"""
    alerts = []
    try:
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)
        if cpu_percent > 80:
            alerts.append({
                'level': 'critical',
                'title': 'HIGH CPU USAGE',
                'message': f'CPU usage at {cpu_percent:.1f}%'
            })
        elif cpu_percent > 60:
            alerts.append({
                'level': 'warning',
                'title': 'ELEVATED CPU USAGE',
                'message': f'CPU usage at {cpu_percent:.1f}%'
            })
        
        # Check Memory usage
        mem = psutil.virtual_memory()
        if mem.percent > 85:
            alerts.append({
                'level': 'critical',
                'title': 'CRITICAL MEMORY USAGE',
                'message': f'RAM usage at {mem.percent:.1f}%'
            })
        elif mem.percent > 70:
            alerts.append({
                'level': 'warning',
                'title': 'HIGH MEMORY USAGE',
                'message': f'RAM usage at {mem.percent:.1f}%'
            })
        
        # Check Disk usage
        disk = psutil.disk_usage('/')
        if disk.percent > 90:
            alerts.append({
                'level': 'critical',
                'title': 'CRITICAL DISK USAGE',
                'message': f'Disk usage at {disk.percent:.1f}%'
            })
        elif disk.percent > 80:
            alerts.append({
                'level': 'warning',
                'title': 'HIGH DISK USAGE',
                'message': f'Disk usage at {disk.percent:.1f}%'
            })
        
        # Check for suspicious process count
        proc_count = len(psutil.pids())
        if proc_count > 300:
            alerts.append({
                'level': 'warning',
                'title': 'HIGH PROCESS COUNT',
                'message': f'{proc_count} processes running'
            })
        
        # Check network connections
        try:
            conn_count = len(psutil.net_connections())
            if conn_count > 100:
                alerts.append({
                    'level': 'info',
                    'title': 'ELEVATED CONNECTION COUNT',
                    'message': f'{conn_count} network connections'
                })
        except:
            pass
        
        if not alerts:
            alerts.append({
                'level': 'success',
                'title': 'SYSTEM HEALTHY',
                'message': 'All systems operating normally'
            })
        
        return jsonify({'alerts': alerts})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/open-ports')
def get_open_ports():
    """Get list of listening ports"""
    try:
        connections = psutil.net_connections()
        ports = []
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                try:
                    proc = psutil.Process(conn.pid)
                    ports.append({
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'protocol': 'TCP' if conn.type == 1 else 'UDP',
                        'pid': conn.pid,
                        'process': proc.name()
                    })
                except:
                    pass
        return jsonify({'ports': ports})
    except Exception as e:
        return jsonify({'error': str(e)})

import shutil

@app.route('/packets')
def get_packets():
    """Capture and return a few network packets using tcpdump"""
    # ensure tool is available
    if not shutil.which('tcpdump'):
        return jsonify({'error': 'tcpdump not installed. Install with "pkg install tcpdump" or "apt install tcpdump".'})

    count = request.args.get('count', '20')
    filt = request.args.get('filter', '')
    # build tcpdump command; run on all interfaces
    cmd = f"tcpdump -nn -c {count} -i any {filt} 2>&1"
    output = run_cmd_safe(cmd, timeout=10 + int(count))
    # the command output could include permission errors as well
    return jsonify({'output': output})

@app.route('/run', methods=['POST'])
def run_command():
    """Execute arbitrary command (dangerous!)"""
    data = request.json
    cmd = data.get('cmd')
    if not cmd:
        return jsonify({'error': 'no command'}), 400
    log_activity('EXECUTE_COMMAND', f'Executed: {cmd[:50]}...', 'success')
    output = run_cmd_safe(cmd, timeout=30)
    return jsonify({'output': output, 'status': 'success'})

@app.route('/start-process', methods=['POST'])
def start_process():
    """Start a new process or script"""
    data = request.json
    cmd = data.get('cmd')
    if not cmd:
        return jsonify({'error': 'no command'}), 400
    try:
        # Start process in background
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_activity('START_PROCESS', f'Started: {cmd}', 'success')
        return jsonify({'status': 'success', 'message': f'Process started: {cmd}'})
    except Exception as e:
        log_activity('START_PROCESS', f'Failed to start: {cmd}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/activity-log')
def get_activity_log():
    """Get all logged activities"""
    return jsonify({'activities': list(activity_log)})

@app.route('/kill/<int:pid>', methods=['POST'])
def kill_process(pid):
    """Kill a specific process by PID"""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        log_activity('KILL_PROCESS', f'Killed PID {pid} ({name})', 'success')
        return jsonify({'status': 'success', 'message': f'Process {pid} killed'})
    except Exception as e:
        log_activity('KILL_PROCESS', f'Failed to kill PID {pid}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/suspend/<int:pid>', methods=['POST'])
def suspend_process(pid):
    """Suspend a specific process by PID"""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.suspend()
        log_activity('SUSPEND_PROCESS', f'Suspended PID {pid} ({name})', 'success')
        return jsonify({'status': 'success', 'message': f'Process {pid} suspended'})
    except Exception as e:
        log_activity('SUSPEND_PROCESS', f'Failed to suspend PID {pid}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/resume/<int:pid>', methods=['POST'])
def resume_process(pid):
    """Resume a specific process by PID"""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.resume()
        log_activity('RESUME_PROCESS', f'Resumed PID {pid} ({name})', 'success')
        return jsonify({'status': 'success', 'message': f'Process {pid} resumed'})
    except Exception as e:
        log_activity('RESUME_PROCESS', f'Failed to resume PID {pid}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/file-read', methods=['POST'])
def file_read():
    """Read file contents"""
    data = request.json
    filepath = data.get('path')
    if not filepath:
        return jsonify({'error': 'no path'}), 400
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        log_activity('FILE_READ', f'Read file: {filepath}', 'success')
        return jsonify({'content': content})
    except Exception as e:
        log_activity('FILE_READ', f'Failed to read: {filepath}', 'error')
        return jsonify({'error': str(e)})

@app.route('/file-write', methods=['POST'])
def file_write():
    """Write to file"""
    data = request.json
    filepath = data.get('path')
    content = data.get('content')
    if not filepath or content is None:
        return jsonify({'error': 'missing path or content'}), 400
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        log_activity('FILE_WRITE', f'Wrote to file: {filepath}', 'success')
        return jsonify({'status': 'success'})
    except Exception as e:
        log_activity('FILE_WRITE', f'Failed to write: {filepath}', 'error')
        return jsonify({'error': str(e)})

@app.route('/file-delete', methods=['POST'])
def file_delete():
    """Delete a file"""
    data = request.json
    filepath = data.get('path')
    if not filepath:
        return jsonify({'error': 'no path'}), 400
    try:
        os.remove(filepath)
        log_activity('FILE_DELETE', f'Deleted file: {filepath}', 'success')
        return jsonify({'status': 'success'})
    except Exception as e:
        log_activity('FILE_DELETE', f'Failed to delete: {filepath}', 'error')
        return jsonify({'error': str(e)})

@app.route('/dir-list', methods=['POST'])
def dir_list():
    """List directory contents"""
    data = request.json
    dirpath = data.get('path', os.path.expanduser('~'))
    try:
        items = []
        for item in os.listdir(dirpath):
            fullpath = os.path.join(dirpath, item)
            is_dir = os.path.isdir(fullpath)
            items.append({'name': item, 'path': fullpath, 'is_dir': is_dir})
        return jsonify({'items': items})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/packages/installed')
def get_installed_packages():
    """Get list of installed packages"""
    try:
        output = run_cmd_safe('apt list --installed 2>/dev/null | head -50')
        packages = []
        for line in output.split('\n'):
            if line and '/' in line:
                parts = line.split('/')
                packages.append({
                    'name': parts[0].strip(),
                    'version': parts[1].strip() if len(parts) > 1 else 'unknown'
                })
        return jsonify({'packages': packages, 'total': len(packages)})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/packages/search', methods=['POST'])
def search_packages():
    """Search for packages"""
    data = request.json
    query = data.get('query')
    if not query:
        return jsonify({'error': 'no query'}), 400
    try:
        output = run_cmd_safe(f'apt search {query} 2>/dev/null | grep -E "^[a-z]" | head -30')
        packages = []
        for line in output.split('\n'):
            if line and '/' not in line:
                parts = line.split(' - ')
                if len(parts) >= 2:
                    pkg_info = parts[0].strip().split('/')
                    packages.append({
                        'name': pkg_info[0].strip(),
                        'description': parts[1].strip() if len(parts) > 1 else 'No description'
                    })
        return jsonify({'packages': packages})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/packages/install', methods=['POST'])
def install_package():
    """Install a package"""
    data = request.json
    pkg_name = data.get('package')
    if not pkg_name:
        return jsonify({'error': 'no package name'}), 400
    try:
        output = run_cmd_safe(f'apt-get install -y {pkg_name} 2>&1')
        log_activity('INSTALL_PACKAGE', f'Installed: {pkg_name}', 'success')
        return jsonify({'status': 'success', 'output': output})
    except Exception as e:
        log_activity('INSTALL_PACKAGE', f'Failed to install: {pkg_name}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/packages/remove', methods=['POST'])
def remove_package():
    """Remove a package"""
    data = request.json
    pkg_name = data.get('package')
    if not pkg_name:
        return jsonify({'error': 'no package name'}), 400
    try:
        output = run_cmd_safe(f'apt-get remove -y {pkg_name} 2>&1')
        log_activity('REMOVE_PACKAGE', f'Removed: {pkg_name}', 'success')
        return jsonify({'status': 'success', 'output': output})
    except Exception as e:
        log_activity('REMOVE_PACKAGE', f'Failed to remove: {pkg_name}', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/packages/update', methods=['POST'])
def update_packages():
    """Update package list"""
    try:
        output = run_cmd_safe('apt-get update 2>&1')
        log_activity('UPDATE_PACKAGES', 'Updated package list', 'success')
        return jsonify({'status': 'success', 'output': output})
    except Exception as e:
        log_activity('UPDATE_PACKAGES', 'Failed to update packages', 'error')
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # host 0.0.0.0 to be reachable from mobile (use port 8088 to avoid conflicts)
    app.run(host='0.0.0.0', port=8088, debug=True)
