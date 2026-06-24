#!/usr/bin/env python3
"""
BackupShield Web GUI - Simple HTTP server with web interface
Usage: python3 backup-shield-web.py

Opens in browser at http://localhost:8080
"""

import http.server
import socketserver
import urllib.parse
import os
import sys
import subprocess
import webbrowser
from pathlib import Path
import threading
import json

PORT = 8080

# Find binary
def get_binary_path():
    base_dir = Path(__file__).parent.parent
    binary_name = "backup-shield.exe" if sys.platform == "win32" else "backup-shield"
    
    release_bin = base_dir / "target" / "release" / binary_name
    if release_bin.exists():
        return str(release_bin)
    
    if Path(binary_name).exists():
        return binary_name
    
    import shutil
    return shutil.which(binary_name) or binary_name

BINARY = get_binary_path()

HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BackupShield v0.6.0</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        .header {
            background: linear-gradient(135deg, #1976d2, #1565c0);
            color: white;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 24px; }
        .header p { opacity: 0.8; font-size: 14px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }
        .card h3 { color: #1976d2; margin-bottom: 10px; }
        .card p { color: #666; font-size: 14px; line-height: 1.5; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            margin-top: 10px;
        }
        .btn:hover { background: #1565c0; }
        .btn-secondary { background: #757575; }
        .btn-secondary:hover { background: #616161; }
        input, select {
            width: 100%;
            padding: 10px;
            margin: 5px 0 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .output {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Monaco', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            margin-top: 20px;
        }
        .status { padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; }
        .nav a {
            padding: 10px 20px;
            background: white;
            border-radius: 4px;
            text-decoration: none;
            color: #333;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .nav a:hover { background: #e3f2fd; }
        .repo-info { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ BackupShield</h1>
        <p>v0.6.0 - Cross-platform Backup Manager</p>
    </div>
    
    <div class="container">
        <div id="nav" class="nav">
            <a href="/?page=dashboard">Dashboard</a>
            <a href="/?page=backup">New Backup</a>
            <a href="/?page=snapshots">Snapshots</a>
            <a href="/?page=settings">Settings</a>
        </div>
        
        <div id="content">
            <!-- Content loaded dynamically -->
        </div>
    </div>

    <script>
        let currentRepo = null;
        
        function loadPage(page, params = {}) {
            let url = '/api/' + page;
            if (Object.keys(params).length > 0) {
                url += '?' + new URLSearchParams(params).toString();
            }
            fetch(url)
                .then(r => r.text())
                .then(html => {
                    document.getElementById('content').innerHTML = html;
                });
        }
        
        function runCommand(cmd, params = {}) {
            let url = '/api/exec?' + new URLSearchParams({cmd: cmd, ...params});
            fetch(url)
                .then(r => r.text())
                .then(result => {
                    document.getElementById('output').textContent = result;
                });
        }
        
        // Load dashboard on start
        loadPage('dashboard');
    </script>
</body>
</html>
"""

def run_cmd(args):
    """Run backup-shield command."""
    cmd = [BINARY] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

class BackupHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/'):
            self.handle_api()
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML.encode())
    
    def handle_api(self):
        path = self.path[5:]  # Remove /api/
        
        if path == 'dashboard':
            repo = self.get_current_repo()
            if repo:
                stats = run_cmd(['stats', '--repo', repo])
                html = f'''
                    <div class="repo-info">
                        <strong>Repository:</strong> {repo}
                    </div>
                    <div class="grid">
                        <div class="card">
                            <h3>📊 Statistics</h3>
                            <div class="output">{stats}</div>
                        </div>
                        <div class="card">
                            <h3>🚀 Quick Actions</h3>
                            <p>Use the navigation above to manage your backups.</p>
                            <a href="/?page=backup" class="btn">Start Backup</a>
                            <a href="/?page=verify" class="btn btn-secondary">Verify</a>
                        </div>
                    </div>
                '''
            else:
                html = '''
                    <div class="card">
                        <h3>Welcome to BackupShield!</h3>
                        <p>No repository open. Create or open one to get started.</p>
                    </div>
                '''
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        
        if path == 'backup':
            html = '''
                <h2>Start New Backup</h2>
                <div class="card">
                    <form onsubmit="event.preventDefault(); runCommand('backup', {source: this.source.value, repo: this.repo.value, tag: this.tag.value})">
                        <label>Source Folder:</label>
                        <input type="text" name="source" placeholder="/path/to/backup" required>
                        
                        <label>Repository:</label>
                        <input type="text" name="repo" placeholder="/path/to/repo" required>
                        
                        <label>Tag (optional):</label>
                        <input type="text" name="tag" placeholder="backup tag">
                        
                        <button type="submit" class="btn">Start Backup</button>
                    </form>
                    <div id="output" class="output"></div>
                </div>
            '''
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        
        if path == 'snapshots':
            repo = self.get_current_repo()
            if not repo:
                html = '<p>No repository open</p>'
            else:
                result = run_cmd(['snapshots', '--repo', repo])
                html = f'''
                    <h2>Snapshots</h2>
                    <div class="output">{result}</div>
                '''
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        
        if path == 'settings':
            repo = self.get_current_repo()
            if not repo:
                html = '<p>No repository open</p>'
            else:
                result = run_cmd(['config', '--repo', repo, '--show'])
                html = f'''
                    <h2>Settings</h2>
                    <div class="card">
                        <div class="output">{result}</div>
                    </div>
                    <div class="card">
                        <h3>Create Recovery Bundle</h3>
                        <form onsubmit="event.preventDefault(); runCommand('recovery', {repo: this.repo.value, output: this.output.value})">
                            <label>Repository:</label>
                            <input type="text" name="repo" value="{repo}" required>
                            <label>Output Folder:</label>
                            <input type="text" name="output" placeholder="/path/to/recovery" required>
                            <button type="submit" class="btn">Create</button>
                        </form>
                    </div>
                '''
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return
        
        # Default
        self.send_response(404)
        self.end_headers()
    
    def get_current_repo(self):
        # Simple: first argument or look for config.toml in common locations
        return None

def main():
    print(f"Starting BackupShield Web GUI...")
    print(f"Binary: {BINARY}")
    print(f"Open http://localhost:{PORT} in your browser")
    print("Press Ctrl+C to stop")
    
    webbrowser.open(f"http://localhost:{PORT}")
    
    with socketserver.TCPServer(("", PORT), BackupHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")

if __name__ == "__main__":
    main()