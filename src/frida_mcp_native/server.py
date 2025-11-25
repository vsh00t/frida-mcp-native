#!/usr/bin/env python3
"""
Frida MCP Native Server

Uses Frida CLI directly via subprocess to get full Java/ObjC support.
This works around the Frida 17+ change where Java bridge is no longer
baked into GumJS runtime for python-frida and npm frida.
"""

import asyncio
import json
import subprocess
import threading
import time
import re
import os
import signal
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from mcp.server.fastmcp import FastMCP

# Initialize MCP server
mcp = FastMCP("frida-native")

# ============================================================================
# Frida CLI Paths - adjust if frida is installed elsewhere
# ============================================================================

# Try to find frida in common locations
def _find_frida_path():
    """Find the frida CLI installation path."""
    import shutil
    
    # Common locations to check - order matters, check user paths first
    locations = [
        os.path.expanduser("~/.local/bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
    ]
    
    # Check common locations first (more reliable than shutil.which in isolated envs)
    for loc in locations:
        frida_path = os.path.join(loc, "frida")
        if os.path.exists(frida_path) and os.access(frida_path, os.X_OK):
            return loc
    
    # Fallback to PATH lookup
    frida_path = shutil.which("frida")
    if frida_path:
        return os.path.dirname(frida_path)
    
    return None

FRIDA_BIN_PATH = _find_frida_path()

if FRIDA_BIN_PATH is None:
    import sys
    print("WARNING: Frida CLI not found. Please install frida-tools.", file=sys.stderr)
    FRIDA_BIN_PATH = os.path.expanduser("~/.local/bin")  # Fallback

def _frida_cmd(cmd: str) -> str:
    """Get full path to a frida command."""
    return os.path.join(FRIDA_BIN_PATH, cmd)

# ============================================================================
# Session Management
# ============================================================================

@dataclass
class FridaSession:
    """Represents an interactive Frida session."""
    session_id: str
    device: Optional[str]
    target: str  # PID or process name
    process: subprocess.Popen
    output_buffer: List[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    is_ready: bool = False
    last_activity: float = field(default_factory=time.time)

# Global session storage
_sessions: Dict[str, FridaSession] = {}
_session_counter = 0

# Remote devices cache
_remote_devices: Dict[str, str] = {}  # host:port -> description


def _get_device_args(device: Optional[str]) -> List[str]:
    """Get frida CLI arguments for device selection."""
    if not device:
        return []
    
    # Check if it's a remote device (host:port format)
    if ':' in device and not device.startswith('/'):
        return ['-H', device]
    elif device == 'usb':
        return ['-U']
    elif device == 'local':
        return ['-D', 'local']
    else:
        return ['-D', device]


def _run_frida_command(args: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a frida command and return the result."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": f"Command timed out after {timeout} seconds"
        }
    except FileNotFoundError as e:
        return {
            "status": "error", 
            "error": f"Frida CLI not found. Make sure frida-tools is installed: {e}"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# ============================================================================
# Device Tools
# ============================================================================

@mcp.tool()
def list_devices() -> Dict[str, Any]:
    """
    List all available Frida devices.
    
    Returns a list of devices including local, USB, and any added remote devices.
    """
    result = _run_frida_command([_frida_cmd('frida-ls-devices')])
    
    if result["status"] != "success":
        return result
    
    devices = []
    lines = result["stdout"].strip().split('\n')
    
    # Parse frida-ls-devices output
    # Format: Id                            Type    Name
    for line in lines[1:]:  # Skip header
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            device_id = parts[0]
            device_type = parts[1]
            device_name = ' '.join(parts[2:])
            devices.append({
                "id": device_id,
                "type": device_type,
                "name": device_name
            })
    
    # Add cached remote devices
    for host, desc in _remote_devices.items():
        if not any(d["id"] == f"socket@{host}" for d in devices):
            devices.append({
                "id": f"socket@{host}",
                "type": "remote",
                "name": desc or host
            })
    
    return {
        "status": "success",
        "devices": devices
    }


@mcp.tool()
def add_remote_device(
    host: str = "The host:port of the remote frida-server (e.g., '192.168.1.100:27042')"
) -> Dict[str, Any]:
    """
    Add a remote device running frida-server.
    
    This tests the connection and caches the device for later use.
    """
    # Test connection by listing processes
    result = _run_frida_command([_frida_cmd('frida-ps'), '-H', host], timeout=10)
    
    if result["status"] == "success":
        _remote_devices[host] = f"Remote device at {host}"
        return {
            "status": "success",
            "host": host,
            "message": f"Successfully connected to remote device at {host}"
        }
    else:
        return {
            "status": "error",
            "host": host,
            "error": result.get("error") or result.get("stderr", "Connection failed")
        }


@mcp.tool()
def list_remote_devices() -> Dict[str, Any]:
    """List all configured remote devices."""
    return {
        "status": "success",
        "devices": [
            {"host": host, "description": desc}
            for host, desc in _remote_devices.items()
        ]
    }


# ============================================================================
# Process Tools
# ============================================================================

@mcp.tool()
def list_processes(
    device: Optional[str] = None,
    applications_only: bool = False
) -> Dict[str, Any]:
    """
    List processes running on a device.
    
    Args:
        device: Device identifier. Can be:
                - None for local device
                - "usb" for USB device
                - "host:port" for remote device (e.g., "192.168.4.220:9999")
        applications_only: If True, only list applications (uses frida-ps -a)
    
    Returns:
        List of processes with PID and name.
    """
    args = [_frida_cmd('frida-ps')] + _get_device_args(device)
    if applications_only:
        args.append('-a')
    
    result = _run_frida_command(args, timeout=30)
    
    if result["status"] != "success":
        return result
    
    processes = []
    lines = result["stdout"].strip().split('\n')
    
    # Parse output - format varies slightly between -a and regular
    for line in lines[1:]:  # Skip header
        if not line.strip():
            continue
        parts = line.split(None, 1)  # Split on first whitespace
        if len(parts) >= 2:
            try:
                pid = int(parts[0])
                name = parts[1].strip()
                processes.append({"pid": pid, "name": name})
            except ValueError:
                continue
    
    return {
        "status": "success",
        "count": len(processes),
        "processes": processes
    }


@mcp.tool()
def list_installed_apps(
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    List all installed applications on an Android device (not just running ones).
    
    This uses frida-ps -ai to show all installed applications including those
    that are not currently running.
    
    Args:
        device: Device identifier. Can be:
                - None for local device
                - "usb" for USB device
                - "host:port" for remote device (e.g., "192.168.4.220:9999")
    
    Returns:
        List of all installed applications with PID (if running), name, and package identifier.
    """
    args = [_frida_cmd('frida-ps')] + _get_device_args(device) + ['-ai']
    
    result = _run_frida_command(args, timeout=30)
    
    if result["status"] != "success":
        return result
    
    applications = []
    running_count = 0
    lines = result["stdout"].strip().split('\n')
    
    # Parse output - format: PID  Name  Identifier
    for line in lines[1:]:  # Skip header
        if not line.strip() or line.startswith('---'):
            continue
        
        # Split the line - PID can be a number or '-' for not running
        parts = line.split()
        if len(parts) >= 3:
            pid_str = parts[0]
            # Name can have spaces, identifier is always the last part
            identifier = parts[-1]
            name = ' '.join(parts[1:-1])
            
            if pid_str == '-':
                pid = None
                running = False
            else:
                try:
                    pid = int(pid_str)
                    running = True
                    running_count += 1
                except ValueError:
                    pid = None
                    running = False
            
            applications.append({
                "pid": pid,
                "name": name,
                "identifier": identifier,
                "running": running
            })
    
    return {
        "status": "success",
        "total": len(applications),
        "running": running_count,
        "stopped": len(applications) - running_count,
        "applications": applications
    }


@mcp.tool()
def spawn_process(
    identifier: str,
    device: Optional[str] = None,
    paused: bool = True
) -> Dict[str, Any]:
    """
    Spawn a new process.
    
    Args:
        identifier: Application identifier (e.g., "com.example.app")
        device: Device identifier (None for local, "usb", or "host:port")
        paused: If True, process starts paused (default). Use resume_process to continue.
    
    Returns:
        PID of the spawned process.
    """
    # Note: frida CLI with -f always spawns and runs when using -e
    # The process will continue after script execution
    args = [_frida_cmd('frida')] + _get_device_args(device) + ['-f', identifier]
    
    # We need to spawn and quickly exit to get the PID
    # Use a script that just prints the PID
    args.extend(['-e', 'console.log("PID:" + Process.id);', '-q'])
    
    result = _run_frida_command(args, timeout=30)
    
    if result["status"] != "success":
        return result
    
    # Parse PID from output
    output = result["stdout"] + result["stderr"]
    pid_match = re.search(r'PID:(\d+)', output)
    
    if pid_match:
        return {
            "status": "success",
            "pid": int(pid_match.group(1)),
            "identifier": identifier,
            "paused": paused
        }
    else:
        # Try to find PID in spawn message
        spawn_match = re.search(r'Spawned.*pid=(\d+)', output)
        if spawn_match:
            return {
                "status": "success", 
                "pid": int(spawn_match.group(1)),
                "identifier": identifier,
                "paused": paused
            }
        
        return {
            "status": "error",
            "error": "Could not determine PID of spawned process",
            "output": output
        }


@mcp.tool()
def kill_process(
    target: int,
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    Kill a process by PID.
    
    Args:
        target: Process ID to kill
        device: Device identifier
    """
    args = [_frida_cmd('frida-kill')] + _get_device_args(device) + [str(target)]
    result = _run_frida_command(args, timeout=10)
    
    if result["status"] == "success" or "killed" in result.get("stdout", "").lower():
        return {
            "status": "success",
            "message": f"Process {target} killed"
        }
    
    return result


# ============================================================================
# Script Execution Tools
# ============================================================================

@mcp.tool()
def execute_script(
    target: str,
    script: str,
    device: Optional[str] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Execute a JavaScript script in a process (one-shot execution).
    
    This is the main tool for running Frida scripts. The script has full access
    to Frida's JavaScript API including Java.* and ObjC.* bridges.
    
    Args:
        target: Process name or PID to attach to
        script: JavaScript code to execute. Use console.log() for output.
        device: Device identifier (None for local, "usb", or "host:port")
        timeout: Maximum execution time in seconds
    
    Returns:
        Script output from console.log() calls.
    
    Example scripts:
        # Check Java availability
        "console.log('Java available:', Java.available);"
        
        # List loaded classes
        "Java.perform(() => { console.log(Java.enumerateLoadedClassesSync().length + ' classes'); });"
        
        # Hook a method
        '''
        Java.perform(() => {
            var Activity = Java.use('android.app.Activity');
            Activity.onCreate.implementation = function(bundle) {
                console.log('onCreate called!');
                this.onCreate(bundle);
            };
        });
        '''
    """
    # Wrap script to ensure output is captured
    wrapped_script = f"""
try {{
    {script}
}} catch(e) {{
    console.log('ERROR: ' + e.message);
    console.log(e.stack);
}}
// Give time for async operations
setTimeout(function() {{}}, 500);
"""
    
    args = [_frida_cmd('frida')] + _get_device_args(device)
    
    # Determine if target is PID or name
    try:
        pid = int(target)
        args.extend(['-p', str(pid)])
    except ValueError:
        args.extend(['-n', target])
    
    args.extend(['-e', wrapped_script, '-q'])
    
    result = _run_frida_command(args, timeout=timeout)
    
    # Process output
    output = result.get("stdout", "")
    errors = result.get("stderr", "")
    
    # Filter out frida noise
    output_lines = [
        line for line in output.split('\n')
        if line.strip() and not line.startswith('     ') and 'Frida' not in line
    ]
    
    if result["status"] == "success":
        return {
            "status": "success",
            "output": '\n'.join(output_lines),
            "errors": errors if errors.strip() else None
        }
    else:
        return {
            "status": "error",
            "output": '\n'.join(output_lines),
            "error": result.get("error") or errors
        }


@mcp.tool()
def execute_script_spawn(
    identifier: str,
    script: str,
    device: Optional[str] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Spawn a process and execute a script in it.
    
    This spawns the application, injects the script at startup, and captures output.
    Useful for hooking early initialization code.
    
    Args:
        identifier: Application identifier (e.g., "com.example.app")
        script: JavaScript code to execute
        device: Device identifier
        timeout: Maximum execution time in seconds
    
    Returns:
        Script output and spawned process PID.
    """
    wrapped_script = f"""
console.log('SPAWN_PID:' + Process.id);
try {{
    {script}
}} catch(e) {{
    console.log('ERROR: ' + e.message);
    console.log(e.stack);
}}
setTimeout(function() {{}}, 1000);
"""
    
    # Note: frida -f spawns and auto-resumes when using -e
    # No --no-pause flag needed (it doesn't exist)
    args = [_frida_cmd('frida')] + _get_device_args(device) + ['-f', identifier]
    args.extend(['-e', wrapped_script, '-q'])
    
    result = _run_frida_command(args, timeout=timeout)
    
    output = result.get("stdout", "") + result.get("stderr", "")
    
    # Extract PID
    pid = None
    pid_match = re.search(r'SPAWN_PID:(\d+)', output)
    if pid_match:
        pid = int(pid_match.group(1))
    
    # Filter output
    output_lines = [
        line for line in output.split('\n')
        if line.strip() 
        and not line.startswith('SPAWN_PID:')
        and 'Spawned' not in line
        and 'Frida' not in line
    ]
    
    return {
        "status": result["status"],
        "pid": pid,
        "identifier": identifier,
        "output": '\n'.join(output_lines),
        "error": result.get("error") if result["status"] != "success" else None
    }


# ============================================================================
# Interactive Session Tools
# ============================================================================

def _session_output_reader(session: FridaSession):
    """Background thread to read session output."""
    try:
        while True:
            if session.process.stdout:
                line = session.process.stdout.readline()
                if not line:
                    break
                with session.lock:
                    session.output_buffer.append(line)
                    session.last_activity = time.time()
                    if '>' in line or 'attached' in line.lower():
                        session.is_ready = True
    except Exception:
        pass


@mcp.tool()
def create_session(
    target: str,
    device: Optional[str] = None,
    spawn: bool = False
) -> Dict[str, Any]:
    """
    Create an interactive Frida session.
    
    This starts a persistent frida process that you can send multiple commands to.
    Use run_in_session() to execute code and close_session() when done.
    
    Args:
        target: Process name, PID, or app identifier (if spawn=True)
        device: Device identifier
        spawn: If True, spawn the app instead of attaching
    
    Returns:
        Session ID to use with other session commands.
    """
    global _session_counter
    _session_counter += 1
    session_id = f"session_{_session_counter}_{int(time.time())}"
    
    args = [_frida_cmd('frida')] + _get_device_args(device)
    
    if spawn:
        args.extend(['-f', target, '--no-pause'])
    else:
        try:
            pid = int(target)
            args.extend(['-p', str(pid)])
        except ValueError:
            args.extend(['-n', target])
    
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        session = FridaSession(
            session_id=session_id,
            device=device,
            target=target,
            process=process
        )
        
        # Start output reader thread
        reader_thread = threading.Thread(
            target=_session_output_reader,
            args=(session,),
            daemon=True
        )
        reader_thread.start()
        
        # Wait for session to be ready
        start_time = time.time()
        while not session.is_ready and time.time() - start_time < 10:
            time.sleep(0.1)
            if process.poll() is not None:
                break
        
        if process.poll() is not None:
            # Process died
            with session.lock:
                output = ''.join(session.output_buffer)
            return {
                "status": "error",
                "error": "Frida process terminated unexpectedly",
                "output": output
            }
        
        _sessions[session_id] = session
        
        return {
            "status": "success",
            "session_id": session_id,
            "target": target,
            "device": device,
            "spawned": spawn,
            "message": "Session created. Use run_in_session() to execute code."
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def run_in_session(
    session_id: str,
    code: str,
    wait_time: float = 1.0
) -> Dict[str, Any]:
    """
    Execute JavaScript code in an existing session.
    
    Args:
        session_id: Session ID from create_session()
        code: JavaScript code to execute
        wait_time: Time to wait for output (seconds)
    
    Returns:
        Output from the code execution.
    """
    if session_id not in _sessions:
        return {
            "status": "error",
            "error": f"Session {session_id} not found"
        }
    
    session = _sessions[session_id]
    
    if session.process.poll() is not None:
        del _sessions[session_id]
        return {
            "status": "error", 
            "error": "Session has terminated"
        }
    
    # Clear output buffer
    with session.lock:
        session.output_buffer.clear()
    
    # Send code to frida REPL
    try:
        session.process.stdin.write(code + '\n')
        session.process.stdin.flush()
    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to send code: {e}"
        }
    
    # Wait for output
    time.sleep(wait_time)
    
    # Collect output
    with session.lock:
        output = ''.join(session.output_buffer)
        session.output_buffer.clear()
    
    # Filter noise
    output_lines = [
        line for line in output.split('\n')
        if line.strip() and not line.strip().startswith('[') and line.strip() != '>'
    ]
    
    return {
        "status": "success",
        "output": '\n'.join(output_lines)
    }


@mcp.tool()
def close_session(session_id: str) -> Dict[str, Any]:
    """
    Close an interactive Frida session.
    
    Args:
        session_id: Session ID to close
    """
    if session_id not in _sessions:
        return {
            "status": "error",
            "error": f"Session {session_id} not found"
        }
    
    session = _sessions[session_id]
    
    try:
        if session.process.poll() is None:
            session.process.stdin.write('exit\n')
            session.process.stdin.flush()
            session.process.wait(timeout=5)
    except Exception:
        try:
            session.process.kill()
        except Exception:
            pass
    
    del _sessions[session_id]
    
    return {
        "status": "success",
        "message": f"Session {session_id} closed"
    }


@mcp.tool()
def list_sessions() -> Dict[str, Any]:
    """List all active Frida sessions."""
    sessions = []
    dead_sessions = []
    
    for session_id, session in _sessions.items():
        if session.process.poll() is not None:
            dead_sessions.append(session_id)
        else:
            sessions.append({
                "session_id": session_id,
                "target": session.target,
                "device": session.device,
                "last_activity": session.last_activity
            })
    
    # Clean up dead sessions
    for sid in dead_sessions:
        del _sessions[sid]
    
    return {
        "status": "success",
        "sessions": sessions,
        "count": len(sessions)
    }


# ============================================================================
# Utility Tools
# ============================================================================

@mcp.tool()
def check_java_available(
    target: str,
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    Check if Java bridge is available in a process.
    
    This is useful to verify that the Frida CLI approach works and Java is accessible.
    
    Args:
        target: Process name or PID
        device: Device identifier
    """
    script = """
var result = {
    fridaVersion: Frida.version,
    scriptRuntime: Script.runtime,
    javaAvailable: typeof Java !== 'undefined',
    objcAvailable: typeof ObjC !== 'undefined'
};

if (typeof Java !== 'undefined') {
    result.javaVMAvailable = Java.available;
    if (Java.available) {
        Java.perform(function() {
            result.androidVersion = Java.use('android.os.Build$VERSION').SDK_INT.value;
        });
    }
}

console.log(JSON.stringify(result, null, 2));
"""
    
    return execute_script(target=target, script=script, device=device)


@mcp.tool()
def get_frida_version() -> Dict[str, Any]:
    """Get the installed Frida CLI version."""
    result = _run_frida_command([_frida_cmd('frida'), '--version'])
    
    if result["status"] == "success":
        return {
            "status": "success",
            "version": result["stdout"].strip()
        }
    return result


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Run the MCP server."""
    import sys
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
