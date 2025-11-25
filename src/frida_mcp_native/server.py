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
# RMS Core Tools - Phase 1: App Environment & Class Enumeration
# ============================================================================

@mcp.tool()
def get_app_env_info(
    target: str,
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get application environment information including directories and paths.
    
    Returns information about the app's filesystem paths:
    - Android: mainDirectory, filesDirectory, cacheDirectory, externalCacheDirectory, 
               codeCacheDirectory, obbDir, packageCodePath
    - iOS: mainDirectory, BundlePath, CachesDirectory, DocumentDirectory, LibraryDirectory
    
    Args:
        target: Process name or PID to attach to
        device: Device identifier
    
    Returns:
        Dictionary with app environment paths.
    """
    script = """
(function() {
    var env = {};
    
    // Android
    if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(function() {
            try {
                var ActivityThread = Java.use('android.app.ActivityThread');
                var targetApp = ActivityThread.currentApplication();
                
                if (targetApp != null) {
                    var context = targetApp.getApplicationContext();
                    env = {
                        platform: 'Android',
                        mainDirectory: context.getFilesDir().getParent(),
                        filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
                        cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
                        externalCacheDirectory: context.getExternalCacheDir() ? 
                            context.getExternalCacheDir().getAbsolutePath().toString() : 'N/A',
                        codeCacheDirectory: 'getCodeCacheDir' in context ? 
                            context.getCodeCacheDir().getAbsolutePath().toString() : 'N/A',
                        obbDir: context.getObbDir().getAbsolutePath().toString(),
                        packageCodePath: context.getPackageCodePath().toString().replace("/base.apk", ""),
                        packageName: context.getPackageName()
                    };
                }
            } catch(e) {
                env.error = e.toString();
            }
        });
    }
    // iOS
    else if (typeof ObjC !== 'undefined' && ObjC.available) {
        try {
            var NSUserDomainMask = 1;
            var NSLibraryDirectory = 5;
            var NSDocumentDirectory = 9;
            var NSCachesDirectory = 13;
            
            var NSBundle = ObjC.classes.NSBundle.mainBundle();
            var NSFileManager = ObjC.classes.NSFileManager.defaultManager();
            
            var libPath = NSFileManager.URLsForDirectory_inDomains_(NSLibraryDirectory, NSUserDomainMask)
                .lastObject().path().toString();
            
            env = {
                platform: 'iOS',
                mainDirectory: libPath.replace("Library", ""),
                BundlePath: NSBundle.bundlePath().toString(),
                CachesDirectory: NSFileManager.URLsForDirectory_inDomains_(NSCachesDirectory, NSUserDomainMask)
                    .lastObject().path().toString(),
                DocumentDirectory: NSFileManager.URLsForDirectory_inDomains_(NSDocumentDirectory, NSUserDomainMask)
                    .lastObject().path().toString(),
                LibraryDirectory: libPath,
                bundleIdentifier: NSBundle.bundleIdentifier() ? NSBundle.bundleIdentifier().toString() : 'N/A'
            };
        } catch(e) {
            env.error = e.toString();
        }
    } else {
        env = {error: 'Neither Java nor ObjC runtime available'};
    }
    
    console.log(JSON.stringify(env));
})();
"""
    
    result = execute_script(target=target, script=script, device=device, timeout=15)
    
    if result["status"] == "success":
        try:
            # Parse JSON from output
            output = result.get("output", "")
            # Find JSON in output
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                env_data = json.loads(json_match.group())
                return {
                    "status": "success",
                    "environment": env_data
                }
        except json.JSONDecodeError:
            pass
        
        return {
            "status": "success",
            "environment": result.get("output", "")
        }
    
    return result


@mcp.tool()
def list_files_at_path(
    target: str,
    path: str,
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    List files at a specific path on the device.
    
    Returns file information including:
    - File names
    - Whether each is a file or directory
    - Size, permissions (readable/writable)
    - Last modified date
    
    Args:
        target: Process name or PID to attach to
        path: Path to list files from (e.g., "/data/data/com.example.app")
        device: Device identifier
    
    Returns:
        Dictionary with path info and list of files with attributes.
    """
    # Escape the path for JavaScript
    escaped_path = path.replace('\\', '\\\\').replace("'", "\\'")
    
    script = f"""
(function() {{
    var listResult = {{
        files: {{}},
        path: '{escaped_path}',
        readable: false,
        writable: false,
        error: null
    }};
    
    // Android
    if (typeof Java !== 'undefined' && Java.available) {{
        Java.perform(function() {{
            try {{
                var File = Java.use("java.io.File");
                var currentPath = File.$new('{escaped_path}');
                
                listResult.readable = currentPath.canRead() ? true : false;
                listResult.writable = currentPath.canWrite() ? true : false;
                
                if (!currentPath.exists()) {{
                    listResult.error = 'Path does not exist';
                    console.log(JSON.stringify(listResult));
                    return;
                }}
                
                if (!currentPath.isDirectory()) {{
                    listResult.error = 'Path is not a directory';
                    console.log(JSON.stringify(listResult));
                    return;
                }}
                
                var files = currentPath.listFiles();
                if (files != null) {{
                    for (var i = 0; i < files.length; i++) {{
                        var f = files[i];
                        var name = f.getName().toString();
                        listResult.files[name] = {{
                            fileName: name,
                            isDirectory: f.isDirectory() ? true : false,
                            isFile: f.isFile() ? true : false,
                            isHidden: f.isHidden() ? true : false,
                            size: parseInt(f.length()),
                            lastModified: new Date(f.lastModified()).toISOString().replace('T', ' ').split('.')[0],
                            readable: f.canRead() ? true : false,
                            writable: f.canWrite() ? true : false
                        }};
                    }}
                }}
            }} catch(e) {{
                listResult.error = e.toString();
            }}
        }});
    }}
    // iOS
    else if (typeof ObjC !== 'undefined' && ObjC.available) {{
        try {{
            var NSFileManager = ObjC.classes.NSFileManager.defaultManager();
            var nsPath = ObjC.classes.NSString.stringWithString_('{escaped_path}');
            
            listResult.readable = NSFileManager.isReadableFileAtPath_(nsPath);
            listResult.writable = NSFileManager.isWritableFileAtPath_(nsPath);
            
            if (!listResult.readable) {{
                listResult.error = 'Path is not readable';
                console.log(JSON.stringify(listResult));
                return;
            }}
            
            var contents = NSFileManager.contentsOfDirectoryAtPath_error_('{escaped_path}', NULL);
            if (contents) {{
                var count = contents.count();
                for (var i = 0; i < count; i++) {{
                    var fileName = contents.objectAtIndex_(i).toString();
                    var filePath = '{escaped_path}/' + fileName;
                    var fileNSPath = ObjC.classes.NSString.stringWithString_(filePath);
                    
                    var attrs = NSFileManager.attributesOfItemAtPath_error_(fileNSPath, NULL);
                    var fileInfo = {{
                        fileName: fileName,
                        readable: NSFileManager.isReadableFileAtPath_(fileNSPath),
                        writable: NSFileManager.isWritableFileAtPath_(fileNSPath)
                    }};
                    
                    if (attrs) {{
                        var fileType = attrs.objectForKey_('NSFileType');
                        fileInfo.isDirectory = fileType ? fileType.toString() === 'NSFileTypeDirectory' : false;
                        fileInfo.isFile = !fileInfo.isDirectory;
                        fileInfo.size = attrs.objectForKey_('NSFileSize') ? 
                            parseInt(attrs.objectForKey_('NSFileSize').toString()) : 0;
                        fileInfo.lastModified = attrs.objectForKey_('NSFileModificationDate') ? 
                            attrs.objectForKey_('NSFileModificationDate').toString() : 'N/A';
                        fileInfo.isHidden = attrs.objectForKey_('NSFileExtensionHidden') ? 
                            attrs.objectForKey_('NSFileExtensionHidden').toString() === '1' : false;
                    }}
                    
                    listResult.files[fileName] = fileInfo;
                }}
            }}
        }} catch(e) {{
            listResult.error = e.toString();
        }}
    }} else {{
        listResult.error = 'Neither Java nor ObjC runtime available';
    }}
    
    console.log(JSON.stringify(listResult));
}})();
"""
    
    result = execute_script(target=target, script=script, device=device, timeout=30)
    
    if result["status"] == "success":
        try:
            output = result.get("output", "")
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                file_data = json.loads(json_match.group())
                return {
                    "status": "success",
                    "result": file_data
                }
        except json.JSONDecodeError:
            pass
        
        return {
            "status": "success",
            "result": result.get("output", "")
        }
    
    return result


@mcp.tool()
def load_classes(
    target: str,
    device: Optional[str] = None,
    filter_prefix: Optional[str] = None,
    exclude_androidx: bool = True,
    min_length: int = 5
) -> Dict[str, Any]:
    """
    Enumerate all loaded classes in the application.
    
    This is a core RMS function that lists all classes loaded in the runtime.
    For Android uses Java.enumerateLoadedClassesSync(), for iOS iterates ObjC.classes.
    
    Args:
        target: Process name or PID to attach to
        device: Device identifier
        filter_prefix: Optional prefix to filter classes (e.g., "com.example")
        exclude_androidx: If True, exclude androidx.* classes (default True)
        min_length: Minimum class name length (default 5)
    
    Returns:
        List of class names.
    """
    filter_code = ""
    if filter_prefix:
        escaped_prefix = filter_prefix.replace('\\', '\\\\').replace("'", "\\'").lower()
        filter_code = f"&& className.toLowerCase().startsWith('{escaped_prefix}')"
    
    exclude_code = "&& !className.includes('androidx')" if exclude_androidx else ""
    
    script = f"""
(function() {{
    var result = {{
        platform: 'unknown',
        classes: [],
        count: 0,
        error: null
    }};
    
    // Android
    if (typeof Java !== 'undefined' && Java.available) {{
        result.platform = 'Android';
        Java.perform(function() {{
            try {{
                var classes = Java.enumerateLoadedClassesSync();
                classes.forEach(function(className) {{
                    if (className.length > {min_length} {exclude_code} {filter_code}) {{
                        result.classes.push(className);
                    }}
                }});
                result.count = result.classes.length;
            }} catch(e) {{
                result.error = e.toString();
            }}
        }});
    }}
    // iOS
    else if (typeof ObjC !== 'undefined' && ObjC.available) {{
        result.platform = 'iOS';
        try {{
            for (var className in ObjC.classes) {{
                if (ObjC.classes.hasOwnProperty(className) && 
                    className.length > {min_length} {filter_code}) {{
                    result.classes.push(className);
                }}
            }}
            result.count = result.classes.length;
        }} catch(e) {{
            result.error = e.toString();
        }}
    }} else {{
        result.error = 'Neither Java nor ObjC runtime available';
    }}
    
    console.log(JSON.stringify(result));
}})();
"""
    
    result = execute_script(target=target, script=script, device=device, timeout=60)
    
    if result["status"] == "success":
        try:
            output = result.get("output", "")
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                class_data = json.loads(json_match.group())
                return {
                    "status": "success",
                    "platform": class_data.get("platform", "unknown"),
                    "count": class_data.get("count", 0),
                    "classes": class_data.get("classes", []),
                    "error": class_data.get("error")
                }
        except json.JSONDecodeError:
            pass
        
        return {
            "status": "success",
            "output": result.get("output", "")
        }
    
    return result


@mcp.tool()
def load_classes_with_filter(
    target: str,
    filter_pattern: str,
    device: Optional[str] = None,
    is_regex: bool = False,
    is_case_sensitive: bool = False,
    match_whole: bool = False
) -> Dict[str, Any]:
    """
    Enumerate loaded classes with advanced filtering options.
    
    This extends load_classes() with regex support, case sensitivity control,
    and whole-word matching. Supports multiple filters separated by comma.
    
    Args:
        target: Process name or PID to attach to
        filter_pattern: Filter string or regex pattern. Multiple filters can be comma-separated.
        device: Device identifier
        is_regex: If True, treat filter_pattern as a regex
        is_case_sensitive: If True, matching is case-sensitive
        match_whole: If True, match entire class name (not just prefix/contains)
    
    Returns:
        List of matching class names.
    
    Examples:
        # Find all classes starting with "com.example"
        load_classes_with_filter(target, "com.example")
        
        # Regex: find classes containing "Security" or "Crypto"  
        load_classes_with_filter(target, "Security|Crypto", is_regex=True)
        
        # Multiple filters (comma-separated)
        load_classes_with_filter(target, "com.example,com.myapp")
    """
    escaped_filter = filter_pattern.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"')
    
    script = f"""
(function() {{
    var result = {{
        platform: 'unknown',
        classes: [],
        count: 0,
        filter: '{escaped_filter}',
        error: null
    }};
    
    var filterPattern = '{escaped_filter}';
    var isRegex = {'true' if is_regex else 'false'};
    var isCase = {'true' if is_case_sensitive else 'false'};
    var isWhole = {'true' if match_whole else 'false'};
    
    function matchesFilter(className) {{
        var originalClassName = className;
        var testName = isCase ? className : className.toLowerCase();
        var testFilter = isCase ? filterPattern : filterPattern.toLowerCase();
        
        if (isRegex) {{
            try {{
                var regex = new RegExp(testFilter, isCase ? '' : 'i');
                return regex.test(className);
            }} catch(e) {{
                return false;
            }}
        }} else {{
            // Support comma-separated filters
            var filters = testFilter.split(',');
            for (var i = 0; i < filters.length; i++) {{
                var f = filters[i].trim();
                if (f.length === 0) continue;
                
                if (isWhole) {{
                    if (testName === f) return true;
                }} else {{
                    if (testName.indexOf(f) !== -1) return true;
                }}
            }}
            return false;
        }}
    }}
    
    // Android
    if (typeof Java !== 'undefined' && Java.available) {{
        result.platform = 'Android';
        Java.perform(function() {{
            try {{
                var classes = Java.enumerateLoadedClassesSync();
                classes.forEach(function(className) {{
                    if (className.length > 3 && matchesFilter(className)) {{
                        result.classes.push(className);
                    }}
                }});
                result.count = result.classes.length;
            }} catch(e) {{
                result.error = e.toString();
            }}
        }});
    }}
    // iOS
    else if (typeof ObjC !== 'undefined' && ObjC.available) {{
        result.platform = 'iOS';
        try {{
            for (var className in ObjC.classes) {{
                if (ObjC.classes.hasOwnProperty(className) && 
                    className.length > 3 && matchesFilter(className)) {{
                    result.classes.push(className);
                }}
            }}
            result.count = result.classes.length;
        }} catch(e) {{
            result.error = e.toString();
        }}
    }} else {{
        result.error = 'Neither Java nor ObjC runtime available';
    }}
    
    console.log(JSON.stringify(result));
}})();
"""
    
    result = execute_script(target=target, script=script, device=device, timeout=60)
    
    if result["status"] == "success":
        try:
            output = result.get("output", "")
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                class_data = json.loads(json_match.group())
                return {
                    "status": "success",
                    "platform": class_data.get("platform", "unknown"),
                    "count": class_data.get("count", 0),
                    "filter": filter_pattern,
                    "classes": class_data.get("classes", []),
                    "error": class_data.get("error")
                }
        except json.JSONDecodeError:
            pass
    
    return result


@mcp.tool()
def load_methods(
    target: str,
    class_names: List[str],
    device: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get all declared methods for specified classes.
    
    Returns method information including name, arguments (in Smali notation for Android),
    and a UI-friendly signature. This is essential for hooking methods with overloads.
    
    Args:
        target: Process name or PID to attach to
        class_names: List of fully qualified class names to inspect
        device: Device identifier
    
    Returns:
        Dictionary mapping class names to their methods with signatures.
        
    Example output:
        {
            "com.example.MyClass": [
                {"name": "myMethod", "args": '"int","java.lang.String"', "ui_name": "void myMethod(int, String)"},
                ...
            ]
        }
    """
    # Serialize class names for JavaScript
    classes_json = json.dumps(class_names)
    
    script = f"""
(function() {{
    var result = {{
        platform: 'unknown',
        methods: {{}},
        classCount: 0,
        methodCount: 0,
        errors: [],
        error: null
    }};
    
    var classNames = {classes_json};
    
    // Android
    if (typeof Java !== 'undefined' && Java.available) {{
        result.platform = 'Android';
        Java.perform(function() {{
            classNames.forEach(function(className) {{
                var classMethods = [];
                try {{
                    var jClass = Java.use(className);
                    var methods = jClass.class.getDeclaredMethods();
                    
                    for (var i = 0; i < methods.length; i++) {{
                        var m = methods[i].toString();
                        
                        // Remove throws clause
                        var throwsIdx = m.indexOf(' throws ');
                        if (throwsIdx !== -1) {{
                            m = m.substring(0, throwsIdx);
                        }}
                        
                        // Remove generics
                        while (m.indexOf('<') !== -1) {{
                            m = m.replace(/<[^>]*>/g, '');
                        }}
                        
                        // Extract arguments from parentheses
                        var argsMatch = m.match(/\\(([^)]*)\\)/);
                        var argsStr = argsMatch ? argsMatch[1].trim() : '';
                        
                        // Extract method name (between last dot and opening paren)
                        var parenIdx = m.indexOf('(');
                        var beforeParen = m.substring(0, parenIdx);
                        var lastDot = beforeParen.lastIndexOf('.');
                        var methodName = beforeParen.substring(lastDot + 1);
                        
                        // Convert args to Smali notation
                        var smaliArgs = '';
                        if (argsStr.length === 0) {{
                            smaliArgs = '""';
                        }} else {{
                            var args = argsStr.split(',');
                            var convertedArgs = [];
                            
                            for (var j = 0; j < args.length; j++) {{
                                var arg = args[j].trim();
                                
                                // Handle arrays
                                var arrayPrefix = '';
                                while (arg.endsWith('[]')) {{
                                    arrayPrefix += '[';
                                    arg = arg.substring(0, arg.length - 2);
                                }}
                                
                                // Convert primitives to Smali notation
                                var smaliArg = arg;
                                if (arg === 'boolean') smaliArg = 'Z';
                                else if (arg === 'byte') smaliArg = 'B';
                                else if (arg === 'char') smaliArg = 'C';
                                else if (arg === 'double') smaliArg = 'D';
                                else if (arg === 'float') smaliArg = 'F';
                                else if (arg === 'int') smaliArg = 'I';
                                else if (arg === 'long') smaliArg = 'J';
                                else if (arg === 'short') smaliArg = 'S';
                                else if (arg === 'void') smaliArg = 'V';
                                else if (arrayPrefix.length > 0 && arg.indexOf('.') !== -1) {{
                                    smaliArg = 'L' + arg.replace(/\\./g, '/') + ';';
                                }}
                                
                                convertedArgs.push('"' + arrayPrefix + smaliArg + '"');
                            }}
                            smaliArgs = convertedArgs.join(',');
                        }}
                        
                        // Create object with string properties only
                        var info = {{
                            name: String(methodName),
                            args: String(smaliArgs),
                            ui_name: String(methods[i].toString().replace(className + '.', ''))
                        }};
                        
                        classMethods.push(info);
                    }}
                    
                    result.methods[className] = classMethods;
                    result.methodCount += classMethods.length;
                }} catch(e) {{
                    result.errors.push(className + ': ' + e.toString());
                    result.methods[className] = [];
                }}
            }});
            result.classCount = classNames.length;
        }});
    }}
    // iOS
    else if (typeof ObjC !== 'undefined' && ObjC.available) {{
        result.platform = 'iOS';
        try {{
            classNames.forEach(function(className) {{
                var classMethods = [];
                try {{
                    if (ObjC.classes.hasOwnProperty(className)) {{
                        var methods = ObjC.classes[className].$ownMethods;
                        
                        methods.forEach(function(methodName) {{
                            var info = {{
                                name: String(methodName),
                                args: null,
                                ui_name: String(methodName)
                            }};
                            
                            try {{
                                var method = ObjC.classes[className][methodName];
                                info.returnType = String(method.returnType);
                                var argTypes = method.argumentTypes;
                                if (argTypes && argTypes.length >= 2) {{
                                    argTypes = argTypes.slice(2);
                                }}
                                info.argumentTypes = argTypes ? argTypes.map(function(t) {{ return String(t); }}) : [];
                                info.ui_name = '(' + info.returnType + ') ' + methodName + '(' + info.argumentTypes.join(', ') + ')';
                            }} catch(e) {{
                                // Method introspection failed, keep basic info
                            }}
                            
                            classMethods.push(info);
                        }});
                    }}
                    
                    result.methods[className] = classMethods;
                    result.methodCount += classMethods.length;
                }} catch(e) {{
                    result.errors.push(className + ': ' + e.toString());
                    result.methods[className] = [];
                }}
            }});
            result.classCount = classNames.length;
        }} catch(e) {{
            result.error = e.toString();
        }}
    }} else {{
        result.error = 'Neither Java nor ObjC runtime available';
    }}
    
    console.log(JSON.stringify(result));
}})();
"""
    
    result = execute_script(target=target, script=script, device=device, timeout=120)
    
    if result["status"] == "success":
        try:
            output = result.get("output", "")
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                method_data = json.loads(json_match.group())
                return {
                    "status": "success",
                    "platform": method_data.get("platform", "unknown"),
                    "classCount": method_data.get("classCount", 0),
                    "methodCount": method_data.get("methodCount", 0),
                    "methods": method_data.get("methods", {}),
                    "errors": method_data.get("errors", [])
                }
        except json.JSONDecodeError:
            pass
    
    return result


# ============================================================================
# Phase 3: Hook Template Generation Tools
# ============================================================================

# Default templates (same as RMS)
ANDROID_HOOK_TEMPLATE = '''
Java.perform(function () {
    var classname = "{className}";
    var classmethod = "{classMethod}";
    var methodsignature = "{methodSignature}";
    var hookclass = Java.use(classname);
    
    //{methodSignature}
    hookclass.{classMethod}.{overload}implementation = function ({args}) {
        send("[Call_Stack]\\nClass: " +classname+"\\nMethod: "+methodsignature+"\\n");
        var ret = this.{classMethod}({args});
        
        var s="";
        s=s+"[Hook_Stack]\\n"
        s=s+"Class: " +classname+"\\n"
        s=s+"Method: " +methodsignature+"\\n"
        s=s+"Called by: "+Java.use('java.lang.Exception').$new().getStackTrace().toString().split(',')[1]+"\\n"
        s=s+"Input: "+eval({argsEval})+"\\n";
        s=s+"Output: "+ret+"\\n";
        //uncomment the line below to print StackTrace
        //s=s+"StackTrace: "+Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()).replace('java.lang.Exception','') +"\\n";

        send(s);
                
        return ret;
    };
});
'''

IOS_HOOK_TEMPLATE = '''
var classname = "{className}";
var classmethod = "{classMethod}";
var methodsignature = "{methodSignature}";
try {
  var hook = eval('ObjC.classes["' + classname + '"]["' + classmethod + '"]');
 
  //{methodSignature}
  Interceptor.attach(hook.implementation, {
    onEnter: function (args) {
      send("[Call_Stack]\\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
      this.s = ""
      this.s = this.s + "[Hook_Stack]\\n"
      this.s = this.s + "Class: " + classname + "\\n"
      this.s = this.s + "Method: " + methodsignature + "\\n"
      if (classmethod.indexOf(":") !== -1) {
        var params = classmethod.split(":");
        params[0] = params[0].split(" ")[1];
        for (var i = 0; i < params.length - 1; i++) {
          try {
            this.s = this.s + "Input: " + params[i] + ": " + new ObjC.Object(args[2 + i]).toString() + "\\n";
          } catch (e) {
            this.s = this.s + "Input: " + params[i] + ": " + args[2 + i].toString() + "\\n";
          }
        }
      }
    },

    //{methodSignature}
    onLeave: function (retval) {
      this.s = this.s + "Output: " + retval.toString() + "\\n";
      //uncomment the lines below to replace retvalue
      //retval.replace(0);  

      //uncomment the line below to print StackTrace
      //this.s = this.s + "StackTrace: \\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + "\\n";
      send(this.s);
    }
  });
} catch (err) {
  send("[!] Exception: " + err.message);
  send("Not able to hook \\nClass: " + classname + "\\nMethod: " + methodsignature + "\\n");
}
'''

ANDROID_HEAP_SEARCH_TEMPLATE = '''
Java.performNow(function () {
    var classname = "{className}"
    var classmethod = "{classMethod}";
    var methodsignature = "{methodSignature}";

    Java.choose(classname, {
        onMatch: function (instance) {
            try 
            {
                var returnValue;
                //{methodSignature}
                returnValue = instance.{classMethod}({args}); //<-- replace v[i] with the value that you want to pass

                //Output
                var s = "";
                s=s+"[Heap_Search]\\n"
                s=s + "[*] Heap Search - START\\n"

                s=s + "Instance Found: " + instance.toString() + "\\n";
                s=s + "Calling method: \\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + methodsignature + "\\n"
                s=s + "-->Output: " + returnValue + "\\n";

                s = s + "[*] Heap Search - END\\n"

                send(s);
            } 
            catch (err) 
            {
                var s = "";
                s=s+"[Heap_Search]\\n"
                s=s + "[*] Heap Search - START\\n"
                s=s + "Instance NOT Found or Exception while calling the method\\n";
                s=s + "   Class: " + classname + "\\n"
                s=s + "   Method: " + methodsignature + "\\n"
                s=s + "-->Exception: " + err + "\\n"
                s=s + "[*] Heap Search - END\\n"
                send(s)
            }

        }
    });

});
'''

IOS_HEAP_SEARCH_TEMPLATE = '''
var classname = "{className}";
var classmethod = "{classMethod}";
var methodsignature = "{methodSignature}";

ObjC.choose(ObjC.classes[classname], {
  onMatch: function (instance) {
    try
    {   
        var returnValue;
        //{methodSignature}
        returnValue = instance[classmethod](); //<-- insert args if needed

        var s=""
        s=s+"[Heap_Search]\\n"
        s=s + "[*] Heap Search - START\\n"
        s=s+"Instance Found: " + instance.toString() + "\\n";
        s=s+"Calling method: \\n";
        s=s+"   Class: " + classname + "\\n"
        s=s+"   Method: " + methodsignature + "\\n"
        s=s+"-->Output: " + returnValue + "\\n";

        s=s+"[*] Heap Search - END\\n"
        send(s);
        
    }catch(err)
    {
        var s = "";
        s=s+"[Heap_Search]\\n"
        s=s + "[*] Heap Search - START\\n"
        s=s + "Instance NOT Found or Exception while calling the method\\n";
        s=s + "   Class: " + classname + "\\n"
        s=s + "   Method: " + methodsignature + "\\n"
        s=s + "-->Exception: " + err + "\\n"
        s=s + "[*] Heap Search - END\\n"
        send(s)
    }
  },
  onComplete: function () {
  }
});
'''


def _generate_args_string(args_count: int) -> str:
    """Generate v0, v1, v2... argument string"""
    if args_count == 0:
        return ""
    return ",".join([f"v{i}" for i in range(args_count)])


@mcp.tool()
def generate_hook_template(
    classes: List[str],
    methods: Dict[str, List[Dict[str, str]]],
    platform: str = "android",
    custom_template: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate Frida hook code templates for specified classes and methods.
    
    This generates ready-to-use JavaScript code that can be executed with execute_script
    or modified before execution. Does NOT execute the hooks - only generates code.
    
    Args:
        classes: List of class names to generate hooks for
        methods: Dictionary mapping class names to their methods (from load_methods output)
                 Each method should have: name, args, ui_name
        platform: Target platform - "android" or "ios"
        custom_template: Optional custom template string with placeholders:
                        {className}, {classMethod}, {methodSignature}, {overload}, {args}
    
    Returns:
        Dictionary with generated hook code and metadata
        
    Example:
        # First get methods using load_methods
        methods_result = load_methods(target, ["com.example.MyClass"], device)
        
        # Then generate hooks
        hooks = generate_hook_template(
            classes=["com.example.MyClass"],
            methods=methods_result["methods"],
            platform="android"
        )
        
        # Execute the generated code
        execute_script(target, hooks["code"], device)
    """
    try:
        # Select template based on platform
        if custom_template:
            template = custom_template
        elif platform.lower() == "ios":
            template = IOS_HOOK_TEMPLATE
        else:
            template = ANDROID_HOOK_TEMPLATE
        
        generated_code = ""
        hooks_generated = 0
        
        for class_name in classes:
            if class_name not in methods:
                continue
                
            for method in methods[class_name]:
                t = template
                method_name = method.get("name", "")
                method_args = method.get("args", '""')
                method_ui_name = method.get("ui_name", method_name)
                
                # Replace placeholders
                t = t.replace("{className}", class_name)
                t = t.replace("{classMethod}", method_name)
                t = t.replace("{classMethod}", method_name)
                t = t.replace("{classMethod}", method_name)
                t = t.replace("{methodSignature}", method_ui_name)
                t = t.replace("{methodSignature}", method_ui_name)
                
                # Handle overload and args
                if method_args != '""' and method_args:
                    # Has arguments
                    t = t.replace("{overload}", f"overload({method_args}).")
                    
                    # Count args
                    args_count = len(method_args.split(","))
                    args_str = _generate_args_string(args_count)
                    
                    t = t.replace("{args}", args_str)
                    t = t.replace("{args}", args_str)
                    t = t.replace("{argsEval}", args_str if args_str else '""')
                else:
                    # No arguments
                    t = t.replace("{overload}", "overload().")
                    t = t.replace("{args}", "")
                    t = t.replace("{args}", "")
                    t = t.replace("{argsEval}", '""')
                
                generated_code += t + "\n"
                hooks_generated += 1
        
        return {
            "status": "success",
            "platform": platform,
            "classCount": len(classes),
            "hooksGenerated": hooks_generated,
            "code": generated_code,
            "note": "Use execute_script() to run this code, or modify it first as needed"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def heap_search_template(
    classes: List[str],
    methods: Dict[str, List[Dict[str, str]]],
    platform: str = "android",
    custom_template: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate Frida heap search code templates for specified classes and methods.
    
    This generates code that searches for existing instances of classes in the heap
    and calls methods on them. Useful for interacting with already-instantiated objects.
    
    Args:
        classes: List of class names to search for in heap
        methods: Dictionary mapping class names to their methods (from load_methods output)
                 Each method should have: name, args, ui_name
        platform: Target platform - "android" or "ios"
        custom_template: Optional custom template string with placeholders
    
    Returns:
        Dictionary with generated heap search code and metadata
        
    Example:
        # Get methods first
        methods_result = load_methods(target, ["com.example.Singleton"], device)
        
        # Generate heap search code
        heap_code = heap_search_template(
            classes=["com.example.Singleton"],
            methods=methods_result["methods"],
            platform="android"
        )
        
        # Modify args in the code if needed, then execute
        execute_script(target, heap_code["code"], device)
    
    Note:
        The generated code uses placeholder arguments (v0, v1, etc.)
        You may need to replace these with actual values before execution.
    """
    try:
        # Select template based on platform
        if custom_template:
            template = custom_template
        elif platform.lower() == "ios":
            template = IOS_HEAP_SEARCH_TEMPLATE
        else:
            template = ANDROID_HEAP_SEARCH_TEMPLATE
        
        generated_code = ""
        templates_generated = 0
        
        for class_name in classes:
            if class_name not in methods:
                continue
                
            for method in methods[class_name]:
                t = template
                method_name = method.get("name", "")
                method_args = method.get("args", '""')
                method_ui_name = method.get("ui_name", method_name)
                
                # Replace placeholders
                t = t.replace("{className}", class_name)
                t = t.replace("{classMethod}", method_name)
                t = t.replace("{classMethod}", method_name)
                t = t.replace("{methodSignature}", method_ui_name)
                t = t.replace("{methodSignature}", method_ui_name)
                
                # Handle args
                if method_args != '""' and method_args:
                    # Has arguments
                    args_count = len(method_args.split(","))
                    args_str = _generate_args_string(args_count)
                    t = t.replace("{args}", args_str)
                else:
                    # No arguments
                    t = t.replace("{args}", "")
                
                generated_code += t + "\n"
                templates_generated += 1
        
        return {
            "status": "success",
            "platform": platform,
            "classCount": len(classes),
            "templatesGenerated": templates_generated,
            "code": generated_code,
            "note": "Replace v0, v1, etc. with actual values before execution. Use execute_script() to run."
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }



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
