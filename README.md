# Frida MCP Native

MCP server para Frida que usa el CLI nativo de Frida en lugar de las librerías de Python o npm.

## ¿Por qué?

A partir de Frida 17, el bridge de `Java` ya no está incluido en el runtime de GumJS. Esto afecta a:
- `python-frida` (pip)
- `frida` (npm/Node.js)

Sin embargo, el CLI de Frida (`frida`, `frida-ps`, etc.) **sí incluye el bridge de Java** para el REPL y frida-trace.

Este MCP server usa directamente los comandos CLI de Frida via subprocess, lo que permite:
- ✅ Acceso completo a `Java.*` API en Android
- ✅ Acceso completo a `ObjC.*` API en iOS
- ✅ Compatible con Android 16 + Frida 17.5.1
- ✅ Sin dependencias de python-frida o npm frida

## Requisitos

- Python 3.10+
- Frida CLI tools instalados (`pip install frida-tools` o descarga desde GitHub releases)
- frida-server corriendo en el dispositivo target

## Instalación

```bash
cd frida-mcp-native
pipx install .
```

## Uso con Claude Desktop / VS Code

Agregar a tu configuración de MCP:

```json
{
  "mcpServers": {
    "frida-native": {
      "command": "frida-mcp-native"
    }
  }
}
```

## Herramientas disponibles (26 tools)

### Dispositivos
- `list_devices` - Lista dispositivos disponibles
- `add_remote_device` - Conecta a un dispositivo remoto (frida-server)
- `list_remote_devices` - Lista dispositivos remotos configurados

### Procesos
- `list_processes` - Lista procesos en un dispositivo
- `list_installed_apps` - Lista todas las apps instaladas (no solo las en ejecución)
- `spawn_process` - Inicia una aplicación
- `kill_process` - Termina un proceso

### Scripting
- `execute_script` - Ejecuta código JavaScript en un proceso (one-shot)
- `execute_script_spawn` - Spawn + script (para hooks tempranos)
- `create_session` - Crea una sesión interactiva para múltiples comandos
- `run_in_session` - Ejecuta código en una sesión existente
- `close_session` - Cierra una sesión
- `list_sessions` - Lista sesiones activas
- `check_java_available` - Verifica si Java bridge está disponible

### RMS Functions - Análisis de Apps (Phase 1-2)
- `get_app_env_info` - Obtiene rutas y directorios de la app
- `list_files_at_path` - Lista archivos en un path del dispositivo
- `load_classes` - Enumera todas las clases cargadas
- `load_classes_with_filter` - Enumera clases con filtros avanzados (regex, case-sensitive)
- `load_methods` - Obtiene métodos de clases específicas con sus firmas

### RMS Functions - Hook Templates (Phase 3)
- `generate_hook_template` - Genera código de hooks para clases/métodos
- `heap_search_template` - Genera código para buscar instancias en heap

### RMS Functions - Live Hooking (Phase 4)
- `hook_classes_and_methods` - Instala hooks en tiempo real

### RMS Functions - API Monitor (Phase 5) 🆕
- `list_api_categories` - Lista categorías de APIs disponibles para monitorear
- `api_monitor` - Monitorea APIs del sistema (Crypto, Network, SharedPrefs, etc.)
- `load_custom_api_config` - Carga configuración personalizada de APIs (formato RMS)

## Categorías de API Monitor

| Categoría | APIs Monitoreadas |
|-----------|-------------------|
| **Device Info** | TelephonyManager, WifiInfo, Debug.isDebuggerConnected |
| **Crypto** | SecretKeySpec, Cipher.doFinal |
| **Hash** | MessageDigest.digest/update |
| **Base64** | Base64.encode/decode/encodeToString |
| **Network** | URL.openConnection, Socket |
| **WebView** | loadUrl, evaluateJavascript, addJavascriptInterface |
| **SharedPreferences** | getString/putString, getInt/putInt, etc. |
| **Database** | SQLiteDatabase execSQL/rawQuery/insert |
| **FileSystem** | FileInputStream/FileOutputStream |
| **Commands** | Runtime.exec, ProcessBuilder.start |
| **JNI** | Runtime.loadLibrary/load |
| **Clipboard** | ClipboardManager getPrimaryClip/setPrimaryClip |
| **SMS** | SmsManager.sendTextMessage |
| **Location** | Location.getLatitude/getLongitude |
| **Permissions** | checkSelfPermission |

## Ejemplo de uso

```python
# Listar procesos en dispositivo remoto
list_processes(device="192.168.4.220:9999")

# Ejecutar script con Java API
execute_script(
    device="192.168.4.220:9999",
    target="com.example.app",
    script="Java.perform(() => { console.log('Classes:', Java.enumerateLoadedClassesSync().length); })"
)

# Cargar clases con filtro
load_classes_with_filter(
    target="com.example.app",
    filter_pattern="Security|Crypto|Root",
    is_regex=True,
    device="192.168.4.220:9999"
)

# Monitorear APIs de Crypto y Network
api_monitor(
    target="com.example.app",
    categories=["Crypto", "Network", "SharedPreferences"],
    device="192.168.4.220:9999"
)

# Cargar configuración de API Monitor personalizada (formato RMS)
load_custom_api_config("/path/to/api_monitor.json")
```

## Progreso de Implementación

| Fase | Descripción | Estado |
|------|-------------|--------|
| Phase 1 | Core RMS functions (get_app_env_info, list_files, load_classes) | ✅ |
| Phase 2 | Advanced filtering (load_classes_with_filter, load_methods) | ✅ |
| Phase 3 | Hook templates (generate_hook_template, heap_search_template) | ✅ |
| Phase 4 | Live hooking (hook_classes_and_methods) | ✅ |
| Phase 5 | API Monitor (api_monitor, list_api_categories) | ✅ |
| Phase 6 | Custom Scripts Library | ⏳ Pending |
