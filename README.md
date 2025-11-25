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

\`\`\`bash
cd frida-mcp-native
pipx install .
\`\`\`

## Uso con Claude Desktop / VS Code

Agregar a tu configuración de MCP:

\`\`\`json
{
  "mcpServers": {
    "frida-native": {
      "command": "frida-mcp-native"
    }
  }
}
\`\`\`

## Herramientas disponibles (30 tools)

### 📱 Dispositivos
| Herramienta | Descripción |
|-------------|-------------|
| \`list_devices\` | Lista dispositivos disponibles |
| \`add_remote_device\` | Conecta a un dispositivo remoto (frida-server) |
| \`list_remote_devices\` | Lista dispositivos remotos configurados |

### ⚙️ Procesos
| Herramienta | Descripción |
|-------------|-------------|
| \`list_processes\` | Lista procesos en un dispositivo |
| \`list_installed_apps\` | Lista todas las apps instaladas (no solo las en ejecución) |
| \`spawn_process\` | Inicia una aplicación |
| \`kill_process\` | Termina un proceso |

### 📜 Scripting
| Herramienta | Descripción |
|-------------|-------------|
| \`execute_script\` | Ejecuta código JavaScript en un proceso (one-shot) |
| \`execute_script_spawn\` | Spawn + script (para hooks tempranos) |
| \`create_session\` | Crea una sesión interactiva para múltiples comandos |
| \`run_in_session\` | Ejecuta código en una sesión existente |
| \`close_session\` | Cierra una sesión |
| \`list_sessions\` | Lista sesiones activas |
| \`check_java_available\` | Verifica si Java bridge está disponible |
| \`get_frida_version\` | Obtiene la versión de Frida CLI |

### 🔍 RMS Functions - Análisis de Apps (Phase 1-2)
| Herramienta | Descripción |
|-------------|-------------|
| \`get_app_env_info\` | Obtiene rutas y directorios de la app |
| \`list_files_at_path\` | Lista archivos en un path del dispositivo |
| \`load_classes\` | Enumera todas las clases cargadas |
| \`load_classes_with_filter\` | Enumera clases con filtros avanzados (regex, case-sensitive) |
| \`load_methods\` | Obtiene métodos de clases específicas con sus firmas |

### 🪝 RMS Functions - Hook Templates (Phase 3)
| Herramienta | Descripción |
|-------------|-------------|
| \`generate_hook_template\` | Genera código de hooks para clases/métodos |
| \`heap_search_template\` | Genera código para buscar instancias en heap |

### ⚡ RMS Functions - Live Hooking (Phase 4)
| Herramienta | Descripción |
|-------------|-------------|
| \`hook_classes_and_methods\` | Instala hooks en tiempo real |

### 📊 RMS Functions - API Monitor (Phase 5)
| Herramienta | Descripción |
|-------------|-------------|
| \`list_api_categories\` | Lista categorías de APIs disponibles para monitorear |
| \`api_monitor\` | Monitorea APIs del sistema (Crypto, Network, SharedPrefs, etc.) |
| \`load_custom_api_config\` | Carga configuración personalizada de APIs (formato RMS) |

### 🛡️ RMS Functions - Custom Scripts Library (Phase 6)
| Herramienta | Descripción |
|-------------|-------------|
| \`list_custom_scripts\` | Lista todos los scripts disponibles (con filtros) |
| \`run_custom_script\` | Ejecuta un script de la librería built-in |
| \`load_script_from_file\` | Carga y ejecuta cualquier archivo .js |
| \`get_script_code\` | Obtiene el código fuente de un script |

---

## 📊 Categorías de API Monitor

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

---

## 🛡️ Scripts Built-in

### Android (7 scripts)
| Script | Categoría | Descripción |
|--------|-----------|-------------|
| \`ssl_pinning_bypass\` | bypass | SSL Pinning universal (OkHttp3, Trustkit, TrustManager) |
| \`root_detection_bypass\` | bypass | Oculta indicadores de root (Magisk, SuperSU, etc.) |
| \`intercept_crypto\` | tracer | Intercepta operaciones criptográficas (keys, algorithms) |
| \`emulator_detection_bypass\` | bypass | Hace parecer emulador como dispositivo real |
| \`debugger_bypass\` | bypass | Oculta debugger de anti-tampering |
| \`fingerprint_bypass\` | bypass | Bypass de autenticación biométrica |
| \`flag_secure_bypass\` | bypass | Permite screenshots en pantallas protegidas |

### iOS (4 scripts)
| Script | Categoría | Descripción |
|--------|-----------|-------------|
| \`ios_ssl_pinning_bypass\` | bypass | SSL Pinning para iOS 12-17 (libboringssl) |
| \`ios_jailbreak_bypass\` | bypass | Oculta indicadores de jailbreak |
| \`ios_touch_id_bypass\` | bypass | Bypass de Touch ID / Face ID |
| \`ios_keychain_dump\` | dump | Extrae todos los items del keychain |

---

## 📝 Ejemplos de uso

### Listar procesos
\`\`\`python
list_processes(device="192.168.4.220:9999", applications_only=True)
\`\`\`

### Ejecutar script con Java API
\`\`\`python
execute_script(
    device="192.168.4.220:9999",
    target="com.example.app",
    script="Java.perform(() => { console.log('Classes:', Java.enumerateLoadedClassesSync().length); })"
)
\`\`\`

### Buscar clases con regex
\`\`\`python
load_classes_with_filter(
    target="com.example.app",
    filter_pattern="Security|Crypto|Root",
    is_regex=True,
    device="192.168.4.220:9999"
)
\`\`\`

### Monitorear APIs
\`\`\`python
api_monitor(
    target="com.example.app",
    categories=["Crypto", "Network", "SharedPreferences"],
    device="192.168.4.220:9999"
)
\`\`\`

### Bypass SSL Pinning
\`\`\`python
run_custom_script(
    target="com.example.app",
    script_name="ssl_pinning_bypass",
    device="192.168.4.220:9999"
)
\`\`\`

### Bypass Root Detection
\`\`\`python
run_custom_script(
    target="com.example.app",
    script_name="root_detection_bypass",
    device="192.168.4.220:9999"
)
\`\`\`

### Cargar script personalizado
\`\`\`python
load_script_from_file(
    target="com.example.app",
    script_path="/path/to/custom_script.js",
    device="192.168.4.220:9999"
)
\`\`\`

---

## ✅ Progreso de Implementación

| Fase | Descripción | Estado |
|------|-------------|--------|
| Phase 1 | Core RMS functions (get_app_env_info, list_files, load_classes) | ✅ Complete |
| Phase 2 | Advanced filtering (load_classes_with_filter, load_methods) | ✅ Complete |
| Phase 3 | Hook templates (generate_hook_template, heap_search_template) | ✅ Complete |
| Phase 4 | Live hooking (hook_classes_and_methods) | ✅ Complete |
| Phase 5 | API Monitor (api_monitor, list_api_categories) | ✅ Complete |
| Phase 6 | Custom Scripts Library (11 scripts, 4 tools) | ✅ Complete |

**Total: 30 herramientas MCP + 11 scripts built-in**

---

## 🔗 Links

- **Frida**: https://frida.re/
- **RMS (Runtime Mobile Security)**: https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security
- **MCP Protocol**: https://modelcontextprotocol.io/

## 📄 License

MIT License
