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

## Herramientas disponibles

### Dispositivos
- `list_devices` - Lista dispositivos disponibles
- `add_remote_device` - Conecta a un dispositivo remoto (frida-server)

### Procesos
- `list_processes` - Lista procesos en un dispositivo
- `spawn_process` - Inicia una aplicación
- `kill_process` - Termina un proceso

### Scripting
- `execute_script` - Ejecuta código JavaScript en un proceso (one-shot)
- `create_session` - Crea una sesión interactiva para múltiples comandos
- `run_in_session` - Ejecuta código en una sesión existente
- `close_session` - Cierra una sesión

## Ejemplo de uso

```
# Listar procesos en dispositivo remoto
list_processes(device="192.168.4.220:9999")

# Ejecutar script con Java API
execute_script(
    device="192.168.4.220:9999",
    target="com.example.app",
    script="Java.perform(() => { console.log('Classes:', Java.enumerateLoadedClassesSync().length); })"
)
```
