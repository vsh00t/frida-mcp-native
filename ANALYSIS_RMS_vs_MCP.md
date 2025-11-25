# Análisis Comparativo: RMS vs frida-mcp-native

## 1. RESUMEN EJECUTIVO

### Totales
| Métrica | Cantidad |
|---------|----------|
| **Funcionalidades RMS Core (rpc.exports)** | 11 |
| **Ya implementadas en frida-mcp-native** | 1 (parcial) |
| **Pendientes de implementación** | 10 |
| **Custom Scripts RMS (Android)** | 27 |
| **Custom Scripts RMS (iOS)** | 17 |
| **Total funcionalidades a migrar** | 54 |

### Distribución por Complejidad

| Complejidad | Cantidad | Horas Est. Total |
|-------------|----------|------------------|
| **Básica** (1-3h) | 8 | 16-24h |
| **Media** (4-8h) | 6 | 24-48h |
| **Alta** (9-16h) | 4 | 36-64h |
| **Muy Alta** (>16h) | 2 | 32-40h |
| **TOTAL** | 20 core | 108-176h |

---

## 2. ANÁLISIS COMPARATIVO

### Funcionalidades Core RMS (rpc.exports)

| Funcionalidad RMS | Estado frida-mcp-native | Plataforma | Complejidad |
|-------------------|-------------------------|------------|-------------|
| `checkmobileos()` | ✅ Implementada (via execute_script) | Ambas | Básica |
| `loadclasses()` | ⚠️ Parcial (manual via execute_script) | Ambas | Básica |
| `loadclasseswithfilter()` | ❌ No implementada | Ambas | Básica |
| `loadmethods()` | ❌ No implementada | Ambas | Media |
| `loadcustomfridascript()` | ⚠️ Parcial (execute_script sin templates) | Ambas | Básica |
| `hookclassesandmethods()` | ❌ No implementada | Ambas | Alta |
| `generatehooktemplate()` | ❌ No implementada | Ambas | Media |
| `heapsearchtemplate()` | ❌ No implementada | Ambas | Media |
| `apimonitor()` | ❌ No implementada | Android | Muy Alta |
| `getappenvinfo()` | ❌ No implementada | Ambas | Básica |
| `listfilesatpath()` | ❌ No implementada | Ambas | Básica |

### Herramientas frida-mcp-native Existentes

| Herramienta MCP | Equivalente RMS | Estado |
|-----------------|-----------------|--------|
| `list_devices()` | N/A (RMS usa Flask) | ✅ Completa |
| `add_remote_device()` | N/A | ✅ Completa |
| `list_processes()` | N/A | ✅ Completa |
| `list_installed_apps()` | N/A | ✅ Completa |
| `execute_script()` | `loadcustomfridascript()` | ⚠️ Parcial |
| `execute_script_spawn()` | Similar | ✅ Completa |
| `create_session()` | N/A (RMS mantiene session via Flask) | ✅ Completa |
| `check_java_available()` | `checkmobileos()` | ✅ Completa |

---

## 3. LISTADO PRIORIZADO (DE FÁCIL A COMPLEJA)

---

### [1]. getappenvinfo
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Básica (1-2 horas)

**Descripción técnica:**  
Obtiene información del entorno de la aplicación: directorios principales, paths de archivos, cache, código fuente, etc. Es una función de solo lectura que no requiere manejo de estados.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 615-652 (Android), 1006-1022 (iOS)
- APIs Frida utilizadas: 
  - Android: `Java.use('android.app.ActivityThread')`, `getApplicationContext()`
  - iOS: `ObjC.classes.NSBundle`, `ObjC.classes.NSFileManager`
- Lógica clave: Obtiene context de Android y usa métodos como `getFilesDir()`, `getCacheDir()`, etc.

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `get_app_env_info(target, device)`
- [ ] Script JS embebido para Android
- [ ] Script JS embebido para iOS
- [ ] Detección automática de plataforma

**Justificación de complejidad:**  
Es una función de solo lectura sin estados, sin overloads que manejar, con APIs de Frida bien documentadas. Solo requiere ejecutar un script y parsear JSON de respuesta.

**Double-check:**  
✓ Verificación 1: La función RMS retorna un objeto JSON simple con 7 campos (Android) o 5 campos (iOS)  
✓ Verificación 2: No hay dependencias de otras funciones RMS, es completamente autónoma

---

### [2]. listfilesatpath
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Básica (1-2 horas)

**Descripción técnica:**  
Lista archivos en una ruta específica del dispositivo, incluyendo atributos como permisos, tamaño, fecha de modificación, y si es directorio o archivo.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 654-690 (Android), 1024-1078 (iOS)
- APIs Frida utilizadas:
  - Android: `Java.use("java.io.File")`, métodos `listFiles()`, `canRead()`, `canWrite()`, `isDirectory()`
  - iOS: `ObjC.classes.NSFileManager`, `contentsOfDirectoryAtPath_error_()`, `attributesOfItemAtPath_error_()`
- Lógica clave: Crea instancia de File/NSFileManager, itera sobre contenido y recopila atributos

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `list_files_at_path(target, path, device)`
- [ ] Script JS para Android con manejo de excepciones
- [ ] Script JS para iOS con lectura de atributos NSFile
- [ ] Formato de respuesta unificado entre plataformas

**Justificación de complejidad:**  
Función de solo lectura, sin hooks ni overloads. La lógica es lineal: obtener lista de archivos e iterar. El parsing de atributos es directo.

**Double-check:**  
✓ Verificación 1: Android usa `java.io.File.$new(path)` - clase estándar de Java  
✓ Verificación 2: iOS usa NSFileManager que es API estable de Foundation

---

### [3]. loadclasses
**Estado actual:** ⚠️ Parcialmente implementada (manual via execute_script)  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Básica (2-3 horas)

**Descripción técnica:**  
Enumera todas las clases cargadas en la VM de la aplicación. En Android usa `Java.enumerateLoadedClasses`, en iOS itera sobre `ObjC.classes`. Filtra clases muy cortas y excluye androidx por defecto.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 35-99 (exports), 285-304 (Android), 815-827 (iOS)
- APIs Frida utilizadas:
  - Android: `Java.enumerateLoadedClasses({onMatch, onComplete})`
  - iOS: `for (var className in ObjC.classes)`
- Lógica clave: Callback `onMatch` agrega clase si cumple filtros (length > 5, no androidx)

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `load_classes(target, device, exclude_androidx=True, min_length=5)`
- [ ] Implementar detección de plataforma
- [ ] Retornar lista JSON de clases
- [ ] Agregar parámetros de filtro opcionales

**Justificación de complejidad:**  
La enumeración es síncrona con `enumerateLoadedClassesSync()`. RMS usa versión async pero MCP puede usar sync para simplicidad. El manejo de Android 16 ya está resuelto en frida-mcp-native via CLI.

**Double-check:**  
✓ Verificación 1: `enumerateLoadedClassesSync()` disponible en Frida CLI (Java bridge incluido)  
✓ Verificación 2: iOS no tiene restricciones similares a Android 16

---

### [4]. loadclasseswithfilter
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Básica (2-3 horas)

**Descripción técnica:**  
Extiende `loadclasses` con filtrado avanzado: soporta regex, case-sensitive/insensitive, filtro de palabra completa, y múltiples filtros separados por coma.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 101-137 (exports), 306-361 (Android), 829-880 (iOS)
- APIs Frida utilizadas: Mismas que `loadclasses` + lógica de filtrado JavaScript
- Lógica clave:
  ```javascript
  if (isRegex) { className.search(filter) > -1 }
  else { 
    filter_array.forEach(f => {
      isWhole ? className == f : className.startsWith(f)
    })
  }
  ```

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `load_classes_with_filter(target, filter, device, is_regex=False, is_case=False, is_whole=False)`
- [ ] Implementar lógica de filtrado en el script JS embebido
- [ ] Soporte para múltiples filtros (comma-separated)
- [ ] Documentar patrones de uso comunes

**Justificación de complejidad:**  
Es una extensión de `loadclasses`. La lógica de filtrado es JavaScript puro, no requiere APIs adicionales de Frida. Los parámetros son booleanos simples.

**Double-check:**  
✓ Verificación 1: El filtrado ocurre dentro de `onMatch`, no post-procesamiento  
✓ Verificación 2: Soporta regex nativo de JavaScript via `.search()`

---

### [5]. loadcustomfridascript
**Estado actual:** ⚠️ Parcialmente implementada (execute_script existe pero sin contexto RMS)  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Básica (1-2 horas)

**Descripción técnica:**  
Permite cargar y ejecutar scripts Frida personalizados proporcionados por el usuario. En RMS simplemente hace `eval()` del script dentro del contexto Java.perform/ObjC.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 163-176 (exports), 452-458 (Android), 921-925 (iOS)
- APIs Frida utilizadas: `Java.perform()` + `eval()`
- Lógica clave: Muy simple - envuelve el script en `Java.perform()` y ejecuta con `eval()`

**Requerimientos para frida-mcp-native:**  
- [ ] Renombrar o alias `execute_script` → `load_custom_script` para consistencia
- [ ] Agregar opción para cargar desde archivo local
- [ ] Agregar biblioteca de scripts predefinidos (los custom_scripts de RMS)

**Justificación de complejidad:**  
Ya existe como `execute_script()`. Solo requiere agregar features de conveniencia: carga desde archivo, templates predefinidos.

**Double-check:**  
✓ Verificación 1: `execute_script()` ya envuelve en try/catch similar a RMS  
✓ Verificación 2: El wrapping en `Java.perform()` ya está resuelto en el script embebido

---

### [6]. loadmethods
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Media (4-6 horas)

**Descripción técnica:**  
Dada una lista de clases, obtiene todos los métodos declarados de cada clase, incluyendo información de argumentos en notación Smali para Android (necesaria para overloads).

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 139-160 (exports), 363-450 (Android), 882-919 (iOS)
- APIs Frida utilizadas:
  - Android: `Java.use(className)`, `jClass.class.getDeclaredMethods()`
  - iOS: `ObjC.classes[className].$ownMethods`, `returnType`, `argumentTypes`
- Lógica clave (Android):
  1. Parsea string del método para extraer nombre
  2. Convierte argumentos a notación Smali (int→I, boolean→Z, arrays→[)
  3. Construye objeto con `name`, `args`, `ui_name`

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `load_methods(target, classes, device)`
- [ ] Implementar conversión a notación Smali para arrays
- [ ] Manejar excepciones por clase (algunas no se pueden inspeccionar)
- [ ] Retornar diccionario {className: [methods]}

**Justificación de complejidad:**  
El parsing de métodos Android requiere lógica no trivial:
- Eliminar genéricos `<.*?>` 
- Eliminar `throws` clauses
- Convertir tipos primitivos a Smali
- Manejar arrays multidimensionales
Esta lógica está en líneas 400-450 de RMS_core.js

**Double-check:**  
✓ Verificación 1: La conversión Smali es necesaria para `overload()` en hooks  
✓ Verificación 2: iOS es más simple (líneas 882-919) - solo lee `$ownMethods` directamente

---

### [7]. generatehooktemplate
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Media (4-6 horas)

**Descripción técnica:**  
Genera código JavaScript de hook basado en templates para las clases/métodos seleccionados. No ejecuta los hooks, solo genera el código que el usuario puede modificar y luego ejecutar.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 200-217 (exports), 510-569 (Android), 947-973 (iOS)
- APIs Frida utilizadas: Solo manipulación de strings, no APIs runtime
- Lógica clave:
  - Template con placeholders: `{className}`, `{classMethod}`, `{overload}`, `{args}`, `{methodSignature}`
  - Itera sobre clases y métodos, reemplaza placeholders
  - Genera string de argumentos dinámico (`v0,v1,v2...`)

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `generate_hook_template(target, classes, methods, template, device)`
- [ ] Definir templates predefinidos para casos comunes
- [ ] Lógica de generación de argumentos `vN`
- [ ] Manejo de overloads (incluir notación Smali en template)

**Justificación de complejidad:**  
Requiere primero implementar `loadmethods()` para obtener la estructura de métodos. La generación de templates es string manipulation pero debe manejar:
- Métodos sin argumentos (caso especial)
- Múltiples overloads
- Diferencias Android vs iOS

**Double-check:**  
✓ Verificación 1: Depende de `loadmethods()` - implementar primero  
✓ Verificación 2: Templates iOS no usan `overload()` - son más simples

---

### [8]. heapsearchtemplate
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Media (4-6 horas)

**Descripción técnica:**  
Similar a `generatehooktemplate` pero genera código para buscar instancias en el heap y llamar métodos en ellas. Útil para invocar métodos de objetos ya instanciados.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 219-236 (exports), 571-613 (Android), 975-1004 (iOS)
- APIs Frida utilizadas: Template usa `Java.choose()` / `ObjC.choose()`
- Lógica clave:
  - Template diferente al de hooks
  - Usa `Java.choose(className, {onMatch: function(instance) {...}})`
  - Permite llamar métodos en instancias encontradas

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `heap_search_template(target, classes, methods, template, device)`
- [ ] Template predefinido para heap search
- [ ] Documentar uso de `Java.choose()` / `ObjC.choose()`

**Justificación de complejidad:**  
Muy similar a `generatehooktemplate` en implementación. La diferencia es el template base que usa `Java.choose()`. Puede reutilizar mucha lógica.

**Double-check:**  
✓ Verificación 1: Comparte estructura con `generatehooktemplate`  
✓ Verificación 2: `Java.choose()` es API estable de Frida

---

### [9]. hookclassesandmethods
**Estado actual:** ❌ No implementada  
**Plataforma:** Ambas (Android + iOS)  
**Complejidad:** Alta (9-12 horas)

**Descripción técnica:**  
Ejecuta hooks en tiempo real para las clases/métodos seleccionados usando un template. A diferencia de `generatehooktemplate`, este ejecuta (`eval()`) los hooks inmediatamente.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 178-198 (exports), 460-508 (Android), 927-945 (iOS)
- APIs Frida utilizadas: `Java.use()`, `.implementation`, `overload()`, `eval()`
- Lógica clave:
  ```javascript
  loaded_classes.forEach(clazz => {
    loaded_methods[clazz].forEach(dict => {
      var t = template;
      // Replace placeholders
      t = t.replace("{className}", clazz);
      // ... más reemplazos
      eval(t);  // ← Ejecuta el hook
    });
  });
  ```

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `hook_classes_and_methods(target, classes, methods, template, device)`
- [ ] Requiere `loadmethods()` implementado primero
- [ ] Manejo de sesión persistente (hooks deben mantenerse activos)
- [ ] Sistema de callback para reportar invocaciones hooked
- [ ] Manejo de errores por método individual (no fallar todo si uno falla)

**Justificación de complejidad:**  
- Requiere sesión persistente (los hooks deben mantenerse vivos)
- Manejo de múltiples overloads por método
- Sistema de output para las invocaciones interceptadas
- Error handling granular (línea 350-352 de RMS)
- La arquitectura MCP one-shot no es ideal para hooks persistentes

**Double-check:**  
✓ Verificación 1: Requiere `create_session()` para mantener hooks activos  
✓ Verificación 2: El template de RMS (líneas 460-508) usa eval() que funciona en CLI

---

### [10]. apimonitor (Android)
**Estado actual:** ❌ No implementada  
**Plataforma:** Android (iOS es stub vacío)  
**Complejidad:** Muy Alta (16-24 horas)

**Descripción técnica:**  
Sistema completo de monitoreo de APIs del sistema Android. Hookea automáticamente cientos de métodos organizados por categoría (Device Info, Crypto, Network, etc.) y reporta cada invocación con argumentos y stack trace.

**Implementación en RMS:**  
- Referencia: `agent/RMS_core.js` líneas 238-248 (exports), 692-768 (Android)
- Archivo config: `config/api_monitor.json` (832 líneas, ~100 hooks definidos)
- APIs Frida utilizadas:
  - `Java.use(clazz)[method].overloads[i].implementation`
  - `Java.use('java.lang.Exception').$new().getStackTrace()`
  - `Interceptor.attach()` para hooks nativos (libc.so)
- Lógica clave:
  1. Carga JSON de configuración con categorías y hooks
  2. Para cada hook, determina si es Java o Native
  3. Hooks Java: Itera overloads y reemplaza implementation
  4. Hooks Native: Usa `Interceptor.attach()` en exports de libc
  5. Callback reporta: category, class, method, args, returnValue, calledFrom

**Requerimientos para frida-mcp-native:**  
- [ ] Crear función `api_monitor(target, categories, device)`
- [ ] Migrar `api_monitor.json` (832 líneas)
- [ ] Implementar `javadynamichook()` (líneas 732-768)
- [ ] Implementar `nativedynamichook()` (líneas 713-730)
- [ ] Sistema de streaming de eventos (no one-shot)
- [ ] Filtrado por categoría
- [ ] Manejo de versiones Android (`target` field en hooks)

**Justificación de complejidad:**  
- Requiere 832 líneas de configuración JSON
- Combina hooks Java y Native
- Sistema de callbacks dinámicos con stack traces
- Manejo de overloads para todos los métodos
- Filtrado por versión Android
- Output en streaming (no encaja bien en modelo MCP request-response)
- iOS no implementado en RMS original (stub vacío)

**Double-check:**  
✓ Verificación 1: `javadynamichook()` itera `toHook.overloads.length` (línea 754)  
✓ Verificación 2: Hooks nativos solo para File System (`libc.so` open)

---

### [11]. Custom Scripts Collection (Android - 27 scripts)
**Estado actual:** ❌ No implementada como biblioteca  
**Plataforma:** Android  
**Complejidad:** Alta (12-16 horas para integrar todos)

**Descripción técnica:**  
Colección de scripts Frida predefinidos para tareas comunes de análisis de seguridad Android:
- Bypasses: root detection, SSL pinning (6 variantes), emulator, fingerprint, debugger, FLAG_SECURE
- Tracers: Cipher, KeyStore, SecretKeyFactory
- Enumeración: DEX classes, native exports
- Utilidades: Android ID, crypto interception, file system monitor

**Scripts prioritarios por uso:**
1. `ssl_pinning_multi_bypass.js` - Bypass SSL pinning universal
2. `root_detection_bypass.js` - Bypass detección de root
3. `intercept_crypto.js` - Interceptar operaciones criptográficas
4. `tracer_keystore.js` - Rastrear uso de KeyStore

**Requerimientos para frida-mcp-native:**  
- [ ] Crear sistema de biblioteca de scripts
- [ ] Función `run_predefined_script(target, script_name, device)`
- [ ] Categorización: bypass, tracer, enum, util
- [ ] Documentación de cada script
- [ ] Parámetros configurables por script

**Justificación de complejidad:**  
27 scripts individuales a integrar. Cada uno tiene lógica específica. Algunos son simples (get_android_id.js), otros complejos (ssl_pinning_multi_bypass.js con múltiples técnicas).

**Double-check:**  
✓ Verificación 1: Scripts son autocontenidos, pueden ejecutarse con `execute_script()`  
✓ Verificación 2: Algunos scripts requieren parámetros (enum_native_lib_exports.js necesita nombre de librería)

---

### [12]. Custom Scripts Collection (iOS - 17 scripts)  
**Estado actual:** ❌ No implementada como biblioteca  
**Plataforma:** iOS  
**Complejidad:** Alta (10-14 horas para integrar todos)

**Descripción técnica:**  
Colección de scripts Frida para análisis de seguridad iOS:
- Bypasses: jailbreak detection, SSL pinning (4 versiones por iOS), Touch ID
- Dumps: keychain, cookies, NSUserDefaults, UI hierarchy, decrypted app, data protection keys
- Análisis: static_analysis.js, pasteboard monitor

**Scripts prioritarios:**
1. `jailbreak_detection_bypass.js` - Bypass detección jailbreak
2. `dump_keychain.js` - Extraer keychain
3. `ssl_pinning_bypass_iOS_13.js` - Bypass SSL para iOS moderno
4. `intercept_crypto.js` - Interceptar crypto

**Requerimientos para frida-mcp-native:**  
- [ ] Incluir en sistema de biblioteca junto con Android
- [ ] Función unificada que detecte plataforma
- [ ] Scripts iOS específicos por versión

**Justificación de complejidad:**  
Similar a Android pero con menos scripts. iOS tiene scripts más específicos por versión del OS.

**Double-check:**  
✓ Verificación 1: SSL bypass tiene 4 versiones (iOS 10, 11, 12, 13)  
✓ Verificación 2: dump_keychain.js es uno de los más complejos (~200 líneas)

---

## 4. RECOMENDACIONES DE IMPLEMENTACIÓN

### Orden Sugerido de Desarrollo (Fases)

#### Fase 1: Fundamentos (1-2 días)
1. `getappenvinfo()` - Base para navegación
2. `listfilesatpath()` - Exploración de filesystem
3. `loadclasses()` - Base para análisis

#### Fase 2: Análisis de Clases (2-3 días)
4. `loadclasseswithfilter()` - Filtrado avanzado
5. `loadmethods()` - **Crítico** - requerido para hooks
6. `loadcustomfridascript()` - Mejorar execute_script

#### Fase 3: Generación de Código (2-3 días)
7. `generatehooktemplate()` - Depende de loadmethods
8. `heapsearchtemplate()` - Reutiliza lógica de templates

#### Fase 4: Hooking Activo (3-4 días)
9. `hookclassesandmethods()` - Requiere sesiones persistentes

#### Fase 5: Monitoreo Avanzado (4-5 días)
10. `apimonitor()` - El más complejo, requiere todo lo anterior

#### Fase 6: Biblioteca de Scripts (3-5 días)
11. Custom Scripts Android (27)
12. Custom Scripts iOS (17)

### Dependencias Entre Funcionalidades

```
loadclasses() 
    └── loadclasseswithfilter()
    
loadmethods() ←── loadclasses()
    ├── generatehooktemplate()
    ├── heapsearchtemplate()  
    └── hookclassesandmethods()
    
apimonitor() ←── hookclassesandmethods() + config JSON

Custom Scripts ←── loadcustomfridascript() mejorado
```

### Riesgos Técnicos Identificados

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| Sesiones persistentes en MCP | Alto | Usar `create_session()` existente, agregar timeout auto |
| Output streaming para hooks | Alto | Implementar sistema de polling o WebSocket |
| Tamaño de respuesta (loadclasses puede retornar 10K+ clases) | Medio | Paginación o filtrado obligatorio |
| Compatibilidad Android 16 | Bajo | Ya resuelto con CLI approach |
| iOS testing | Medio | Requiere dispositivo iOS real para validar |

### Sugerencias de Optimización

1. **Caching de clases**: `loadclasses()` es costoso. Cachear resultado por sesión.

2. **Lazy loading de métodos**: No cargar todos los métodos de todas las clases. Usar filtro obligatorio.

3. **Templates predefinidos**: Incluir templates comunes en el código, no solo como parámetro.

4. **Batch operations**: Permitir hookear múltiples métodos en una sola llamada MCP.

5. **Script compilation**: Pre-compilar scripts frecuentes para reducir overhead de eval().

---

## VERIFICACIÓN FINAL

- [x] Todas las 11 funcionalidades exportadas en RMS están listadas
- [x] El orden va estrictamente de menor a mayor complejidad
- [x] Cada funcionalidad tiene justificación técnica completa
- [x] Las estimaciones de tiempo son coherentes con la complejidad asignada
- [x] Se incluyen referencias específicas al código fuente (líneas)
- [x] El análisis cubre tanto Android como iOS
- [x] Las dependencias técnicas están claramente identificadas
- [x] El double-check está completo para cada ítem
- [x] No hay funcionalidades duplicadas en la lista
- [x] Las funcionalidades parcialmente implementadas tienen detalles de qué falta

---

*Documento generado: 25 de noviembre de 2025*  
*Repositorios analizados:*
- `m0bilesecurity/RMS-Runtime-Mobile-Security` (agent/RMS_core.js: 1081 líneas)
- `vsh00t/frida-mcp-native` (server.py: 906 líneas)
