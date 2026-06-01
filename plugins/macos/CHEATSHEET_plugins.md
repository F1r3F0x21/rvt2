# Cheatsheet — Crear plugins macOS para RVT2

## Estructura mínima de un módulo

```python
# plugins/macos/RVT_macos.py — añadir al final del fichero

import os
import base.job
from plugins.common.RVT_files import GetFiles
from base.utils import check_folder

class MiModulo(base.job.BaseModule):

    def read_config(self):
        """Valores de config por defecto (opcional)."""
        super().read_config()
        self.set_default_config('outdir', '${macosdir}/mi_modulo')
        self.set_default_config('mi_opcion', 'valor_defecto')

    def run(self, path=""):
        # 1. Validar precondiciones
        if not os.path.isdir(self.myconfig('mountdir')):
            raise base.job.RVTError(f"Folder {self.myconfig('mountdir')} not exists")

        # 2. Preparar directorio de salida
        outdir = self.myconfig('outdir')
        check_folder(outdir)

        # 3. Buscar artefactos
        search = GetFiles(self.config)
        files = search.search(r"patron_regex_aqui$")   # regex sobre rutas relativas

        # 4. Procesar
        with open(os.path.join(outdir, 'resultado.txt'), 'w') as out:
            for f in files:
                full_path = os.path.join(self.myconfig('casedir'), f)
                self.logger().info(f"Procesando {f}")
                try:
                    # ... tu lógica aquí
                    pass
                except Exception as e:
                    self.logger().warning(f"Error en {f}: {e}")
                    continue

        self.logger().info("MiModulo completado")
        return []   # devolver lista vacía si no hay datos que pasar al siguiente módulo
```

## Añadir la sección de configuración

```ini
# plugins/macos/modules.cfg — añadir al final

[plugins.macos.RVT_macos.MiModulo]
inherits: plugins.common
outdir: ${macosdir}/mi_modulo
mi_opcion: valor
```

## Registrar en el job (opcional)

```ini
# plugins/macos/jobs.cfg — dentro de [macforensics].jobs

    plugins.macos.RVT_macos.MiModulo
```

---

## Variables de configuración disponibles (heredadas de `plugins.common`)

| Variable     | Descripción                                                      |
|--------------|------------------------------------------------------------------|
| `mountdir`   | Ruta a la imagen montada: `${sourcedir}/mnt`                     |
| `casedir`    | Raíz del caso: `${morgue}/${client}/${casename}/${source}/mnt`   |
| `macosdir`   | Carpeta de salida macOS: `${outputdir}/macos`                    |
| `sourcedir`  | Directorio fuente: `${casedir}`                                  |
| `rvthome`    | Directorio raíz de RVT2                                          |
| `source`     | Nombre del source actual                                         |

## Métodos clave de `BaseModule`

```python
self.myconfig('opcion')               # leer string de config
self.myconfig('opcion', 'default')    # con valor por defecto
self.myflag('flag_booleano')          # leer bool
self.myarray('lista_opciones')        # leer lista separada por espacios/JSON

self.logger().info("mensaje")
self.logger().warning("aviso")
self.logger().error("error")
self.logger().debug("debug")
```

## Patrones de artefactos macOS más comunes

```python
# Búsquedas útiles con GetFiles.search(regex)
r"\.plist$"                                           # todos los plists
r"var/log/asl/.*\.asl$"                               # logs ASL
r"/knowledgec\.db$"                                   # KnowledgeC
r"/netusage\.sqlite$"                                 # uso de red
r"/com\.apple\.LaunchServices\.QuarantineEventsV2$"   # quarantine
r"/\.ds_store$"                                       # DS_Store
r"p\d+(/root)?/Users/[^/]+$"                          # directorios de usuarios
r"/var/db/diagnostics$"                               # Unified Log
r"QuickLook\.thumbnailcache$"                         # thumbnails QuickLook
r"/Library/Preferences/SystemConfiguration/NetworkInterfaces\.plist$"
```

## SQLite en modo solo lectura (patrón estándar)

```python
import sqlite3

db_path = os.path.join(self.myconfig('casedir'), relative_path)
with sqlite3.connect(f"file://{db_path}?mode=ro", uri=True) as conn:
    conn.text_factory = str
    c = conn.cursor()
    c.execute("SELECT ... FROM ... WHERE ...;")
    for row in c.fetchall():
        # row[0], row[1], ...
        pass
```

## Conversión de timestamps macOS

```python
import datetime

# Core Foundation Time → datetime UTC
CF_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
dt = CF_EPOCH + datetime.timedelta(seconds=cf_timestamp)
dt_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# En SQL directamente (Core Data / SQLite):
# datetime(ZCREATIONDATE + 978307200, 'UNIXEPOCH', 'LOCALTIME')
# 978307200 = segundos entre 1970-01-01 y 2001-01-01
```

## Llamar a herramientas externas

```python
from base.commands import run_command

python3 = self.myconfig('python3', '/usr/bin/python3')
script = os.path.join(self.myconfig('rvthome'), 'plugins/external/mi_tool/script.py')

with open(logfile_path, 'a') as logfile:
    run_command([python3, script, arg1, arg2], stdout=logfile, stderr=logfile)
```

## Parsear plists (binarios y XML)

```python
import biplist

try:
    plist = biplist.readPlist(full_path)            # desde fichero
    plist = biplist.readPlistFromString(raw_bytes)  # desde bytes
except biplist.InvalidPlistException:
    self.logger().warning(f"Plist inválido: {full_path}")
except biplist.NotBinaryPlistException:
    self.logger().warning(f"No es plist binario: {full_path}")
```

## Salida CSV con separador pipe (estándar del proyecto)

```python
import csv

with open(os.path.join(outdir, 'salida.csv'), 'w') as f:
    writer = csv.writer(f, delimiter="|", quotechar='"')
    writer.writerow(["Col1", "Col2", "Col3"])
    writer.writerow([valor1, valor2, valor3])
```

## Plugins existentes para usar como referencia

| Si quieres parsear...        | Mira el módulo...              |
|------------------------------|-------------------------------|
| SQLite con fechas CoreData   | `KnowledgeC` o `NetworkUsage` |
| Plist binario                | `BasicInfo` o `Network`       |
| Ficheros por usuario         | `MacMRU`                      |
| Herramienta externa Python   | `FSEvents` o `MacMRU`         |
| CSV de salida                | `Network.GetNetworkInterfaceInfo` |
| Texto plano con secciones    | `KnowledgeC`                  |

---

# Guía de pruebas en macOS (portátil)

## Preparación del entorno

### Opción 1 — Docker (recomendada, más limpia)

```bash
# Construir la imagen
docker build -t rvt2 .

# Correr con acceso a tus imágenes forenses
docker run -it --rm \
  -v /ruta/a/morgue:/morgue \
  -v /ruta/a/imagen.E01:/imagen.E01 \
  rvt2 bash

# Dentro del contenedor, ejecutar tu módulo
python3 rvt2.py --morgue /morgue --client TEST --casename CASO -s fuente \
  -j plugins.macos.RVT_macos.MiModulo
```

### Opción 2 — Entorno virtual nativo en macOS

```bash
# Instalar dependencias del sistema
brew install python3 libplist

# Crear venv
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias Python
pip install biplist ujson

# Verificar que carga tu módulo
python3 -c "from plugins.macos.RVT_macos import MiModulo; print('OK')"
```

## Crear un caso de prueba sobre el Mac vivo

La forma más rápida: un script que crea el caso e indexa todo el Mac automáticamente.

```bash
# Ejecutar desde el directorio raíz de RVT2
bash plugins/macos/setup_test_mac.sh /tmp/rvt2_morgue
```

El script crea `mnt/p01 → /` (symlink al Mac real) y genera `alloc_files.txt`
con `find -L` sobre el filesystem completo. No copia ningún archivo.

**Estructura que genera RVT2 tras un mount real** (convención importante):
```
mnt/
└── p01/        ← raíz del filesystem directamente aquí (NO mnt/p01/root/)
    ├── System/
    ├── Library/
    ├── private/
    ├── Users/
    └── ...
```

Si prefieres copiar artefactos concretos (p.ej. para un caso mínimo):
```bash
mkdir -p /tmp/morgue/TEST/CASO/fuente/mnt/p01/System/Library/CoreServices/
cp /System/Library/CoreServices/SystemVersion.plist \
   /tmp/morgue/TEST/CASO/fuente/mnt/p01/System/Library/CoreServices/
cp /private/var/db/netusage.sqlite \
   /tmp/morgue/TEST/CASO/fuente/mnt/p01/private/var/db/
```

> Los ficheros del sistema requieren **Acceso Total al Disco** en Terminal:
> Ajustes del Sistema → Privacidad y Seguridad → Acceso Total al Disco

## Ejecutar un módulo individual

```bash
cd /ruta/a/rvt2
source .venv/bin/activate

# Módulo individual
python3 rvt2.py \
  --morgue /tmp/morgue \
  --client TEST \
  --casename CASO \
  -s fuente \
  -j plugins.macos.RVT_macos.MiModulo

# Con verbose para ver todos los logs
python3 rvt2.py -v \
  --morgue /tmp/morgue --client TEST --casename CASO -s fuente \
  -j plugins.macos.RVT_macos.MiModulo
```

## Probar con una imagen DMG real de macOS

```bash
# 1. Montar la imagen DMG (macOS lo hace nativamente)
hdiutil attach /ruta/imagen.dmg -mountpoint /Volumes/FuenteMac -readonly

# 2. Crear la estructura de caso apuntando al montaje
mkdir -p /tmp/morgue/TEST/CASO/fuente/mnt
ln -s /Volumes/FuenteMac /tmp/morgue/TEST/CASO/fuente/mnt/p1

# 3. Ejecutar
python3 rvt2.py --morgue /tmp/morgue --client TEST --casename CASO \
  -s fuente -j plugins.macos.RVT_macos.BasicInfo

# 4. Desmontar cuando termines
hdiutil detach /Volumes/FuenteMac
```

## Test unitario rápido para un módulo nuevo

```python
# test_mi_modulo.py
import sys, os
sys.path.insert(0, '/ruta/a/rvt2')

from base.config import default_config
from plugins.macos.RVT_macos import MiModulo

config = default_config()
config.read_dict({
    'DEFAULT': {
        'morgue': '/tmp/morgue',
        'client': 'TEST',
        'casename': 'CASO',
        'source': 'fuente',
        'rvthome': '/ruta/a/rvt2',
    }
})

module = MiModulo(config, section='plugins.macos.RVT_macos.MiModulo')
result = list(module.run())
print(f"Resultado: {len(result)} items")
```

```bash
python3 test_mi_modulo.py
```

## Comprobaciones rápidas de salida

```bash
# Ver qué ficheros generó tu módulo
ls -lh /tmp/morgue/TEST/CASO/fuente/output/macos/

# Ver el log del caso para errores
cat /tmp/morgue/TEST/CASO/fuente/*_aux.log

# Validar CSV pipe-delimited
python3 -c "
import csv
with open('/tmp/morgue/TEST/CASO/fuente/output/macos/resultado.csv') as f:
    reader = csv.reader(f, delimiter='|')
    for i, row in enumerate(reader):
        print(i, row)
        if i > 5: break
"
```
