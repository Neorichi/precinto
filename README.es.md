# precinto

[English](README.md) · Español

> **precinto**: ligadura sellada que mantiene algo cerrado para que no se abra sino cuando y por quien corresponda.

precinto es una bóveda al estilo de KeePass para las sesiones de los agentes de programación con IA. Tú decides qué carpetas importan. Cuando una de ellas se bloquea (porque has dejado de teclear, porque se ha bloqueado la pantalla o porque lo pides), precinto sella en cápsulas cifradas con [age](https://age-encryption.org) las conversaciones, los resúmenes, las memorias, los planes, las salidas de herramientas y las notas que los agentes escribieron en ella. Para recuperarlas hace falta tu presencia (Touch ID o la contraseña del Mac, una llave de seguridad o una frase de paso), y todo vuelve a su sitio exactamente igual, byte a byte.

> **Estado: versión preliminar, especificación v0.2, en pleno desarrollo.** Los comandos de esta página describen la especificación v0.2 y se están implementando ahora mismo: puede que falte alguno o que cambie. Primero macOS; Linux, en parte; Windows, no. El repositorio todavía no es público y todas las decisiones de diseño son valores por defecto pendientes de que el responsable del proyecto las confirme, así que los detalles pueden cambiar.

## Índice

- [El problema](#el-problema)
- [Cómo funciona](#cómo-funciona)
- [Estado del proyecto](#estado-del-proyecto)
- [Instalación desde el código fuente](#instalación-desde-el-código-fuente)
- [Primeros pasos](#primeros-pasos)
- [Comandos habituales](#comandos-habituales)
- [Configuración](#configuración)
- [Herramientas compatibles](#herramientas-compatibles)
- [Contra qué no protege precinto](#contra-qué-no-protege-precinto)
- [Preguntas frecuentes](#preguntas-frecuentes)
- [Documentación](#documentación)
- [Licencia](#licencia)

## El problema

Los agentes de programación (Claude Code, Codex y compañía; precinto los llama *harnesses*) guardan en el disco, en texto plano, todo lo que se dice en cada sesión:

- la transcripción completa de cada conversación, con los archivos que leyó el agente, la salida de los comandos y todo lo que pegaste;
- datos derivados: resúmenes de compactación, memoria automática, planes, copias de los archivos editados, resultados de herramientas, listas de tareas, registros de depuración;
- el historial de tus mensajes, en un archivo aparte;
- las notas y los planes en Markdown que el agente escribe dentro de tu proyecto.

Esos archivos pasan semanas en tu carpeta personal, protegidos solo por los permisos del sistema de archivos, así que cualquier programa que se ejecute con tu usuario puede leerlos: un *infostealer* que se ejecute una sola vez, el script de instalación de un paquete, otro agente que rebusque en tu carpeta personal, una copia de seguridad o una carpeta sincronizada.

precinto mantiene esos archivos cifrados mientras nadie los usa, y te pide que estés presente antes de devolverlos.

## Cómo funciona

### Carpetas protegidas, una bóveda cada una

Una carpeta se protege con `precinto protect DIR`. Cada carpeta protegida tiene su propia bóveda: una identidad X25519 envuelta una vez por cada forma que tengas de desbloquearla (tus *factores*). Al desbloquear una carpeta solo se desenvuelve su clave, como si tuvieras una base de datos de KeePass por carpeta, de modo que un agente que trabaja en una carpeta no puede hacerse con la clave de otra sin ti. Una bóveda aparte, `global`, guarda los pocos almacenes del harness que no pertenecen a ninguna carpeta.

### Cápsulas

precinto agrupa los archivos que escribe cada harness en *unidades*: una sesión de Claude Code con sus subagentes y sus resultados de herramientas, la memoria automática de un proyecto, un plan, las líneas del historial que corresponden a una carpeta, el directorio de Codex de una carpeta, una nota en Markdown. Al sellar una unidad se escribe una *cápsula*: un único archivo age con un manifiesto y los bytes exactos de cada archivo. Cada cápsula se cifra para tres claves: la bóveda de la carpeta, tu clave de recuperación y una clave de un solo uso con la que precinto descifra y comprueba la cápsula antes de borrar el texto plano.

- Las cápsulas viven en el directorio de precinto (`~/Library/Application Support/precinto` en macOS; `$XDG_DATA_HOME/precinto`, por defecto `~/.local/share/precinto`, en Linux), nunca entre los archivos del harness ni en tu proyecto. De una nota sellada solo queda un pequeño marcador de texto, `NOMBRE.md.precinto`, donde estaba.
- Una cápsula nunca se sobrescribe. Cada nuevo sellado añade una *generación*, y las antiguas solo desaparecen cuando las borras tú (`precinto prune`, `precinto forget`).
- Solo se restauran las cápsulas que selló el propio precinto, anotadas en su registro de cápsulas, y solo en los lugares que admite su tipo de unidad.
- **Sellar nunca necesita una clave.** Cualquier tarea de precinto en segundo plano (un barrido, el final de una sesión, un bloqueo) puede sellar; solo restaurar te necesita a ti.

### Dos niveles de bloqueo

| Nivel | Qué ocurre |
|---|---|
| **Bloqueada** (bloqueo suave) | La clave de la carpeta se borra de la memoria al instante y sus sesiones quedan *en pausa*: los hooks de precinto bloquean los mensajes nuevos (también los automáticos), deniegan las herramientas y los diálogos de permisos y detienen la compactación. Si la sesión se lanzó a través de precinto, aparece además una pantalla de bloqueo que oculta la conversación y descarta lo que teclees; Intro desbloquea y Ctrl-D termina la sesión y la sella. Los archivos que ya no puede escribir ningún proceso se sellan. |
| **Terminada y sellada** (bloqueo fuerte) | Más tarde, las sesiones en pausa se *terminan*: precinto cierra el harness de forma ordenada, limpia la terminal y sella todo lo que escribió la sesión. Este es el paso que convierte una sesión viva en datos cifrados. |

Los mensajes de la herramienta están en inglés y solo hablan de *locked* (bloqueada), *paused* (en pausa) y *ended and sealed* (terminada y sellada). Un turno que esté en marcha cuando se bloquea la carpeta puede terminar (durante un máximo de 30 minutos desde el bloqueo), salvo después de `precinto lock`, que lo frena todo en el acto a menos que añadas `--let-finish`. Las sesiones en segundo plano de Claude Code (`--bg` y la vista de agentes) nunca se terminan: siguen en pausa y `precinto status` las señala.

### Qué bloquea una carpeta

| Cuándo | Qué ocurre | Ajuste |
|---|---|---|
| 15 min sin actividad tuya en la carpeta | la carpeta se bloquea | `idle_soft` |
| 60 min sin actividad tuya | las sesiones en pausa se terminan y se sellan | `idle_hard` |
| se bloquea la pantalla | todas las carpetas se bloquean a la vez; con 15 min seguidos de pantalla bloqueada se terminan las sesiones inactivas (las ocupadas, a los 30 min) | `lock_on_screen_lock`, `screen_lock_hard_after`, `busy_grace` |
| el ordenador entra en reposo | al despertar, todas las carpetas están bloqueadas | – |
| 8 h después de desbloquear | la carpeta se bloquea aunque sigas trabajando; avisa 10 min antes, y `precinto unlock --extend` vuelve a pedirte presencia | `max_unlock` (24 h como máximo) |
| `precinto lock` | se bloquean ya todas las carpetas (o una, con `--root DIR`); `--end` también termina las sesiones | – |
| arranca el daemon de precinto | todas las bóvedas empiezan bloqueadas | – |

"Actividad" quiere decir actividad humana: teclas pulsadas en una sesión lanzada a través de precinto, o un mensaje que precinto considera escrito por ti. Los bucles, las tareas programadas y demás mensajes automáticos nunca mantienen una carpeta desbloqueada. Ningún evento del sistema operativo desbloquea jamás una carpeta.

### Hooks y lanzador

precinto se conecta a cada harness de dos maneras:

- **Hooks**, de un plugin que instala `precinto integrate`. Antes de cada mensaje, llamada a herramienta, diálogo de permisos o compactación, el harness pregunta a precinto, que responde en milisegundos con el estado del daemon. En las sesiones de carpetas protegidas, cualquier fallo bloquea (*fail closed*); fuera de ellas, precinto no interfiere. Los hooks también anotan qué archivos ha tocado cada sesión y la ponen en cola para sellarla cuando termina.
- **El lanzador** (el *wrapper*): `precinto run`, o las funciones `claude` y `codex` que instala `precinto shell-init`. Pide el desbloqueo antes de arrancar el harness, restaura la sesión que vas a reanudar antes de que el harness la busque, dibuja la pantalla de bloqueo, termina la sesión limpiamente cuando toca y la sella al salir. La integración con la shell, además, ofrece desbloquear cuando entras con `cd` en una carpeta bloqueada.

Los hooks son una barrera, no una frontera de seguridad: un harness se puede arrancar con los hooks desactivados. Lo que protege tus datos es el cifrado en reposo, unas claves que solo custodia el daemon y unos barridos que no necesitan clave. Los detalles están en [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (en inglés).

### El daemon

`precinto agent` es un proceso por usuario que arranca solo cuando hace falta. Es el único que desenvuelve las claves de las bóvedas: las guarda en memoria bloqueada, nunca las escribe en disco y solo entrega claves de cápsulas concretas, solo al mismo ejecutable de precinto, solo para cápsulas que figuran en su registro y solo mientras todas las carpetas de esa cápsula estén desbloqueadas.

## Estado del proyecto

- **Versión preliminar, especificación v0.2** (sustituye a la v0.1). La especificación, el contrato de la API en Go y el plan de pruebas están escritos, y el código se está implementando ahora a partir de ellos. Faltarán comandos y habrá cambios incompatibles.
- **Primero macOS**: factor del Secure Enclave mediante `age-plugin-se`, disparadores por bloqueo de pantalla, inactividad y reposo, y un servicio opcional de resellado en segundo plano (un LaunchAgent).
- **Linux, en parte**: compila y funciona con una frase de paso como factor (o con un plugin de age, como una YubiKey), y lee el bloqueo de pantalla y la inactividad de `loginctl`. Todavía no hay servicio en segundo plano (`precinto service install` solo existe en macOS en la v0.2), y en las máquinas sin logind solo cuentan los temporizadores de inactividad y el límite de 8 horas.
- **Windows, no** (WSL se comporta como Linux).
- **Aún no es público**: no hay repositorio público, versiones publicadas ni descargas. La ruta del módulo Go, `github.com/precinto/precinto`, es provisional.
- **Las decisiones son provisionales**: cada entrada de [docs/DECISIONS.md](docs/DECISIONS.md) es un valor por defecto prudente a la espera de que lo confirme el responsable del proyecto, y puede cambiar.

## Instalación desde el código fuente

Necesitas una copia del repositorio y además:

- Go 1.21 o posterior, `make` y `git`. `go.mod` fija `toolchain go1.26.11`, así que, con el valor por defecto `GOTOOLCHAIN=auto`, el comando go descarga y usa Go 1.26.11 la primera vez que compilas (para eso necesita acceso de red al proxy de módulos de Go).
- En macOS, para el factor por defecto, `age-plugin-se` (`brew install age-plugin-se`; revisa qué versiones de macOS admite). Opcional: `pinentry-mac`, para desbloquear con una frase de paso o con un plugin desde dentro de un harness.
- En Linux, opcionales: `pinentry-gnome3`, y `age-plugin-yubikey` si quieres usar una YubiKey.

```sh
cd precinto                    # tu copia del repositorio
make build                     # genera bin/precinto (sin CGO, con -trimpath)
sudo install -m 0755 bin/precinto /usr/local/bin/precinto   # o cualquier directorio de tu PATH
precinto version
```

`make` usa el primer `go` de tu `PATH` que funcione; con `make GO=/ruta/a/go` eliges otro. No hay paquetes precompilados ni firmados. Cuando el repositorio sea público está previsto ofrecer `go install` y una fórmula de Homebrew que compile desde el código fuente (puede cambiar). Una compilación propia no está firmada ni notarizada, así que en macOS `precinto doctor` la señala como no endurecida (*unhardened build*); es lo normal.

Cada vez que sustituyas el binario, ejecuta `precinto agent --restart`: los clientes se niegan a hablar con un daemon que ejecuta otro binario.

## Primeros pasos

Ejecuta estos comandos tú, en tu propia terminal, no dentro de la sesión de un agente: precinto se niega a mostrar la clave de recuperación o a cambiar tus factores donde un agente pueda leerlos.

```sh
precinto init                       # 1. bóvedas, factor de desbloqueo y clave de recuperación (una sola vez)
precinto protect ~/work/acme        # 2. proteger una carpeta
precinto shell-init zsh --install   # 3. integración con la shell (o bash, fish)
precinto integrate claude-code      # 4. instalar los hooks
precinto integrate codex

cd ~/work/acme                      # 5. trabajar como siempre
claude                              #    pasa por precinto gracias al paso 3
precinto run codex                  #    la forma explícita, sin integración con la shell

precinto status                     # 6. qué está bloqueado, en marcha o todavía sin cifrar
precinto lock                       #    bloquear ya todas las carpetas
precinto lock --end                 #    ...y además terminar y sellar sus sesiones
precinto unlock                     #    desbloquear la carpeta en la que estás
precinto unlock --root ~/work/acme  #    o indicarla
```

1. **`precinto init`** crea tus bóvedas y tus factores. En macOS el factor por defecto es una clave del Secure Enclave creada con `age-plugin-se`, que se desbloquea con Touch ID o, si no tienes Touch ID emparejado, con la contraseña del Mac. En Linux te pide una frase de paso (al menos 12 caracteres; puede proponerte una de 7 palabras). Dentro de tmux, screen o SSH, donde el diálogo de macOS no puede aparecer, ofrece además una frase de paso como segundo factor. Después te muestra la clave de recuperación una sola vez, en una pantalla limpia, y te pide que escribas sus 4 últimos caracteres (con `--recovery-out ARCHIVO`, en cambio, la guarda en un archivo). En macOS ofrece también instalar el servicio de resellado en segundo plano. Comprueba la clave de recuperación con `precinto recover --verify`.
2. **`precinto protect DIR`** crea la bóveda de la carpeta y la registra. Opciones: `--md ledger|all|off` (qué Markdown sellar; por defecto, solo el que escribió un agente), `--on-enter prompt|notify|off`, `--harness LISTA` y `--claude-settings`. Ofrece añadir `*.md.precinto` al `.git/info/exclude` local del repositorio, que nunca se incluye en un commit. Las sesiones de Claude Code que tuviste en esa carpeta antes de protegerla aparecen en `precinto status`; séllalas con `precinto seal --adopt`. Las conversaciones anteriores de Codex se quedan en tu propio directorio de Codex, que precinto no sella.
3. **`precinto shell-init zsh|bash|fish`** imprime funciones de shell para tus harnesses y un hook que ofrece desbloquear al entrar en una carpeta bloqueada. `--install` añade una línea al archivo de arranque de tu shell después de preguntarte; también puedes añadirla a mano, por ejemplo `eval "$(precinto shell-init zsh)"`, o `precinto shell-init fish | source` en fish.
4. **`precinto integrate HARNESS`** instala el plugin de precinto con los propios comandos de plugins del harness (`--print` enseña los pasos sin ejecutarlos). Rechaza las versiones de Claude Code anteriores a la 2.1.295. Codex solo ejecuta los hooks de un plugin cuando confías en ellos: arranca Codex en la carpeta protegida a través de precinto, ejecuta `/hooks` y marca precinto como de confianza; precinto nunca lo hace por ti. Los hooks de Codex son opcionales: sin ellos, el historial de Codex se sella igualmente al salir, pero los mensajes no se pausan mientras la carpeta está bloqueada.
5. **`precinto run HARNESS [ARGS]`** (o la función de la shell) comprueba que la carpeta esté desbloqueada y, si no lo está, te lo pide; luego restaura lo que necesita la sesión, arranca el harness y sella la sesión al salir. Las sesiones que nunca tocan una carpeta protegida quedan al margen.
6. **`status`, `lock` y `unlock`**: consulta [Comandos habituales](#comandos-habituales). Tras un desbloqueo, precinto restaura en segundo plano las cinco sesiones más recientes de la carpeta, sus notas y su historial de mensajes.

## Comandos habituales

| Comando | Qué hace |
|---|---|
| `precinto status [--json] [--check]` | las carpetas y su estado, las sesiones, los archivos todavía sin cifrar y el motivo, el estado de los hooks y lo que requiere atención (cada aviso indica el comando que lo resuelve). Con `--check` sale con código 3 si alguna carpeta bloqueada conserva archivos sin cifrar. |
| `precinto unlock [--root DIR \| --all \| --global] [--for DURACIÓN] [--extend]` | desbloquear con tu presencia. `--all` la pide una vez por carpeta, tras una confirmación escrita. Desbloquear una carpeta la desbloquea en todas las terminales. |
| `precinto lock [--root DIR \| --all] [--end] [--let-finish] [--force]` | bloquear ya (por defecto, todas las carpetas). `--end` termina también las sesiones; `--force` no espera a que acabe una compactación en curso. |
| `precinto run [--harness H] [--no-pty] -- CMD [ARGS]` | ejecutar un harness a través de precinto |
| `precinto resume [ID \| --last \| --pick]` | restaurar una sesión de Claude Code y reanudarla |
| `precinto seal [--adopt] [--dry-run]` | sellar ahora; nunca necesita clave |
| `precinto ls [--root DIR] [--conflicts]` | listar las unidades y notas selladas |
| `precinto open ARCHIVO.md.precinto`, `precinto cat ARCHIVO.md.precinto` | restaurar una nota sellada en su sitio, o mostrarla |
| `precinto resolve ARCHIVO [--keep capsule\|plaintext]` | resolver un conflicto entre la versión sellada y la actual |
| `precinto prune`, `precinto forget ARCHIVO\|UNIDAD` | borrar generaciones antiguas, o las copias selladas de una unidad, tras una confirmación escrita |
| `precinto doctor [--leaks] [HARNESS]` | comprobaciones de solo lectura; `--leaks` busca copias fuera del alcance de precinto |
| `precinto service install\|uninstall\|status` | macOS: resellado en segundo plano cada 10 minutos (nunca guarda claves) |
| `precinto factor list\|add\|remove\|test`, `precinto recover --verify` | gestionar los factores; comprobar la clave de recuperación |

## Configuración

La configuración vive en `config.toml`, dentro del directorio de precinto. La tabla `[policy]` reúne los temporizadores y las opciones descritos más arriba, por ejemplo:

```toml
[policy]
idle_soft = "15m"              # bloquear tras este tiempo de inactividad
idle_hard = "60m"              # terminar las sesiones en pausa ("0" = nunca)
max_unlock = "8h"              # límite absoluto de un desbloqueo (24h como máximo)
lock_on_screen_lock = true
screen_lock_hard_after = "15m"
on_enter = "prompt"            # ofrecer el desbloqueo al entrar con cd en una carpeta bloqueada
unlock_on_prompt = false       # que un mensaje escrito en una sesión bloqueada abra el diálogo de desbloqueo
```

Los cambios que **rebajan** la protección (quitar una carpeta o un harness, alargar un temporizador, desactivar un disparador, sellar menos notas, relajar las peticiones de desbloqueo) quedan en espera hasta que, en tu próximo desbloqueo desde una terminal, precinto te los enseña y los confirmas. Los cambios más estrictos se aplican al momento. Así, ni otro programa que se ejecute con tu usuario ni un agente pueden rebajar la protección sin que te enteres. `unlock_on_prompt` viene desactivado; está previsto activarlo cuando su prueba de extremo a extremo pase en la versión de Claude Code de referencia.

## Herramientas compatibles

| Harness | Soporte | Cómo se conecta precinto |
|---|---|---|
| Claude Code | **Compatible.** Verificado con la 2.1.329; requiere la 2.1.295 o posterior | hooks del plugin (`precinto integrate claude-code`) y el lanzador |
| Codex CLI | **Compatible**, 0.154.x (verificado sobre su código fuente; las demás versiones muestran un aviso hasta que se verifiquen) | el lanzador da a cada carpeta protegida su propio directorio de Codex sellado; los hooks son opcionales y exigen que confíes en ellos desde Codex |
| Factory Droid, Cursor, GitHub Copilot CLI | **Experimental**, sin verificar | hooks del mismo plugin, que solo se activan con `precinto integrate <host> --experimental` |
| Gemini CLI, Kimi Code, Qwen Code, OpenCode | **Experimental** | solo el lanzador, con un inventario declarativo; el sellado es manual (`precinto seal --dormant <id> --experimental`) y no se restaura nada automáticamente |

Qué se sella con cada harness, cómo encajan los hooks y el lanzador, y las salvedades conocidas: [docs/HARNESSES.md](docs/HARNESSES.md) (en inglés).

## Contra qué no protege precinto

precinto acorta el tiempo que tus sesiones pasan en el disco como texto plano, pero no vuelve secreta una sesión que está en marcha. En concreto:

- **Malware que sigue ejecutándose con tu usuario.** Puede leer todo lo que esté desbloqueado o en uso, y capturar la clave de una carpeta la próxima vez que la desbloquees. Tener bóvedas separadas lo limita a las carpetas que desbloquees.
- **Sesiones en uso.** Los archivos de una sesión en marcha y los de una carpeta desbloqueada están en texto plano, en el disco y en memoria, al alcance de cualquier programa que se ejecute con tu usuario.
- **Copias en otros sitios.** Lo que guarden los proveedores de los modelos, la sincronización en la nube de un harness, y las copias hechas antes de proteger una carpeta o fuera del inventario de precinto: el índice de Spotlight, las instantáneas y copias de Time Machine tomadas con la carpeta desbloqueada, el historial y la restauración de sesiones de la terminal (iTerm2, Terminal.app, tmux-resurrect), el portapapeles y Handoff, el historial de notificaciones, los historiales de los editores, los objetos de git, los almacenes de la app de escritorio de Claude y los de los propios servidores MCP. `precinto doctor --leaks` informa de lo que encuentra.
- **Texto plano borrado en discos SSD.** Pueden sobrevivir bloques antiguos después de sellar y borrar un archivo. Activa FileVault, o el cifrado de disco en Linux.
- **Mensajes escritos con la carpeta bloqueada.** No llegan al modelo, pero el harness puede guardarlos igualmente en la transcripción y en su historial de mensajes. La copia de la transcripción se sella con la sesión; la línea del historial espera a la siguiente rotación, que exige cerrar todos los procesos de Claude Code. No escribas secretos en una sesión bloqueada.
- **Sesiones arrancadas sin el lanzador.** En la terminal de un IDE, en una app de escritorio o con `command claude`, un bloqueo solo detiene al modelo: la conversación sigue a la vista y los comandos locales como `/export` o `/copy` siguen funcionando. Si esa sesión tampoco tiene hooks que funcionen (plugin desactivado, `--bare`, `disableAllHooks`), una sesión interactiva de Claude Code se termina al bloquear y cualquier otra solo se notifica.
- **Hooks que dejan pasar cuando fallan.** Codex 0.154 deja seguir una acción cuando un hook agota su tiempo, y no ejecuta ningún hook en el que no hayas confiado. Claude Code 2.1.329 tiene una vía, condicionada por un indicador interno, que puede compactar pese al bloqueo de precinto. Copilot CLI no puede bloquear mensajes. Si el binario de precinto falla, su shim solo bloquea las sesiones cuyo directorio de trabajo o de proyecto está dentro de una carpeta protegida.
- **Codex arrancado sin precinto** en una carpeta protegida escribe en tu propio directorio de Codex, que precinto nunca sella; `status` y `doctor` cuentan esas conversaciones.
- **Metadatos.** Las rutas de las carpetas, cuántas sesiones hay y el tamaño y la fecha de las cápsulas se pueden leer sin clave. Los títulos y el contenido, no.
- **Un programa decidido que se ejecuta con tu usuario.** La detección de agentes y las confirmaciones escritas frenan los accidentes y a los agentes manipulados mediante inyección de instrucciones, no a un programa que se haga pasar por una terminal. precinto también confía en tu `$HOME`, en el `PATH` de tu shell y en su propio binario.

Y en la v0.2, además: una sesión grande se vuelve a cifrar entera cada vez que cambia; las líneas del historial de mensajes solo se sellan cuando no hay ningún proceso de Claude Code en marcha, y la memoria del proyecto, cuando ninguno trabaja en el repositorio de esa carpeta. La lista completa, con sus motivos, está en [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (en inglés).

## Preguntas frecuentes

### ¿precinto cifra mis archivos mientras trabajo?

No. Mientras una carpeta está desbloqueada, o mientras una sesión puede seguir escribiendo sus archivos, estos siguen en texto plano, justo donde el harness los espera. precinto nunca sella, mueve ni borra un archivo que un proceso pueda estar escribiendo: los harnesses van añadiendo líneas a sus transcripciones, y una transcripción que se aparta con la sesión en marcha pierde historial. Los archivos se sellan cuando la carpeta está bloqueada y ya nada los escribe, y como muy tarde cuando termina la sesión.

### ¿Qué pasa cuando el agente compacta la conversación?

La compactación añade un resumen al final de la misma transcripción, así que el resumen se sella junto con la sesión. Con la carpeta bloqueada, precinto detiene la compactación (un turno que ya estaba en marcha puede terminar). Cuando precinto arranca Claude Code en una carpeta protegida, desactiva además los resúmenes que Claude Code escribe en segundo plano mientras no estás (la compactación por inactividad, el resumen de ausencia y la compactación precalculada), porque añadirían texto plano nuevo a una sesión que todavía no se puede sellar. Lo que de verdad protege una conversación compactada es terminar la sesión. Más detalles en [docs/COMPACTION.md](docs/COMPACTION.md) (en inglés).

### ¿Cómo reanudo una sesión sellada?

Como siempre, pero a través de precinto: con la integración de la shell, `claude --resume ID`, `claude --continue` y el selector de `claude --resume` funcionan sin más, porque precinto restaura la transcripción antes de que arranque Claude Code (que la busca antes de que se ejecute ningún hook). Al desbloquear, las cinco sesiones más recientes de la carpeta vuelven en segundo plano, de modo que el selector de Claude Code las muestra; para las más antiguas usa `precinto resume --pick`, `precinto resume ID` o `precinto resume --last`. En Codex, todo el directorio de Codex de la carpeta se restaura antes de arrancar, así que `codex resume` también funciona a través de precinto.

Si arrancas un harness sin precinto y la sesión está sellada, el harness no la encontrará; en ese caso precinto te dice cómo reanudarla. Las restauraciones automáticas se saltan las sesiones de Claude Code que rozan el límite `cleanupPeriodDays` del propio Claude Code; si reanudas una de ellas a propósito, precinto la restaura con una fecha reciente para que Claude Code no la borre al arrancar. La copia sellada se conserva en cualquier caso.

### ¿Puedo tener varias sesiones a la vez?

Sí. Todas las sesiones de una carpeta comparten su bloqueo: un desbloqueo abre la carpeta en todas las terminales y un bloqueo las pausa todas. Cada sesión se sella cuando termina.

- Si abres una sesión que ya está en marcha en otra terminal, precinto te propone abrir una copia con `--fork-session`, porque dos procesos escribiendo la misma transcripción pueden perder mensajes.
- Una sesión que trabaja en dos carpetas protegidas queda en pausa en cuanto se bloquea cualquiera de ellas, y para restaurarse necesita las dos desbloqueadas.
- La memoria automática de Claude Code es común a todas las sesiones de un repositorio git, así que precinto solo la sella cuando ningún proceso de Claude Code trabaja en esa carpeta o en su repositorio.
- Carpetas dentro de carpetas: `protect` pide confirmación antes de aceptarlas, y prevalece la carpeta protegida más profunda.
- Varias carpetas: cada una tiene su bóveda y te pide presencia por separado; `precinto unlock --all` la pide una vez por carpeta.

### ¿Qué es la clave de recuperación y qué pasa si la pierdo?

`precinto init` crea una clave de recuperación por instalación. Todas las cápsulas se cifran también para ella y la clave de cada carpeta también se envuelve con ella, así que con ella recuperas tus datos si pierdes un factor: una frase de paso olvidada, una YubiKey perdida o una clave del Secure Enclave que se quedó en un Mac antiguo. Eso significa también que **quien tenga la clave de recuperación puede descifrar todas tus cápsulas**: guárdala fuera del ordenador.

- precinto solo se la muestra a una persona sentada ante una terminal real, nunca dentro de la sesión de un agente (acabaría en una transcripción y se enviaría al proveedor del modelo): una sola vez, en una pantalla limpia, y te pide que escribas sus 4 últimos caracteres. Con `--recovery-out ARCHIVO` la guarda en un archivo, pero no dentro de una carpeta protegida, del directorio de datos de un harness ni de una carpeta sincronizada.
- Compruébala con `precinto recover --verify`; hasta entonces, `precinto status` avisa de que nunca se ha probado ("recovery key: never tested").
- La usan `precinto recover` y, si alguien ha manipulado el archivo de una bóveda, `precinto vault repair --recovery`.
- Si pierdes la clave de recuperación pero tu factor habitual sigue funcionando, no pierdes nada, aunque la v0.2 no puede emitir una nueva (`rekey` llegará en una versión posterior).

### ¿Puede un agente desbloquear la carpeta o leer archivos sellados?

No por su cuenta. El plugin de precinto no trae ningún comando para desbloquear, y su *skill* indica al modelo que nunca ejecute unlock, restore, cat, open ni recover. Cuando un comando llega desde dentro de la sesión de un agente, precinto se niega a desbloquear cualquier carpeta que no sea la de esa sesión, y para esa solo puede abrir un diálogo de desbloqueo en tu pantalla (Secure Enclave o pinentry) que tienes que aprobar tú. Restaurar, abrir o mostrar contenido sellado vuelve a pedir tu presencia aunque la carpeta esté desbloqueada. `init`, los cambios de factores, la clave de recuperación, `vault repair`, `prune`, `forget` y `unprotect` se rechazan. Estas comprobaciones frenan accidentes y agentes manipulados, no al malware que se ejecuta con tu usuario.

### ¿Y si se cuelga precinto, su daemon o el ordenador?

Cada sellado y cada restauración quedan anotados en un diario y aguantan las caídas: un cuelgue o un corte de luz en cualquier paso no pierde datos, y el siguiente barrido termina o deshace lo que hubiera quedado a medias. Como sellar no necesita clave, lo que quede suelto se sella aunque no haya nada desbloqueado. Si el daemon no está en marcha, los hooks mantienen bloqueadas las sesiones de las carpetas protegidas en lugar de dejarlas pasar; `precinto unlock` lo vuelve a arrancar.

### ¿Qué cambia precinto en mis proyectos?

Muy poco. Las cápsulas viven en el directorio de precinto. Una nota sellada deja un marcador `NOMBRE.md.precinto` (texto plano, sin nada cifrado dentro); perder un marcador no hace perder nada, y la nota vuelve igualmente al desbloquear. precinto solo añade `*.md.precinto` al `.git/info/exclude` local de un repositorio si lo aceptas al proteger la carpeta, y solo escribe ajustes de Claude Code en un proyecto si se lo pides con `protect --claude-settings`. Los archivos controlados por git y los de instrucciones (`README.md`, `CLAUDE.md`, `AGENTS.md` y otros) nunca se sellan.

### ¿Cómo dejo de proteger una carpeta?

Con `precinto unprotect DIR`. Primero restaura todo lo de la carpeta, así que esta tiene que estar desbloqueada, y te pide una confirmación escrita. precinto nunca borra cápsulas por iniciativa propia: solo lo hacen `prune`, `forget` y `unprotect`, después de enumerar lo que van a borrar y pedirte una confirmación escrita.

### ¿Por qué `precinto doctor` avisa de carpetas dentro de Documentos, Descargas o Escritorio?

Los controles de privacidad de macOS pueden impedir que el servicio en segundo plano lea esas carpetas. En ese caso, sus sesiones las sellan los procesos de precinto arrancados desde tu terminal, o quedan marcadas como inaccesibles; nunca se dan por desaparecidas.

## Documentación

La documentación detallada está en inglés:

| Documento | Contenido |
|---|---|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | activos, adversarios, fronteras de confianza, alcance y riesgos residuales |
| [docs/HARNESSES.md](docs/HARNESSES.md) | qué se sella con cada harness, hooks, lanzador y salvedades |
| [docs/COMPACTION.md](docs/COMPACTION.md) | compactación y resúmenes en segundo plano, con la carpeta bloqueada y desbloqueada |
| [docs/SPEC.md](docs/SPEC.md) | la especificación normativa (v0.2) |
| [docs/DECISIONS.md](docs/DECISIONS.md) | las decisiones de diseño y su estado |
| [docs/HOOKS-IO.md](docs/HOOKS-IO.md) | entradas y salidas exactas de los hooks de cada harness |
| [docs/API.md](docs/API.md), [docs/TESTPLAN.md](docs/TESTPLAN.md) | el contrato en Go y el plan de pruebas, para quien contribuya |
| [SECURITY.md](SECURITY.md) | cómo informar de una vulnerabilidad |
| [CONTRIBUTING.md](CONTRIBUTING.md) | compilación, pruebas, organización del código y la firma DCO |
| [TRADEMARKS.md](TRADEMARKS.md) | uso del nombre precinto y de los nombres de terceros |

## Licencia

precinto se distribuye bajo la [licencia Apache 2.0](LICENSE); el software de terceros figura en [NOTICE](NOTICE). Las contribuciones se aceptan bajo el Developer Certificate of Origin ([CONTRIBUTING.md](CONTRIBUTING.md)). precinto es un proyecto independiente, sin vínculo con ningún fabricante de harnesses ni respaldo por su parte ([TRADEMARKS.md](TRADEMARKS.md)).
