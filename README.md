# CC3069 Laboratorio 03: búsqueda de una clave AES con Open MPI

Universidad del Valle de Guatemala, Computación Paralela y Distribuida, ciclo 2 de 2026.

**Integrantes:** María José Girón Isidro, Cindy Gualim Perez y Leonardo Dufrey Mejía Mejía.

El informe con las respuestas, el diagrama de flujo y las capturas está en [Laboratorio03_CC3069.pdf](Laboratorio03_CC3069.pdf).

## Archivos

| Archivo | Contenido |
| --- | --- |
| `busqueda_clave_aes_secuencial.c` | Programa original, sin cambios |
| `busqueda_clave_aes_secuencial_mejorado.c` | Versión secuencial con las mejoras |
| `busqueda_clave_aes_mpi.c` | Versión paralela con Open MPI |
| `Makefile` | Compila los tres programas |
| `medir_speedup.sh` | Compara ambas versiones y calcula el Speedup con 2, 3 y 4 procesos |
| `diagrama/` | Diagrama de flujo de AES-128 (imagen y archivo editable de draw.io) |

## Requisitos

Ubuntu o WSL con gcc, OpenSSL y Open MPI:

```bash
sudo apt update
sudo apt install build-essential libssl-dev openmpi-bin libopenmpi-dev
```

## Compilar y ejecutar

```bash
make
./busqueda_clave_aes_secuencial
./busqueda_clave_aes_secuencial_mejorado -k 12345
mpirun -np 4 ./busqueda_clave_aes_mpi -k 12345
./medir_speedup.sh 20 1048575 10
```

La versión mejorada y la paralela aceptan tres opciones: `-b` para la cantidad de claves a revisar (por ejemplo, `-b 20` son 2 elevado a 20 claves), `-k` para la clave secreta (si no se indica, se elige al azar) y `-m` para el mensaje.
