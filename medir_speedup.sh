#!/bin/bash
#----------------------------------------------------------------------
# CC3069 - Laboratorio 03
# Verifica que la version secuencial mejorada y la version MPI recuperen
# la misma clave y mensaje, mide el tiempo de busqueda de ambas con
# 2, 3 y 4 procesos y calcula Speedup = T_secuencial / T_paralelo.
# Cada tiempo es el promedio de REPS ejecuciones. En cada repeticion se
# ejecutan todas las configuraciones (1, 2, 3 y 4 procesos) para que el
# calentamiento del equipo afecte a todas por igual.
#
# Uso: ./medir_speedup.sh [bits] [clave] [repeticiones]
#   ./medir_speedup.sh 20 12345 10      # escenario del enunciado
#   ./medir_speedup.sh 20 1048575 10    # recorre todo el rango 2^20
#   ./medir_speedup.sh 24 16777215 5    # recorre todo el rango 2^24
#----------------------------------------------------------------------
BITS=${1:-20}
KEY=${2:-12345}
REPS=${3:-10}
SEQ=./busqueda_clave_aes_secuencial_mejorado
PAR=./busqueda_clave_aes_mpi

# Extrae el valor de la linea "Tiempo:" de la salida.
tiempo() { awk '/^Tiempo:/ {print $2}'; }

# Ejecuta la version con n procesos (n = 1: secuencial) y muestra su tiempo.
ejecutar() {
    if [ "$1" -eq 1 ]; then
        $SEQ -b "$BITS" -k "$KEY" | tiempo
    else
        mpirun -np "$1" $PAR -b "$BITS" -k "$KEY" | tiempo
    fi
}

echo "Escenario: 2^$BITS candidatas, clave secreta $KEY, $REPS repeticiones"
echo

echo "Verificacion de resultados:"
seq_out=$($SEQ -b "$BITS" -k "$KEY")
par_out=$(mpirun -np 4 $PAR -b "$BITS" -k "$KEY")
seq_res=$(echo "$seq_out" | awk '/^Clave encontrada:/ {print $3} /^Mensaje:/')
par_res=$(echo "$par_out" | awk '/^Clave encontrada:/ {print $3} /^Mensaje:/')
echo "  Secuencial: $(echo $seq_res)"
echo "  MPI (4):    $(echo $par_res)"
if [ "$seq_res" = "$par_res" ]; then
    echo "  Ambas versiones recuperan la misma clave y mensaje."
else
    echo "  ERROR: los resultados no coinciden."
fi
echo

# Acumula los tiempos de cada configuracion.
declare -A suma
for ((r = 1; r <= REPS; r++)); do
    printf "Repeticion %d/%d\r" "$r" "$REPS"
    for n in 1 2 3 4; do
        t=$(ejecutar "$n")
        suma[$n]=$(awk -v a="${suma[$n]:-0}" -v b="$t" 'BEGIN { printf "%.6f", a + b }')
    done
done
echo

TS=$(awk -v s="${suma[1]}" -v r="$REPS" 'BEGIN { printf "%.6f", s / r }')

printf "| %-10s | %-15s | %-7s | %-10s |\n" \
    "Procesos" "Tiempo prom (s)" "Speedup" "Eficiencia"
printf "|%s|%s|%s|%s|\n" "------------" "-----------------" "---------" "------------"
printf "| %-10s | %15s | %7s | %10s |\n" "1 (sec.)" "$TS" "1.00" "100.0%"

for n in 2 3 4; do
    awk -v n="$n" -v ts="$TS" -v s="${suma[$n]}" -v r="$REPS" 'BEGIN {
        tp = s / r
        sp = ts / tp
        printf "| %-10s | %15.6f | %7.2f | %9.1f%% |\n", n, tp, sp, 100 * sp / n
    }'
done
