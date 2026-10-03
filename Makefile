CC = gcc
MPICC = mpicc
CFLAGS = -std=c11 -O2 -Wall -Wextra
LDLIBS = -lcrypto

PROGRAMAS = busqueda_clave_aes_secuencial \
            busqueda_clave_aes_secuencial_mejorado \
            busqueda_clave_aes_mpi

all: $(PROGRAMAS)

busqueda_clave_aes_secuencial: busqueda_clave_aes_secuencial.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

busqueda_clave_aes_secuencial_mejorado: busqueda_clave_aes_secuencial_mejorado.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

busqueda_clave_aes_mpi: busqueda_clave_aes_mpi.c
	$(MPICC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGRAMAS)

.PHONY: all clean
