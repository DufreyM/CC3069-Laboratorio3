/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Laboratorio: 03
 * Ejercicio:   Busqueda paralela de una clave AES con Open MPI
 * Descripcion: version paralela de busqueda_clave_aes_secuencial_mejorado.c.
 *
 *              - El proceso 0 actua como emisor: cifra el mensaje con
 *                AES-128-GCM y difunde solo los datos publicos
 *                (IV, texto cifrado y etiqueta) con MPI_Bcast.
 *              - Distribucion ciclica: el proceso r de p prueba las
 *                candidatas r, r + p, r + 2p, ... Cada candidata c
 *                pertenece unicamente al proceso c mod p, por lo que
 *                ninguna se omite ni se repite.
 *              - Cada CHECK_INTERVAL candidatas los procesos comparten
 *                su resultado con MPI_Allreduce (MPI_MIN). Si alguno
 *                encontro la clave, todos terminan; si no, terminan
 *                juntos al agotar el rango.
 *
 * Compilacion: mpicc -std=c11 -O2 -Wall -Wextra
 *                  busqueda_clave_aes_mpi.c
 *                  -o busqueda_clave_aes_mpi -lcrypto
 * Uso:         mpirun -np 4 ./busqueda_clave_aes_mpi
 *                  [-b bits] [-k clave] [-m mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define KEY_LEN 16              /* AES-128: clave de 128 bits */
#define IV_LEN 12               /* IV de 96 bits recomendado para GCM */
#define TAG_LEN 16              /* etiqueta de autenticacion de 128 bits */
#define MAX_MESSAGE_LEN 256
#define DEFAULT_BITS 20         /* 2^20 = 1,048,576 candidatas */
#define MAX_BITS 40
#define NOT_FOUND UINT64_MAX

/* Candidatas que prueba cada proceso entre dos sincronizaciones. */
#ifndef CHECK_INTERVAL
#define CHECK_INTERVAL 512
#endif

#define AES128_KEY_SPACE 3.4028236692093846e38     /* 2^128 */
#define SECONDS_PER_YEAR (365.25 * 24.0 * 3600.0)

static const char default_message[] = "Puedes lograrlo!";

/* Datos que conoce el atacante: no incluyen la clave ni el texto original. */
typedef struct {
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char cipher[MAX_MESSAGE_LEN];
    int length;
} public_data;

/* Parametros de la ejecucion. */
typedef struct {
    int bits;
    uint64_t total;             /* 2^bits candidatas */
    uint64_t secret;
    int random_secret;
    const char *message;
} options;

/* Muestra el error y detiene a todos los procesos. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    exit(EXIT_FAILURE);
}

/*
 * Construye la clave de 128 bits a partir de la candidata.
 * Misma representacion que la version secuencial.
 */
static void make_key(uint64_t candidate, unsigned char key[KEY_LEN])
{
    memset(key, 0, KEY_LEN);

    for (int i = 0; i < 8; i++) {
        key[KEY_LEN - 1 - i] = (unsigned char)(
            (candidate >> (8 * i)) & UINT64_C(0xFF)
        );
    }
}

/* Elige una clave secreta uniforme en [0, total) con un generador criptografico. */
static uint64_t random_candidate(uint64_t total)
{
    uint64_t value = 0;

    if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) {
        fail("Error al generar numeros aleatorios.");
    }

    /* total es potencia de 2, por lo que la mascara no introduce sesgo. */
    return value & (total - 1);
}

/*
 * Cifra el mensaje con AES-128-GCM y un IV aleatorio.
 * Representa al emisor: es la unica funcion que usa la clave secreta.
 */
static void encrypt_message(
    uint64_t secret,
    const unsigned char *message,
    int length,
    public_data *out)
{
    unsigned char key[KEY_LEN];
    int written = 0;
    int final_written = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    make_key(secret, key);

    /* Un IV nuevo en cada cifrado evita que dos mensajes iguales coincidan. */
    if (RAND_bytes(out->iv, IV_LEN) != 1) {
        fail("Error al generar el IV.");
    }

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_128_gcm(), NULL,
            key, out->iv) != 1) {
        fail("Error al inicializar AES-GCM.");
    }

    if (EVP_EncryptUpdate(
            ctx, out->cipher, &written,
            message, length) != 1) {
        fail("Error al cifrar el mensaje.");
    }

    if (EVP_EncryptFinal_ex(
            ctx, out->cipher + written, &final_written) != 1) {
        fail("Error al finalizar el cifrado.");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG,
            TAG_LEN, out->tag) != 1) {
        fail("Error al obtener la etiqueta GCM.");
    }

    out->length = written + final_written;

    /* La clave no debe quedar en memoria despues de usarse. */
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(ctx);
}

/* Configura AES-128-GCM una sola vez; despues solo se cambia la clave. */
static EVP_CIPHER_CTX *create_search_context(void)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    if (EVP_DecryptInit_ex(
            ctx, EVP_aes_128_gcm(), NULL,
            NULL, NULL) != 1) {
        fail("Error al inicializar AES-GCM.");
    }

    return ctx;
}

/*
 * Intenta descifrar con una candidata.
 * Devuelve 1 solo si la etiqueta GCM coincide, es decir, si la clave
 * es correcta. No necesita conocer el texto original.
 */
static int try_key(
    EVP_CIPHER_CTX *ctx,
    uint64_t candidate,
    const public_data *data,
    unsigned char *plain)
{
    unsigned char key[KEY_LEN];
    int written = 0;
    int final_written = 0;

    make_key(candidate, key);

    /* cipher = NULL: reutiliza el algoritmo ya configurado en ctx. */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, data->iv) != 1) {
        fail("Error al cambiar la clave.");
    }

    if (EVP_DecryptUpdate(
            ctx, plain, &written,
            data->cipher, data->length) != 1) {
        fail("Error al descifrar el mensaje.");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG,
            TAG_LEN, (void *)data->tag) != 1) {
        fail("Error al configurar la etiqueta GCM.");
    }

    /* Devuelve 0 cuando la etiqueta no coincide: clave incorrecta. */
    return EVP_DecryptFinal_ex(ctx, plain + written, &final_written) == 1;
}

static void print_hex(const char *label, const unsigned char *data, int length)
{
    printf("%s", label);

    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }

    putchar('\n');
}

/* Muestra el rendimiento y lo extrapola al espacio completo de AES-128. */
static void print_rate(uint64_t tested, double elapsed)
{
    if (elapsed <= 0.0) {
        return;
    }

    double rate = (double)tested / elapsed;
    double years = AES128_KEY_SPACE / rate / SECONDS_PER_YEAR;

    printf("Rendimiento: %.0f claves/s\n", rate);
    printf("Tiempo estimado para 2^128 claves: %.3e años\n", years);
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Uso: mpirun -np <procesos> %s [-b bits] [-k clave] [-m mensaje]\n"
        "  -b bits     explora 2^bits candidatas (1-%d, por defecto %d)\n"
        "  -k clave    clave secreta para pruebas reproducibles\n"
        "              (por defecto: aleatoria dentro del rango)\n"
        "  -m mensaje  texto a cifrar (1-%d bytes, por defecto \"%s\")\n",
        program, MAX_BITS, DEFAULT_BITS,
        MAX_MESSAGE_LEN, default_message);
}

/* Convierte un entero decimal sin signo validando todo el texto. */
static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;

    if (text[0] == '-') {
        return 0;
    }

    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }

    *value = (uint64_t)parsed;
    return 1;
}

static int parse_options(int argc, char *argv[], options *opt)
{
    int option;
    uint64_t value;

    opt->bits = DEFAULT_BITS;
    opt->secret = 0;
    opt->random_secret = 1;
    opt->message = default_message;

    while ((option = getopt(argc, argv, "b:k:m:")) != -1) {
        switch (option) {
        case 'b':
            if (!parse_u64(optarg, &value) ||
                value < 1 || value > MAX_BITS) {
                return 0;
            }
            opt->bits = (int)value;
            break;
        case 'k':
            if (!parse_u64(optarg, &value)) {
                return 0;
            }
            opt->secret = value;
            opt->random_secret = 0;
            break;
        case 'm':
            opt->message = optarg;
            break;
        default:
            return 0;
        }
    }

    size_t length = strlen(opt->message);

    if (optind != argc || length == 0 || length > MAX_MESSAGE_LEN) {
        return 0;
    }

    opt->total = UINT64_C(1) << opt->bits;
    return 1;
}

int main(int argc, char *argv[])
{
    int rank;
    int size;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    /*
     * Todos los procesos reciben los mismos argumentos, asi que todos
     * llegan a la misma conclusion. Solo el proceso 0 muestra mensajes.
     */
    options opt;

    opterr = 0;

    if (!parse_options(argc, argv, &opt)) {
        if (rank == 0) {
            usage(argv[0]);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    /* Emisor: el proceso 0 cifra el mensaje con la clave secreta. */
    public_data data;

    memset(&data, 0, sizeof(data));

    if (rank == 0) {
        if (opt.random_secret) {
            opt.secret = random_candidate(opt.total);
        }

        encrypt_message(
            opt.secret,
            (const unsigned char *)opt.message,
            (int)strlen(opt.message),
            &data);

        printf("Algoritmo: AES-128-GCM (IV aleatorio de 96 bits)\n");
        printf("Rango explorado: 2^%d = %" PRIu64 " candidatas de 2^128\n",
               opt.bits, opt.total);
        printf("Procesos: %d (distribucion ciclica)\n", size);
        print_hex("Texto cifrado (hex): ", data.cipher, data.length);

        if (opt.secret >= opt.total) {
            printf("Aviso: la clave secreta esta fuera del rango explorado.\n");
        }
    }

    /* Los demas procesos solo reciben los datos publicos. */
    MPI_Bcast(&data, (int)sizeof(data), MPI_BYTE, 0, MPI_COMM_WORLD);

    EVP_CIPHER_CTX *ctx = create_search_context();
    unsigned char plain[MAX_MESSAGE_LEN];

    /*
     * Distribucion ciclica: el proceso r prueba r, r + p, r + 2p, ...
     * El proceso 0 es el que tiene mas candidatas, ceil(total / p);
     * con ese valor se calcula cuantas rondas de sincronizacion hacen
     * falta, y todos los procesos ejecutan la misma cantidad.
     */
    uint64_t step = (uint64_t)size;
    uint64_t candidate = (uint64_t)rank;
    uint64_t per_process = (opt.total + step - 1) / step;
    uint64_t rounds = (per_process + CHECK_INTERVAL - 1) / CHECK_INTERVAL;
    uint64_t found_local = NOT_FOUND;
    uint64_t found = NOT_FOUND;
    uint64_t tested = 0;

    /* La medicion comienza cuando todos los procesos estan listos. */
    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    for (uint64_t round = 0; round < rounds && found == NOT_FOUND; round++) {
        for (int i = 0;
             i < CHECK_INTERVAL &&
             candidate < opt.total &&
             found_local == NOT_FOUND;
             i++) {
            tested++;

            if (try_key(ctx, candidate, &data, plain)) {
                found_local = candidate;
            }

            candidate += step;
        }

        /* Todos conocen el resultado; si alguno encontro la clave, terminan. */
        MPI_Allreduce(
            &found_local, &found, 1,
            MPI_UINT64_T, MPI_MIN, MPI_COMM_WORLD);
    }

    double elapsed_local = MPI_Wtime() - start;
    double elapsed = 0.0;
    uint64_t tested_total = 0;

    /* El tiempo paralelo es el del proceso que termina al final. */
    MPI_Reduce(
        &elapsed_local, &elapsed, 1,
        MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(
        &tested, &tested_total, 1,
        MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        if (found != NOT_FOUND) {
            unsigned char key[KEY_LEN];

            /* El proceso 0 recupera el mensaje con la clave encontrada. */
            if (!try_key(ctx, found, &data, plain)) {
                fail("La clave encontrada no valida la etiqueta GCM.");
            }

            make_key(found, key);
            printf("Clave encontrada: %" PRIu64 " (por el proceso %" PRIu64 ")\n",
                   found, found % step);
            print_hex("Clave AES (hex): ", key, KEY_LEN);
            printf("Mensaje: ");
            fwrite(plain, 1, (size_t)data.length, stdout);
            putchar('\n');
            printf("Verificacion: %s\n",
                   found == opt.secret
                       ? "coincide con la clave usada para cifrar"
                       : "NO coincide con la clave usada para cifrar");
        } else {
            printf("No se encontro la clave.\n");
        }

        printf("Candidatas probadas: %" PRIu64 "\n", tested_total);
        printf("Ejecucion: paralela (Open MPI, %d procesos)\n", size);
        printf("Tiempo: %.6f segundos\n", elapsed);
        print_rate(tested_total, elapsed);
    }

    EVP_CIPHER_CTX_free(ctx);
    MPI_Finalize();

    return EXIT_SUCCESS;
}
