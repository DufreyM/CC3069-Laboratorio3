/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Laboratorio: 03
 * Ejercicio:   Busqueda secuencial de una clave AES (version mejorada)
 * Descripcion: un unico proceso prueba claves candidatas en orden.
 *
 *              Cambios respecto a busqueda_clave_aes_secuencial.c:
 *              - AES-128-GCM con IV aleatorio en lugar de ECB.
 *              - La busqueda solo usa datos publicos (IV, texto
 *                cifrado y etiqueta). Una candidata es correcta cuando
 *                la etiqueta de autenticacion GCM es valida, por lo que
 *                no se compara contra el texto original.
 *              - La clave secreta no esta fija en el codigo: se elige
 *                con RAND_bytes dentro del rango o se recibe con -k.
 *              - Rango, clave y mensaje configurables por argumentos.
 *              - El algoritmo se configura una sola vez en el contexto;
 *                para cada candidata solo se cambia la clave.
 *              - Se reporta el rendimiento y la extrapolacion al
 *                espacio completo de 2^128 claves.
 *
 * Compilacion: gcc -std=c11 -O2 -Wall -Wextra
 *                  busqueda_clave_aes_secuencial_mejorado.c
 *                  -o busqueda_clave_aes_secuencial_mejorado -lcrypto
 * Uso:         ./busqueda_clave_aes_secuencial_mejorado
 *                  [-b bits] [-k clave] [-m mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
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

/* Muestra el error y termina el programa. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * Construye la clave de 128 bits a partir de la candidata.
 * Se conserva la representacion del programa original: la candidata
 * ocupa los bytes menos significativos y el resto queda en cero.
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

/* Obtiene el tiempo de un reloj monotono, en segundos. */
static double get_time(void)
{
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        perror("Error al consultar el reloj");
        exit(EXIT_FAILURE);
    }

    return (double)current.tv_sec +
           (double)current.tv_nsec / 1000000000.0;
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
        "Uso: %s [-b bits] [-k clave] [-m mensaje]\n"
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
    options opt;

    if (!parse_options(argc, argv, &opt)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (opt.random_secret) {
        opt.secret = random_candidate(opt.total);
    }

    /* Emisor: cifra el mensaje con la clave secreta. */
    public_data data;

    encrypt_message(
        opt.secret,
        (const unsigned char *)opt.message,
        (int)strlen(opt.message),
        &data);

    printf("Algoritmo: AES-128-GCM (IV aleatorio de 96 bits)\n");
    printf("Rango explorado: 2^%d = %" PRIu64 " candidatas de 2^128\n",
           opt.bits, opt.total);
    print_hex("Texto cifrado (hex): ", data.cipher, data.length);

    if (opt.secret >= opt.total) {
        printf("Aviso: la clave secreta esta fuera del rango explorado.\n");
    }

    /* Atacante: a partir de aqui solo se usan los datos publicos. */
    EVP_CIPHER_CTX *ctx = create_search_context();
    unsigned char plain[MAX_MESSAGE_LEN];
    uint64_t found = NOT_FOUND;
    uint64_t tested = 0;

    /* La medicion comienza despues de preparar el mensaje. */
    double start = get_time();

    /* Prueba las claves consecutivamente desde cero. */
    for (uint64_t candidate = 0; candidate < opt.total; candidate++) {
        tested++;

        if (try_key(ctx, candidate, &data, plain)) {
            found = candidate;
            break;
        }
    }

    double elapsed = get_time() - start;

    if (found != NOT_FOUND) {
        unsigned char key[KEY_LEN];

        make_key(found, key);
        printf("Clave encontrada: %" PRIu64 "\n", found);
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

    printf("Candidatas probadas: %" PRIu64 "\n", tested);
    printf("Ejecucion: secuencial\n");
    printf("Tiempo: %.6f segundos\n", elapsed);
    print_rate(tested, elapsed);

    EVP_CIPHER_CTX_free(ctx);

    return EXIT_SUCCESS;
}
