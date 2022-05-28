#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <threads.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>

#include <tomcrypt.h>

/* because DES discards all LSBs of every byte,
 * the hex alphabet can be reduced by masking out LSB from all characters */
const char *keychars = "02468@BDF";
const char *hexchars = "0123456789ABCDEF";

/* powl(9,8) == 43046721,
 * the key is about 25.3594 bits,
 * a very small space for brute-force searching */
#define KEYSPACE_SIZE 43046721u

/*
 * BIN2HEX: convert one byte from a byte array to a hex array
 * NOTE: this routine assumes little-endian 16-bit integer
 * bin: pointer to binary data
 * hex: pointer to output buffer
 * i: which byte to write to hex
*/
#define BIN2HEX(bin, hex, i) \
        (((uint16_t*)(hex))[i] = \
        (hexchars[(((const char*)(bin))[i] >> 4u) & 0x0Fu]) | \
        (hexchars[(((const char*)(bin))[i]) & 0x0Fu] << 8u))

int pkcs7_check_pad(const char *buf, size_t n);

typedef struct s_key_search_ctx {
    /* first 8 bytes and the last 8 bytes of the ciphertext
     * in encrypted QQ flash image */
    const char *ciphertext;
    /* if routine `yield_possible_key` returns true,
     * the possible 64-bit DES key will be stored here */
    uint64_t yield;
    /* 4 byte effective key space */
    uint32_t next_possible_key;
    /* length of ciphertext */
    uint32_t len;
    bool finished;
} key_search_ctx;

/* constructor of type `key_search_ctx` */
void new_key_search_ctx(
        key_search_ctx *ctx,
        const char *ciphertext,
        uint32_t ciphertext_len,
        uint32_t a
) {
    ctx->finished = false;
    ctx->next_possible_key = a;
    ctx->ciphertext = ciphertext;
    ctx->len = ciphertext_len;
}

/* search key in range [a, b), returns false if
 * no result yield from this call and searching is finished */
bool yield_possible_key(
        key_search_ctx *ctx,
        uint32_t b,
        atomic_bool *stop_signal
) {
    if (ctx->finished) return false;

/*
 * FILL_KEY: convert DES key from integer in search space to 8 bytes
 * buf: char[8]
 * key: uint64_t (high bits unused)
 * i:uint = 0, 1, 2, ..., 7
*/
#define FILL_KEY(buf, key, i) \
        do { ((buf)[7-(i)] = keychars[(key)%9u]); (key) /= 9u; } while(0)

    uint32_t k = ctx->next_possible_key;
    uint64_t plaintext;
    char key[8];
    symmetric_key skey;
    /* check `stop_signal` after every 256 round of loop */
    uint8_t check_stop = 0;
    do {
        if ((b != 0 && k >= b) || (!check_stop++ && atomic_load(stop_signal))) {
            /* out of range, finish searching */
            ctx->finished = true;
            return false;
        }
        /* convert key uint32 to char[],
         * here FILL_KEY will modify key,
         * so we use a temp variable */
        uint32_t k_tmp = k;
        FILL_KEY(key, k_tmp, 0);
        FILL_KEY(key, k_tmp, 1);
        FILL_KEY(key, k_tmp, 2);
        FILL_KEY(key, k_tmp, 3);
        FILL_KEY(key, k_tmp, 4);
        FILL_KEY(key, k_tmp, 5);
        FILL_KEY(key, k_tmp, 6);
        FILL_KEY(key, k_tmp, 7);
        /* decrypt file header with this key */
        int err;
        if ((err = des_setup((const unsigned char *) key, 8, 0, &skey)) !=
            CRYPT_OK) {
            fprintf(stderr, "Err: setup: %s", error_to_string(err));
            return false;
        }
        /* decrypt the first 8 bytes */
        if (des_ecb_decrypt(
                (const unsigned char *) (ctx->ciphertext),
                (unsigned char *) &plaintext,
                (const symmetric_key *) &skey
        ) != CRYPT_OK)
            continue; /* failed to decrypt, skip this key */
        /* validate JPEG header (first 3 bytes) of the plaintext */
        if ((plaintext & 0xFFFFFFu) != 0xFFD8FFu)
            continue; /* invalid JPEG header */

        /* decrypt the last 8 bytes */
        if (des_ecb_decrypt(
                (const unsigned char *) (ctx->ciphertext + ctx->len - 8),
                (unsigned char *) &plaintext,
                (const symmetric_key *) &skey
        ) != CRYPT_OK)
            continue; /* failed to decrypt, skip this key */
        if (pkcs7_check_pad((const char *) &plaintext, 8) < 0)
            continue; /* invalid pkcs7 padding */

        /* all checks passed, this may be a valid key, yield it */
        ctx->yield = *(uint64_t *) key;
        /* if `next_possible_key` goes out of range,
         * it means that we have searched all possible keys */
        ctx->finished = ++ctx->next_possible_key >= b;
        return true;
        /* if b == 0 and k == 0, finish searching */
    } while ((k = ++ctx->next_possible_key) || b != 0);
    ctx->finished = true;
    return false;
}

/* given buf, returns length of the pad, or -1 if
 * the data is not padded with valid pkcs7 */
int pkcs7_check_pad(const char *buf, size_t n) {
    if (!n) return -1;
    if (n == 1) {
        /* if total length is 1, the only valid string is 0x1 */
        return (buf[0] == 1u) ? 1 : -1;
    }
    --n;
    unsigned char pad = buf[n--];
    if (!pad) return -1;
    if (n < pad) return -1; /* buf is shorter than a valid pad */
    for (int i = pad; i > 1; --i) {
        if (buf[n--] != pad) return -1;
    }
    return pad;
}

/* initialized in main function */
typedef struct s_thread_param {
    /* search range */
    uint32_t a;
    uint32_t b;
    int worker_id;
} thread_param;

/* if a worker find this to be true, it will terminate */
atomic_bool key_found;
/* shared across workers */
const char *volatile ciphertext;
/* should not be modified by workers */
uint32_t ciphertext_len;
/* the result generated by a lucky worker */
volatile struct {
    char *plaintext;
    uint32_t len;
} crack_result;

int thread_worker(thread_param *param) {
    key_search_ctx ctx;
    const uint32_t b = param->b; /* search end */
    uint32_t ciphertext_length = ciphertext_len;
    new_key_search_ctx(&ctx, ciphertext, ciphertext_length, param->a);
    char *plaintext = malloc(ciphertext_length);
    if (plaintext == NULL) {
        perror("malloc");
        return 1;
    }
    while (yield_possible_key(&ctx, b, &key_found)) {
        /* we have found a potential DES key */

        /* QQ encrypts flash photo with the first 8 bytes
         * of the uppercase md5 hex string of the photo,
         * so we validate the key using this characteristic */

        /* decrypt the whole ciphertext */
        int err;
        symmetric_key skey;
        if ((err = des_setup((const unsigned char *) (&ctx.yield), 8, 0,
                             &skey)) != CRYPT_OK) {
            fprintf(stderr, "Err: setup: %s", error_to_string(err));
            continue;
        }

        uint_fast32_t blk_cnt = ciphertext_length >> 3;
        for (uint_fast32_t blk = 0; blk < blk_cnt; ++blk) {
            des_ecb_decrypt(
                    (const unsigned char *) ((uint64_t *) ciphertext + blk),
                    (unsigned char *) ((uint64_t *) plaintext + blk),
                    (const symmetric_key *) &skey
            );
            /* error checking is unnecessary here */
        }

        int pad_length = pkcs7_check_pad(plaintext, ciphertext_length);
        const unsigned int unpadded_length = ciphertext_length - pad_length;
        assert(pad_length < ciphertext_length);
        if (pad_length < 0) {
            /* invalid pad, this key is incorrect, skip it */
            continue;
        }

        /* calculate md5 checksum of the decrypted plaintext */
        char md5_out[16];
        hash_state md;
        md5_init(&md);
        md5_process(&md, (const unsigned char *) plaintext, unpadded_length);
        md5_done(&md, (unsigned char *) md5_out);

        /* compare md5_out[0~3] with 8-byte ASCII hex string ctx.yield */
        /* hex of first 4-byte of md5_out,
         * 1 more byte to hold the '\0' terminator */
        char md5_hex[8];
        BIN2HEX(md5_out, md5_hex, 0);
        BIN2HEX(md5_out, md5_hex, 1);
        BIN2HEX(md5_out, md5_hex, 2);
        BIN2HEX(md5_out, md5_hex, 3);
        /* since we have discarded the LSBs of every byte of the key,
         * we always yield keys whose bytes all have their LSB equals to 0.
         * So we mask out the LSBs from md5_hex before comparing */
        if (ctx.yield == ((*(uint64_t *) md5_hex) & 0xFEFEFEFEFEFEFEFEull)) {
            atomic_store(&key_found, true);
            printf("[+] FOUND KEY: ");
            fwrite(md5_hex, 1, sizeof(md5_hex), stdout);
            putchar('\n');
            crack_result.plaintext = plaintext;
            crack_result.len = unpadded_length;
            return 0;
        }
        /* otherwise the key is incorrect, continue searching */
    }
    /* either key is not found, or another worker has found the key */
    return 0;
}

void benchmark() {
#define TEST_CT_LENGTH 1024u
    const int end = 1000000;
    atomic_bool found = false;
    key_search_ctx ctx;
    char test_ciphertext[TEST_CT_LENGTH] = {0};
    clock_t t_start, t_end;

    new_key_search_ctx(
            &ctx,
            test_ciphertext,
            TEST_CT_LENGTH,
            0u
    );
    printf("Benchmarking...\n");


    t_start = clock();
    while (yield_possible_key(&ctx, end, &found)) {
    }
    t_end = clock();

    const double key_per_sec =
            1.0 * end / ((double) (t_end - t_start) / CLOCKS_PER_SEC);
    printf(
            "Finish.\n"
            "Speed (single thread): %.3f key/sec\n",
            key_per_sec
    );

    printf("Time to search the whole key space:\n");

    const int threads[] = {1, 2, 4, 8, 16, 32, 0};
    for (int i = 0; threads[i] > 0; ++i) {
        printf("  %3.d thread: %9.3f sec%s\n",
               threads[i], (double) KEYSPACE_SIZE / key_per_sec / threads[i],
               (threads[i] != 1) ? " (estimate)" : "");
    }
}

int main(int argc, char *argv[]) {
    crack_result.plaintext = NULL;

    if (argc == 1) {
        USAGE:
        printf("Usage: %s <fp_file> "
               "[<where_to_save_the_decrypted_file>] "
               "[-j <threads>] "
               "[--benchmark]\n"
               "The decrypted image won't be saved if "
               "save path is not specified.\n"
               "threads: how many workers to run at the same time, "
               "default: 1\n"
               "--benchmark: if set, other parameters will be ignored\n",
               argv[0]);
        return 0;
    }

    /* run benchmark and exit */
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--benchmark")) {
            benchmark();
            return 0;
        }
    }

    const char *plaintext_save_path =
            (argc >= 3 && strcmp(argv[2], "-j") != 0) ? (argv[2]) : NULL;
    const char *ciphertext_file_path = argv[1];

    /* open file */
    FILE *fp;
    if (!(fp = fopen(ciphertext_file_path, "rb"))) {
        perror("fopen");
        return 1;
    }

    /* validate file header */
    char header[8];
    if (fread(header, 1, 8, fp) != 8) {
        fprintf(stderr, "Cannot read first 8 bytes from file.\n");
        return 1;
    }
    if (*(uint64_t *) header != *(uint64_t *) "ENCRYPT:") {
        fprintf(stderr, "Bad file header.\n");
        return 1;
    }

    /* read ciphertext into memory */
    fseek(fp, 0, SEEK_END);
    long file_length = ftell(fp);
    if (file_length <= 8) {
        fprintf(stderr, "Invalid file length (%ld)\n", file_length);
        return 1;
    }

    const unsigned long ciphertext_length = file_length - 8;
    if (ciphertext_length % 8 != 0) {
        fprintf(stderr, "Invalid file length: %ld can not be divided by 8.\n",
                file_length);
        return 1;
    }
    char *ciphertext_buf = malloc(ciphertext_length);
    /* this buffer is for the future decryption usage,
     * storing padded plaintext (pkcs7) */
    char *plaintext = malloc(ciphertext_length);
    if (ciphertext_buf == NULL || plaintext == NULL) {
        perror("malloc");
        return 1;
    }

    fseek(fp, 8, SEEK_SET);
    if (fread(ciphertext_buf, 1, ciphertext_length, fp) != ciphertext_length) {
        fprintf(stderr, "Cannot read the whole file.\n");
        return 1;
    }

    ciphertext = ciphertext_buf;
    ciphertext_len = ciphertext_length;

    int threads = 1;

    /* read thread count from argv */
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-j")) {
            if (i == argc - 1) {
                printf("-j requires an integer parameter.\n");
                goto USAGE;
            }
            errno = 0;
            char *end;
            long val = strtol(argv[i + 1], &end, 10);
            if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
                (errno != 0 && val == 0) ||
                end == argv[i + 1] ||
                val <= 0) {
                printf("Invalid thread count number.\n");
                goto USAGE; /* invalid integer */
            }
            threads = (int) val;
            break;
        }
    }

    /* start searching */
    printf("Searching key (using %d workers)...\n", threads);
    fflush(stdout);

    atomic_store(&key_found, false);

    thrd_t *thread_ids;
    thread_param *thread_params;
    if ((thread_ids = malloc(sizeof(thrd_t) * threads)) == NULL) {
        perror("malloc");
        return 1;
    }
    if ((thread_params = malloc(sizeof(thread_param) * threads)) == NULL) {
        perror("malloc");
        return 1;
    }

    /* assign search ranges to workers */
    uint32_t range_size = KEYSPACE_SIZE / threads;
    for (int i = 0; i < threads; ++i) {
        thread_params[i].a = range_size * i;
        thread_params[i].b = range_size * i + range_size;
        thread_params[i].worker_id = i;
    }
    /* the last search range should warp */
    thread_params[threads - 1].b = KEYSPACE_SIZE;

    /* start workers */
    for (int i = 0; i < threads; ++i) {
        if (thrd_create(
                &thread_ids[i],
                (thrd_start_t) thread_worker,
                &thread_params[i]) != thrd_success) {
            fprintf(stderr, "Cannot start thread %d.\n", i);
            return 1;
        }
    }

    /* wait for all workers to terminate */
    for (int i = 0; i < threads; ++i) {
        int ret;
        thrd_join(thread_ids[i], &ret);
        if (ret) {
            fprintf(stderr, "Worker terminated with error code %d.\n", ret);
        }
    }

    /* save decrypted data */
    if (crack_result.plaintext != NULL && plaintext_save_path) {
        FILE *fout = fopen(plaintext_save_path, "wb");
        if (!fout) {
            perror("Cannot open file for saving");
            return 1;
        }
        fwrite(crack_result.plaintext, 1, crack_result.len, fout);
        fclose(fout);
        printf("Flash photo has been saved in: %s\n",
               plaintext_save_path);
    }

    if (crack_result.plaintext == NULL) {
        printf("[-] KEY WAS NOT FOUND.\n");
    }

    return 0;
}