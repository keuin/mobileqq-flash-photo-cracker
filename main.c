#include <tomcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

const char *hexchars = "0123456789ABCDEF";

typedef struct s_key_search_ctx {
    /* first 8 bytes of the ciphertext in encrypted QQ flash image */
    uint64_t ciphertext;
    /* if routine `yield_possible_key` returns true,
     * the possible 64-bit DES key will be stored here */
    uint64_t yield;
    /* 4 byte effective key space */
    uint32_t next_possible_key;
    bool finished;
} key_search_ctx;

/* constructor of type `key_search_ctx` */
void new_key_search_ctx(
        key_search_ctx *ctx,
        uint64_t ciphertext,
        uint32_t a
) {
    ctx->finished = false;
    ctx->next_possible_key = a;
    ctx->ciphertext = ciphertext;
}

/* search key in range [a, b), returns false if
 * no result yield from this call and searching is finished */
bool yield_possible_key(key_search_ctx *ctx, uint32_t b) {
    if (ctx->finished) return false;

//    const char[] hexchars = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//                             0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
#define FILL_KEY(buf, key, i) \
        ((buf)[7-(i)] = hexchars[((key) >> (4*(i))) & 0xFu]) \
        // buf: char[8], key: uint64_t, i:uint = 0, 1, 2, ..., 7
    uint32_t k = ctx->next_possible_key;
    uint64_t plaintext;
    char key[8];
    symmetric_key skey;
    do {
        // convert key uint32 to char[]
        FILL_KEY(key, k, 0);
        FILL_KEY(key, k, 1);
        FILL_KEY(key, k, 2);
        FILL_KEY(key, k, 3);
        FILL_KEY(key, k, 4);
        FILL_KEY(key, k, 5);
        FILL_KEY(key, k, 6);
        FILL_KEY(key, k, 7);
        // decrypt file header with this key
        int err;
        if ((err = des_setup((const unsigned char *) key, 8, 0, &skey)) !=
            CRYPT_OK) {
            fprintf(stderr, "Err: setup: %s", error_to_string(err));
            return false;
        }
        if (des_ecb_decrypt(
                (const unsigned char *) &(ctx->ciphertext),
                (unsigned char *) &plaintext,
                (const symmetric_key *) &skey
        ) != CRYPT_OK)
            continue; // failed to decrypt
        // validate first 3 bytes of the cleartext
        if ((plaintext & 0xFFFFFFu) == 0xFFD8FFu) {
            ctx->yield = *(uint64_t *) key;
            // if current `k` goes out of range, finished will be set to true
            ctx->finished = k >= b;
            return true;
        }
    } while ((k = ++ctx->next_possible_key));
    ctx->finished = true;
    return false;
}

/* given buf, returns length of the pad, or -1 if
 * the data is not padded with valid pkcs7 */
int pkcs7_check_pad(const char *buf, size_t n) {
    if (!n) return -1;
    --n;
    unsigned char pad = buf[n--];
    if (!pad) return -1;
    if (n < pad) return -1; // buf is shorter than a valid pad
    for (int i = pad; i > 1; --i) {
        if (buf[n--] != pad) return -1;
    }
    return pad;
}

int main(int argc, char *argv[]) {
//    uint64_t ciphertext = 8022485120222247589;
//    unsigned char plaintext[8];
//    const char *key = "A0979B6D";
//    symmetric_key skey;
    FILE *fp;

    if (argc != 2 && argc != 3) {
        printf("Usage: %s <fp_file> [<where_to_save_the_decrypted_file>]\n"
               "The decrypted image won't be saved if "
               "save path is not specified.\n",
               argv[0]);
        return 0;
    }

    const char *plaintext_save_path = (argc == 3) ? (argv[2]) : NULL;
    const char *ciphertext_file_path = argv[1];

    // open file
    if (!(fp = fopen(ciphertext_file_path, "rb"))) {
        perror("fopen");
        return 1;
    }

    // test file header
    char header[8];
    if (fread(header, 1, 8, fp) != 8) {
        fprintf(stderr, "Cannot read first 8 bytes from file.\n");
        return 1;
    }
    if (*(uint64_t *) header != *(uint64_t *) "ENCRYPT:") {
        fprintf(stderr, "Bad file header.\n");
        return 1;
    }

    // read ciphertext into memory
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
    char *ciphertext = malloc(ciphertext_length);
    /* this buffer is for the future decryption usage,
     * storing padded plaintext (pkcs7) */
    char *plaintext = malloc(ciphertext_length);
    if (ciphertext == NULL || plaintext == NULL) {
        perror("malloc");
        return 1;
    }

    fseek(fp, 8, SEEK_SET);
    if (fread(ciphertext, 1, ciphertext_length, fp) != ciphertext_length) {
        fprintf(stderr, "Cannot read the whole file.\n");
        return 1;
    }

    /* start searching */
    printf("Searching key...\n");
    fflush(stdout);

    key_search_ctx ctx;
    new_key_search_ctx(&ctx, *(uint64_t *) ciphertext);
    /* FOR DEBUGGING ONLY */
//    assert(*(uint64_t *) ciphertext == 8022485120222247589ull);
//    ctx.next_possible_key = 0xA0979B6Du;
    while (yield_possible_key(&ctx)) {
        /* found a possible correct key */
        /* validate it by calculating md5 hashsum of the plaintext */
        printf("Possible key: %zu\n", ctx.yield);
        fflush(stdout);

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
            fprintf(stderr, "Invalid pad.\n");
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
        char md5_hex[8 + 1];
        snprintf(md5_hex, 8 + 1, "%02X%02X%02X%02X",
                 md5_out[0] & 0xFFu, md5_out[1] & 0xFFu,
                 md5_out[2] & 0xFFu, md5_out[3] & 0xFFu);
        if (!memcmp(md5_hex, (const char *) (&ctx.yield), 8)) {
            printf("[+] FOUND KEY: %zu\n", ctx.yield);

            if (plaintext_save_path) {
                FILE *fout = fopen(plaintext_save_path, "wb");
                if (!fout) {
                    perror("Cannot fopen for saving");
                    return 1;
                }
                fwrite(plaintext, 1, unpadded_length, fout);
                fclose(fout);
                printf("Flash photo has been saved in: %s\n",
                       plaintext_save_path);
            }

            return 0;
        }
        /* otherwise the key is incorrect, continue searching */
    }

    return 0;
}