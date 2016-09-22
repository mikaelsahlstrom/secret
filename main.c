#include <stdio.h>
#include <string.h>
#include <sodium.h>

#define SUCCESS 0
#define ERROR 1

#define NONCE_LEN crypto_box_SEEDBYTES
#define KEY_LEN crypto_box_SEEDBYTES
#define BUFF_INCR 1024

static void print_help_text(void)
{
    printf("Arguments: \n-h\t\tThis help text.\n-o PATH\t\tOpen secret box.\n"
           "-c PATH\t\tCreate secret box and print nonce to stdout.\n");
}

static uint32_t read_nonce(uint8_t nonce[NONCE_LEN])
{
    uint32_t r = SUCCESS;

    uint32_t i;
    for (i = 0; i < NONCE_LEN; i += 1)
    {
        nonce[i] = getchar();
        if (nonce[i] == EOF)
        {
            r = ERROR;
            break;
        }
    }

    return r;
}

static uint32_t read_password(char **password, size_t *password_length)
{
    uint32_t r;

    if (getline(password, password_length, stdin) == -1)
    {
        r = ERROR;
    }
    else
    {
        // password_length now includes the \n.
        *password_length -= 1;
        r = SUCCESS;
    }

    return r;
}

static uint32_t derive_key(uint8_t key[KEY_LEN],
                           char *password,
                           size_t password_length,
                           uint8_t nonce[NONCE_LEN])
{
    uint32_t r;

    if (crypto_pwhash(key, KEY_LEN,
                      password, password_length,
                      nonce,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) == 0)
    {
        r = SUCCESS;
    }
    else
    {
        r = ERROR;
    }

    return r;
}

int main(int argc, char **argv)
{
    uint32_t r = SUCCESS;

    if (sodium_init() != -1)
    {
        if (argc <= 1)
        {
            print_help_text();
        }
        else if (strncmp(argv[1], "-h", 2) == 0)
        {
            // Help
            print_help_text();
        }
        else if ((strncmp(argv[1], "-o", 2) == 0) && (argc == 3))
        {
            // Open secret box.
            uint8_t *box = NULL;
            uint32_t box_size = 0;
            char *password = NULL;
            size_t password_length = 0;
            uint8_t nonce[NONCE_LEN] = {0};
            uint8_t key[KEY_LEN] = {0};

            FILE *box_file = fopen(argv[2], "r");
            if (box_file != NULL)
            {
                if (fseek(box_file, 0L, SEEK_END) == 0)
                {
                    long box_file_size = ftell(box_file);
                    if (box_file_size != -1)
                    {
                        if (fseek(box_file, 0L, SEEK_SET) == 0)
                        {
                            box = malloc(box_file_size + 1);
                            if (box != NULL)
                            {
                                size_t read_bytes = fread(box,
                                                          1,
                                                          box_file_size,
                                                          box_file);
                                if (ferror(box_file) == 0)
                                {
                                    box[read_bytes] = '\0';
                                    box_size = read_bytes + 1;
                                }
                                else
                                {
                                    // Read bytes failed.
                                    r = ERROR;
                                }
                            }
                            else
                            {
                                // Malloc of box content failed.
                                r = ERROR;
                            }
                        }
                        else
                        {
                            // Fseek to start of box content failed.
                            r = ERROR;
                        }
                    }
                    else
                    {
                        // Ftell of box content size failed.
                        r  = ERROR;
                    }
                }
                else
                {
                    // Fseek to box content end failed.
                    r = ERROR;
                }

                fclose(box_file);
            }
            else
            {
                // Fopen of box file failed.
                r = ERROR;
            }

            if (r == SUCCESS)
            {
                // Is box size sensible?
                if (box_size < crypto_aead_aes256gcm_ABYTES)
                {
                    r = ERROR;
                }
            }

            if (r == SUCCESS)
            {
                // Create nonce.
                randombytes_buf(nonce, NONCE_LEN);
                uint32_t i;
                for (i = 0; i < NONCE_LEN; i += 1)
                {
                    printf("%02x", nonce[i]);
                }
                printf("\n");
            }

            if (r == SUCCESS)
            {
                r = read_password(&password, &password_length);
            }

            if (r == SUCCESS)
            {
                r = derive_key(key, password, password_length, nonce);
            }

            if (r == SUCCESS)
            {
                // Decrypt box.
                uint8_t decrypted_box[box_size + 1];
                unsigned long long int decrypted_box_size = 0;
                uint8_t real_size[sizeof(uint32_t)] = {0};

                if (crypto_aead_aes256gcm_decrypt(decrypted_box,
                                                  &decrypted_box_size,
                                                  NULL,
                                                  box,
                                                  box_size,
                                                  real_size,
                                                  sizeof(uint32_t),
                                                  nonce,
                                                  key) != 0)
                {
                    // Message forged or in some way not ok at all.
                    r = ERROR;
                }
                else
                {
                    printf("%s\n", decrypted_box);
                    sodium_memzero(decrypted_box, decrypted_box_size);
                }
            }

            sodium_memzero(key, KEY_LEN);
            sodium_memzero(password, password_length);

            free(password);
            free(box);
        }
        else if ((strncmp(argv[1], "-c", 2) == 0) && (argc == 3))
        {
            // Create secret box
            char *password = NULL;
            size_t password_length = 0;
            uint8_t nonce[NONCE_LEN] = {0};
            uint8_t key[KEY_LEN] = {0};
            uint8_t *data = NULL;
            size_t data_size = 0;
            size_t buff_size = BUFF_INCR;
            uint8_t *box = NULL;
            unsigned long long int box_size = 0;

            r = read_nonce(nonce);

            if (r == SUCCESS)
            {
                r = read_password(&password, &password_length);
            }

            if (r == SUCCESS)
            {
                r = derive_key(key, password, password_length, nonce);
            }

            if (r == SUCCESS)
            {
                // Read data.
                data = malloc(buff_size);
                if (data != NULL)
                {
                    data[data_size++] = getchar();
                    while ((r == SUCCESS) && (data[data_size - 1] != EOF))
                    {
                        if (data_size >= 2)
                        {
                            if ((data[data_size - 1] == '\n') &&
                                (data[data_size - 2] == '\n'))
                            {
                                break;
                            }

                            if (data_size == buff_size)
                            {
                                buff_size += BUFF_INCR;
                                uint8_t *tmp_data = realloc(data, buff_size);
                                if (tmp_data != NULL)
                                {
                                    data = tmp_data;
                                }
                                else
                                {
                                    r = ERROR;
                                }
                            }
                        }

                        if (r == SUCCESS)
                        {
                            data[data_size++] = getchar();
                        }
                    }
                }
                else
                {
                    // Malloc of data failed.
                    r = ERROR;
                }
            }

            if (r == SUCCESS)
            {
                // Create box.
                if (crypto_aead_aes256gcm_encrypt(box,
                                                  &box_size,
                                                  data,
                                                  data_size,
                                                  (uint8_t*) &data_size,
                                                  sizeof(size_t),
                                                  NULL,
                                                  nonce,
                                                  key) != 0)
                {
                    r = ERROR;
                }
            }

            if (r == SUCCESS)
            {
                // Write box to file.
                FILE *box_file = fopen(argv[2], "r");
                if (box_file != NULL)
                {
                    if (fwrite(box, sizeof(uint8_t),
                               box_size, box_file) != box_size)
                    {
                        r = ERROR;
                    }

                    fclose(box_file);
                }
                else
                {
                    // Open box_file failed.
                    r = ERROR;
                }
            }

            sodium_memzero(key, KEY_LEN);
            sodium_memzero(password, password_length);
            sodium_memzero(data, buff_size);

            free(password);
            free(data);
        }
        else
        {
            print_help_text();
        }
    }
    else
    {
        r = ERROR;
    }

    if (r == ERROR)
    {
        printf("Error...\n");
    }

    return r;
}
