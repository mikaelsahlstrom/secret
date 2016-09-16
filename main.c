#include <stdio.h>
#include <string.h>
#include <sodium.h>

#define SUCCESS 0
#define ERROR 1

#define NONCE_LEN crypto_box_SEEDBYTES
#define KEY_LEN crypto_box_SEEDBYTES

static void print_help_text(void)
{
    printf("Arguments: \n-h\tThis help text.\n-s\tCreate salt.\n"
           "-o PATH\tOpen secret box.\n-c PATH\tCreate secret box.\n");
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
        else if (strncmp(argv[1], "-s", 2) == 0)
        {
            // Create nonce.
            uint8_t nonce[NONCE_LEN];
            randombytes_buf(nonce, NONCE_LEN);
            if (r == SUCCESS)
            {
                uint32_t i;
                for (i = 0; i < NONCE_LEN; i += 1)
                {
                    printf("%02x", nonce[i]);
                }
                printf("\n");
            }
        }
        else if ((strncmp(argv[1], "-o", 2) == 0) && (argc == 3))
        {
            // Open secret box.
            uint8_t *box = NULL;
            uint32_t box_size = 0;
            uint8_t *password = NULL;
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
                // Read nonce.
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
            }

            if (r == SUCCESS)
            {
                // Read password.
                if (getline(&password, &password_length, stdin) == -1)
                {
                    r = ERROR;
                }
                else
                {
                    // password_length now includes the \n.
                    password_length -= 1;
                }
            }

            if (r == SUCCESS)
            {
                // Derive key.
                if (crypto_pwhash(key, KEY_LEN,
                                  password, password_length,
                                  nonce,
                                  crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                  crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                  crypto_pwhash_ALG_DEFAULT) != 0)
                {
                    r = ERROR;
                }
            }

            if (r == SUCCESS)
            {
                // Decrypt box.
                uint8_t decrypted_box[box_size + 1] = {0};
                uint32_t decrypted_box_size = 0;
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
            }

            if (r == SUCCESS)
            {
                printf("%s\n", decrypted_box);
            }

            sodium_memzero(key, KEY_LEN);
            free(box);
        }
        else if (strncmp(argv[2], "-c", 2) == 0)
        {
            // Create secret box
            
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
