#include "/usr/local/include/sodium.h"
#include <stdio.h>
#include <string.h>

#define MESSAGE (const unsigned char *)"test"
#define MESSAGE_LEN 4
#define ADDITIONAL_DATA (const unsigned char *)"padding"
#define ADDITIONAL_DATA_LEN 7

void usage() { printf("crypt [encrypt | decrypt] <key>\n"); }

void write_file_to_binary(const char *filename, char *content) {
  FILE *f;
  if ((f = fopen(filename, "wb")) == NULL) {
    printf("Error opening file: %s", filename);
  }

  fwrite(&content, sizeof(content), 1, f);
}

char *read_file(char *buffer, char *filename, long *length) {
  // read file
  buffer = 0;
  FILE *f = fopen(filename, "rb");

  if (f) {
    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    fseek(f, 0, SEEK_SET);
    buffer = malloc(*length);
    if (buffer) {
      fread(buffer, 1, *length, f);
    }
    fclose(f);
    return buffer;
  } else {
    return 0;
  }
}

int main(int argc, char *argv[]) {

  if (argc < 3) {
    usage();
    return 1;
  }

  if (sodium_init() < 0) {
    printf("Error: can't initialize libsodium\n");
  }

  // char *key = argv[2];
  long length = 0;
  char *buffer = 0;
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  // key is not auto-generated
  unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

  if (strcmp(argv[1], "encrypt") == 0) {
    printf("encrypting input file...\n");

    // read file
    buffer = 0;
    FILE *f = fopen("passwd.txt", "rb");

    if (f) {
      fseek(f, 0, SEEK_END);
      length = ftell(f);
      fseek(f, 0, SEEK_SET);
      buffer = malloc(length);
      if (buffer) {
        fread(buffer, 1, length, f);
      }
      fclose(f);
    } else {
      return 0;
    }
    printf("buffer:\n%s", buffer);

    unsigned char
        ciphertext[length + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ciphertext_len;

    // write out nonce
    FILE *n;
    if ((n = fopen("nonce", "wb")) == NULL) {
      printf("Error opening file: nonce");
    }

    fwrite(&nonce, sizeof(nonce), 1, f);
    fclose(n);

    // key is no longer generated
    crypto_aead_xchacha20poly1305_ietf_keygen((unsigned char *)key);
    randombytes_buf(nonce, sizeof nonce);
    printf("nonce generated\n");

    // encrypt
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, &ciphertext_len, (const unsigned char *)buffer, length,
        ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, NULL, nonce,
        (unsigned char *)key);

    printf("encrypted: %s\n", ciphertext);
    
    // write encrypted contents to file
    FILE *e;
    if ((e = fopen("passwd", "wb")) == NULL) {
      printf("Error opening file: encrypted");
    }

    fwrite(&ciphertext, sizeof(ciphertext), 1, f);
    fclose(e);
    printf("encrypted contents successfully\n");
    return 0;
  } else if (strcmp(argv[1], "decrypt") == 0) {
    printf("decrypting file contents\n");
    buffer = 0;
    length = 0;

    // read nonce
    strcpy((char *)nonce, read_file((char *)nonce, "nonce", &length));
    printf("nonce read successfully. Reading encrypted contents...\n");

    buffer = read_file(buffer, "passwd", &length);
    printf("encrypted contents read successfully\n");
    unsigned char decrypted[length];
    unsigned long long decrypted_len;
    printf("decrypting contents...\n");
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            decrypted, &decrypted_len, NULL, (unsigned char *)buffer, length,
            ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce,
            (unsigned char *)key) != 0) {
      printf("File contents:\n%s", decrypted);
      printf("contents decrypted successfully\n");
    }
  } else {
    usage();
    return 1;
  }

  // end execution normally
  return 0;
}
