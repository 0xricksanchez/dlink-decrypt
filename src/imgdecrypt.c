#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

RSA *grsa_struct;
static unsigned char iv[] = {0x98, 0xC9, 0xD8, 0xF0, 0x13, 0x3D, 0x06, 0x95,
                             0xE2, 0xA7, 0x09, 0xC8, 0xB6, 0x96, 0x82, 0xD4};
static unsigned char aes_in[] = {0xC8, 0xD3, 0x2F, 0x40, 0x9C, 0xAC,
                                 0xB3, 0x47, 0xC8, 0xD2, 0x6F, 0xDC,
                                 0xB9, 0x09, 0x0B, 0x3C};
static unsigned char aes_key[] = {0x35, 0x87, 0x90, 0x03, 0x45, 0x19,
                                  0xF8, 0xC8, 0x23, 0x5D, 0xB6, 0x49,
                                  0x28, 0x39, 0xA7, 0x3F};
unsigned char out[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
const static char *null = "0";

int check_cert(char *pem, void *n) {
  RSA *lrsa_struct[2];
  OPENSSL_add_all_algorithms_noconf();
  FILE *pem_fd = fopen(pem, "r");
  if (pem_fd != NULL) {
    lrsa_struct[0] = RSA_new();
    if (PEM_read_RSAPublicKey(pem_fd, lrsa_struct, NULL, n) == NULL) {
      RSA_free(lrsa_struct[0]);
      puts("Read RSA private key failed, maybe the password is incorrect.");
    } else {
      grsa_struct = lrsa_struct[0];
    }
    fclose(pem_fd);
  }
  if (grsa_struct == NULL) {
    return -1;
  } else {
    return 0;
  }
}

int aes_cbc_encrypt(unsigned char *in, unsigned int length,
                    unsigned char *user_key, unsigned char *ivec,
                    unsigned char *out) {
  AES_KEY dec_key;
  unsigned char iv[16];
  memcpy(iv, ivec, 16);

  AES_set_decrypt_key(user_key, 0x80, &dec_key);
  AES_cbc_encrypt(in, out, (unsigned int)length, &dec_key, iv, AES_DECRYPT);
  return 0;
}

int call_aes_cbc_encrypt(unsigned char *key) {
  aes_cbc_encrypt(aes_in, 0x10, aes_key, iv, key);
  return 0;
}

int check_magic(void *mapped_mem) {
  return (unsigned int)(memcmp(mapped_mem, "SHRS", 4) == 0);
}

int calc_sha512_digest(void *mapped_mem, u_int32_t len, unsigned char *buf) {
  SHA512_CTX sctx;
  SHA512_Init(&sctx);
  SHA512_Update(&sctx, mapped_mem, len);
  SHA512_Final(buf, &sctx);
  return 0;
}

int calc_sha512_digest_key(void *mapped_mem, u_int32_t len, void *key,
                           unsigned char *buf) {
  SHA512_CTX sctx;
  SHA512_Init(&sctx);
  SHA512_Update(&sctx, mapped_mem, len);
  SHA512_Update(&sctx, key, 0x10);
  SHA512_Final(buf, &sctx);
  return 0;
}

int check_sha512_digest(const unsigned char *m, unsigned int m_length,
                        unsigned char *sigbuf, unsigned int siglen) {
  return RSA_verify((int)0x2a2, m, m_length, sigbuf, siglen, grsa_struct);
}

int actual_decryption(char *sourceFile, char *tmpDecPath, unsigned char *key) {
  int ret_val = -1;
  size_t st_blocks = -1;
  struct stat stat_struct;
  int _fd;
  int fd = -1;
  void *ROM = (void *)0x0;
  unsigned char *RWMEM = (unsigned char *)0x0;
  off_t seek_off;
  unsigned char hash_md_buf[68] = {0};
  unsigned int mcb;
  uint32_t datalen_1;
  uint32_t datalen_2;

  memset(&hash_md_buf, 0, 0x40);
  memset(&stat_struct, 0, 0x90);
  _fd = stat(sourceFile, &stat_struct);
  if (_fd == 0) {
    fd = open(sourceFile, O_RDONLY);
    st_blocks = stat_struct.st_size;
    if (((-1 < fd) &&
         (ROM = mmap(NULL, st_blocks, PROT_READ, MAP_SHARED, fd, 0),
          ROM != 0)) &&
        (_fd = open(tmpDecPath, O_RDWR | O_NOCTTY | O_CREAT, S_IRUSR | S_IWUSR),
         -1 < _fd)) {
      seek_off = lseek(_fd, st_blocks - 1, 0);
      if (seek_off == st_blocks - 1) {
        write(_fd, null, 1);
        close(_fd);
        _fd = open(tmpDecPath, O_RDWR | O_NOCTTY, S_IRUSR | S_IWUSR);
        RWMEM =
            mmap(NULL, st_blocks, PROT_READ | PROT_WRITE, MAP_SHARED, _fd, 0);
        if (RWMEM != 0) {
          mcb = check_magic(ROM);
          if (mcb == 0) {
            puts("No image matic found\r");
          } else {
            datalen_1 = htonl(*(uint32_t *)(ROM + 8));
            datalen_2 = htonl(*(uint32_t *)(ROM + 4));
            calc_sha512_digest((ROM + 0x6dc), datalen_1, hash_md_buf);
            _fd = memcmp(hash_md_buf, (ROM + 0x9c), 0x40);
            if (_fd == 0) {
              aes_cbc_encrypt((ROM + 0x6dc), datalen_1, key,
                              (unsigned char *)(ROM + 0xc), RWMEM);
              calc_sha512_digest(RWMEM, datalen_2, hash_md_buf);
              _fd = memcmp(hash_md_buf, (ROM + 0x5c), 0x40);
              if (_fd == 0) {
                calc_sha512_digest_key(RWMEM, datalen_2, (void *)key,
                                       hash_md_buf);
                _fd = memcmp(hash_md_buf, (ROM + 0x1c), 0x40);
                if (_fd == 0) {
                  _fd = check_sha512_digest((ROM + 0x5c), 0x40, (ROM + 0x2dc),
                                            0x200);
                  if (_fd == 1) {
                    _fd = check_sha512_digest((ROM + 0x9c), 0x40, (ROM + 0x4dc),
                                              0x200);
                    if (_fd == 1) {
                      ret_val = 0;
                      puts("We in!");
                    } else {
                      ret_val = -1;
                    }
                  } else {
                    ret_val = -1;
                  }
                } else {
                  puts("check sha512 vendor failed\r");
                }
              } else {
                printf("check sha512 before failed %d %d\r\n", datalen_2,
                       datalen_1);
                int ctr = 0;
                while (ctr < 0x40) {
                  printf("%02X", *(hash_md_buf + ctr));
                  ctr += 1;
                }
                puts("\r");
                ctr = 0;
                while (ctr < 0x40) {
                  printf("%02X",
                         *(unsigned int *)(unsigned char *)(ROM + ctr + 0x5c));
                  ctr += 1;
                }
                puts("\r");
              }
            } else {
              puts("check sha512 post failed\r");
            }
          }
        }
      }
    }
  }
  if (ROM != (void *)0x0) {
    munmap(ROM, stat_struct.st_blocks);
  }
  if (RWMEM != (unsigned char *)0x0) {
    munmap(RWMEM, st_blocks);
  }
  if (-1 < (int)fd) {
    close(fd);
  }
  return ret_val;
}

int decrypt_firmware(int argc, char **argv) {
  int ret;
  unsigned char key[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
  char *ppem = "/tmp/public.pem";
  int loopCtr = 0;
  if (argc < 2) {
    printf("%s <sourceFile>\r\n", argv[0]);
    ret = -1;
  } else {
    if (2 < argc) {
      ppem = (char *)argv[2];
    }
    int cc = check_cert(ppem, (void *)0);
    if (cc == 0) {
      call_aes_cbc_encrypt((unsigned char *)&key);
      printf("key: ");
      while (loopCtr < 0x10) {
        printf("%02X", *(key + loopCtr) & 0xff);
        loopCtr += 1;
      }
      puts("\r");
      ret = actual_decryption((char *)argv[1], "/tmp/.firmware.orig",
                              (unsigned char *)&key);
      if (ret == 0) {
        unlink(argv[1]);
        rename("/tmp/.firmware.orig", argv[1]);
      }
      RSA_free(grsa_struct);
    } else {
      ret = -1;
    }
  }
  return ret;
}

int encrypt_firmware(int argc, char **argv) {
  puts("TODO\n");
  return -1;
}

int main(int argc, char **argv) {
  int ret;
  char *str_f = strstr(*argv, "decrypt");
  if (str_f != NULL) {
    ret = decrypt_firmware(argc, argv);
  } else {
    ret = encrypt_firmware(argc, argv);
  }
  return ret;
}
