#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> 

FILE *fopen(const char *path, const char *mode);

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
