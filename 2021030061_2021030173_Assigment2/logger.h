#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>

/* Function declarations */
FILE* call_original_fopen(const char *path, const char *mode);
int determine_access_type(const char *path, const char *mode, int *action_denied);
void format_datetime(char *date, char *timestamp);
void get_md5_hash(FILE *file, unsigned char *fingerprint);
void log_access(int uid, const char *filename, char *date, char *timestamp, int access_type, int action_denied, unsigned char *fingerprint);
void log_file_access(int uid, const char *path, const char *date1, const char *timestamp, int access_type, int action_denied, unsigned char *fingerprint);
FILE *fopen(const char *path, const char *mode);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);