#include "logger.h"

FILE *fopen(const char *path, const char *mode) {
    int log = strcmp(path, "file_logging.log"); // if 0, open log file
    int action_denied = 0;
    int access_type = determine_access_type(path, mode, &action_denied);

    FILE *original_fopen_ret = (action_denied == 0)
        ? call_original_fopen(path, mode)
        : call_original_fopen(path, "r");

    if (log != 0) {
        int uid = getuid();
        char *filename = realpath(path, NULL);

        char date[15];
        char timestamp[9];
        format_datetime(date, timestamp);

        unsigned char fingerprint[EVP_MAX_MD_SIZE] = {0};  // Changed to EVP_MAX_MD_SIZE to handle MD5 digest
        if (original_fopen_ret != NULL) {
            get_md5_hash(original_fopen_ret, fingerprint);
        }

        log_access(uid, filename, date, timestamp, access_type, action_denied, fingerprint);
        free(filename);
    }
    return original_fopen_ret;
}

/* Calls the original fopen using dlsym */
FILE* call_original_fopen(const char *path, const char *mode) {
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    return original_fopen(path, mode);
}

/* Determines the access type based on file existence and permissions */
int determine_access_type(const char *path, const char *mode, int *action_denied) {
    int access_type = -1;
    if (access(path, F_OK) != -1) { // File exists
        if (mode[0] == 'r') {
            access_type = 1;
            *action_denied = (access(path, R_OK) == -1);
        } else if (mode[0] == 'w' || mode[0] == 'a') {
            access_type = 2;
            *action_denied = (access(path, W_OK) == -1);
        }
    } else if (mode[0] == 'w' || mode[0] == 'a') { // File doesn't exist
        access_type = 0;
        *action_denied = 0;
    }
    return access_type;
}

/* Formats the current date and time */
void format_datetime(char *date, char *timestamp) {
    time_t times;
    time(&times);
    struct tm *time_info = localtime(&times);
    strftime(date, 15, "%a %b %d %Y", time_info);
    strftime(timestamp, 9, "%H:%M:%S", time_info);
}

/* Gets the MD5 hash of the file contents */
void get_md5_hash(FILE *file, unsigned char *fingerprint) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5(); // Specify MD5 as the hash algorithm

    if (mdctx == NULL) {
        perror("Failed to create MD5 context");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // Initialize the digest context for MD5

    char buffer[4096];
    size_t bytesRead;
    fseek(file, 0, SEEK_SET); // Reset the file pointer to the beginning

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead); // Update the hash with the buffer data
    }

    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, fingerprint, &md_len); // Finalize the digest

    EVP_MD_CTX_free(mdctx); // Clean up the MD context
}

/* Logs the access details to "file_logging.log" */
void log_access(int uid, const char *filename, char *date, char *timestamp, int access_type, int action_denied, unsigned char *fingerprint) {
    FILE *log_file = call_original_fopen("file_logging.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%d %s %s %s %d %d ", uid, filename, date, timestamp, access_type, action_denied);
        for (unsigned int i = 0; i < EVP_MD_size(EVP_md5()); i++) { // Use EVP_MD_size for MD5 size
            fprintf(log_file, "%02x", fingerprint[i]);
        }
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

    // Call the original fwrite function
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");

    // Get user ID
    int uid = getuid();
    int access_type = 2; // access type values [0-2]
    int action_denied = 1; // is action denied values [0-1]

    // Get the file descriptor
    int fileDescriptor = fileno(stream);
    char path[4096];
    char procPath[4096];

    snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fileDescriptor);
    ssize_t pathSize = readlink(procPath, path, sizeof(path));
    if (pathSize != -1) {
        // Check write permissions
        if (access(path, W_OK) != -1) {
            access_type = 2; // Write access granted
            action_denied = 0;
        } else {
            access_type = 2; // Write access denied
            action_denied = 1;
        }

        char date1[15];   // Buffer to hold the formatted date
        char timestamp[9]; // Buffer to hold the formatted timestamp
        format_datetime(date1, timestamp); // Get current time

        unsigned char fingerprint[EVP_MAX_MD_SIZE]; // Buffer to hold the MD5 hash
        if (action_denied == 0) {
            original_fwrite_ret = original_fwrite(ptr, size, nmemb, stream); // Write data
            get_md5_hash(stream, fingerprint); // Compute the MD5 hash of the file content
        } else {
            // If action is denied, just return 0 in this case.
            original_fwrite_ret = 0; 
        }

        // Log the file access details
        log_file_access(uid, path, date1, timestamp, access_type, action_denied, fingerprint);
    }

    return original_fwrite_ret; // Return the original fwrite result
}

/* Logs the file access details */
void log_file_access(int uid, const char *path, const char *date1, const char *timestamp, int access_type, int action_denied, unsigned char *fingerprint) {
    FILE *log_file = call_original_fopen("file_logging.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%d %s %s %s %d %d ", uid, path, date1, timestamp, access_type, action_denied);
        for (unsigned int i = 0; i < EVP_MD_size(EVP_md5()); i++) { // Use EVP_MD_size for MD5 size
            fprintf(log_file, "%02x", fingerprint[i]);
        }
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}


