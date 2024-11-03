#include "logger.h"

FILE *
fopen(const char *path, const char *mode) 
{   
    int log = strcmp(path, "file_logging.log"); //if 0 open log file
    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char*, const char*); //function pointer to original fopen

    /* call the original fopen function */
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    int uid = getuid(); /* user id (positive integer) */
    int access_type; /* access type values [0-2] */
    int action_denied=0; /* is action denied values [0-1] */
    static int counter=0;

    /* determine access type */
    // First checking if file exists
    if (euidaccess(path, F_OK)!=-1) { 
        if (mode[0]=='r') {
            if (euidaccess(path, R_OK)!=-1) {
                // Open file with access
                access_type = 1;
                action_denied = 0;
            } else {
                // Open file with no access
                access_type = 1;
                action_denied = 1;
            }
        }
        if (mode[0]=='w' || mode[0]=='a') {
            if (euidaccess(path, W_OK)!=-1) {
                // Write file with access
                access_type = 2;
                action_denied = 0;
            } else {
                // Write file with no access
                access_type = 2;
                action_denied = 1;
            } 
        }
    } else {
        // If file doesn't exist and we want to write in it  
        if (mode[0]=='w' || mode[0]=='a') {
            action_denied = 0;
            access_type = 0; // File created
        }
    }

    if (action_denied==0) {
        original_fopen_ret = (*original_fopen)(path, mode);
    } else {
        original_fopen_ret = (*original_fopen)(path, "r");
    }
  
    char *filename = realpath(path, NULL); /* filename (string) */
    if(log != 0) {
        time_t times; /* file access time */
        time(&times);
        struct tm *time_info;
        time_info = localtime(&times);
        
        // Get the formatted date and time string
        char* date_time_str = asctime(time_info);
        char timestamp[8+1];  // '\0'
        strncpy(timestamp, date_time_str + 11, 8);
        timestamp[8] = '\0';
            
        char date2[4+1];
        char date1[11+1 + sizeof(date2)];
        strncpy(date1, date_time_str, 10);
        date1[10] = ' ';
        date1[11] = '\0';
        strncpy(date2, date_time_str + 20, 4);
        date2[4] = '\0';
        strcat(date1, date2);

        // Getting the hash value of content from file using EVP
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char fingerprint[EVP_MAX_MD_SIZE];
        unsigned int fingerprint_len;

        md = EVP_md5(); // Select MD5
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);

        char buffer[4096];
        size_t bytesRead;

        if (original_fopen_ret != NULL) {
            fseek(original_fopen_ret, 0, SEEK_SET);
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), original_fopen_ret)) > 0) {
                EVP_DigestUpdate(mdctx, buffer, bytesRead);
            }
            
            EVP_DigestFinal_ex(mdctx, fingerprint, &fingerprint_len);
            EVP_MD_CTX_free(mdctx);
        }
        
        FILE *logg = (*original_fopen)("file_logging.log", "a");
        fprintf(logg, "%d %s %s %s %d %d ", uid, filename, date1, timestamp, access_type, action_denied);
        if (original_fopen_ret != NULL) {
            for (unsigned int i = 0; i < fingerprint_len; i++) {
                fprintf(logg, "%02x", fingerprint[i]);
            }      
        }
        fprintf(logg, "\n");
        fclose(logg);
    }
    return original_fopen_ret;  
}

size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

    /* call the original fwrite function */
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    
    // Get user ID
    int uid = getuid();
    int access_type = 2; /* access type values [0-2] */
    int action_denied = 1; /* is action denied values [0-1] */

    // Get the file descriptor
    int fileDescriptor = fileno(stream);

    // Get the file path using the file descriptor
    char path[4096];
    char procPath[4096];
    snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fileDescriptor);
    ssize_t pathSize = readlink(procPath, path, sizeof(path));
    if (pathSize != -1) {
        if (euidaccess(path, W_OK)!=-1) {
            // Write file with access
            access_type = 2;
            action_denied = 0;
        } else {
            // Write file with no access
            access_type = 2;
            action_denied = 1;
        } 

        FILE * logg = fopen("file_logging.log", "a");

        time_t times; /* file access time */
        time(&times);
        struct tm *time_info;
        time_info = localtime(&times);
        
        // Get the formatted date and time string
        char* date_time_str = asctime(time_info);
        char timestamp[8+1];  // '\0'
        strncpy(timestamp, date_time_str + 11, 8);
        timestamp[8] = '\0';
            
        char date2[4+1];
        char date1[11+1 + sizeof(date2)];
        strncpy(date1, date_time_str, 10);
        date1[10] = ' ';
        date1[11] = '\0';
        strncpy(date2, date_time_str + 20, 4);
        date2[4] = '\0';
        strcat(date1, date2);

        // Getting the hash value of content from file using EVP
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char fingerprint[EVP_MAX_MD_SIZE];
        unsigned int fingerprint_len;

        md = EVP_md5(); // Select MD5
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);

        if (action_denied==0) original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream); // Works for w and w+
        fseek(stream, 0, SEEK_SET);

        char buffer[4096];
        size_t bytesRead;
        while ((bytesRead = fread(buffer, 1, sizeof(buffer), stream)) > 0) {
            EVP_DigestUpdate(mdctx, buffer, bytesRead);
        }
        EVP_DigestFinal_ex(mdctx, fingerprint, &fingerprint_len);
        EVP_MD_CTX_free(mdctx);

        fprintf(logg, "%d %s %s %s %d %d ", uid, path, date1, timestamp, access_type, action_denied);
        for (unsigned int i = 0; i < fingerprint_len; ++i) {
            fprintf(logg, "%02x", fingerprint[i]);
        }

        fprintf(logg, "\n");
        fclose(logg);
    }

    return original_fwrite_ret; // Return the original fwrite result
}
