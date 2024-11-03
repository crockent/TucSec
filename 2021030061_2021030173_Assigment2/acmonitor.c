#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define MAX_USERS 1000
#define MAX_FILES 100
#define MAX_FILENAME_LENGTH 256

struct log_entry {
    int uid;
    int access_type;
    int action_denied;
    char date[15];
    char timestamp[9];
    char file[MAX_FILENAME_LENGTH];
    char fingerprint[65];
};

// Prints usage information
void usage(void) {
    printf(
        "\n"
        "usage:\n"
        "\t./acmonitor\n"
        "Options:\n"
        "-m, Prints malicious users\n"
        "-i <filename>, Prints table of users that modified "
        "the file <filename> and the number of modifications\n"
        "-h, Help message\n\n"
    );
    exit(1);
}

// List unauthorized accesses for users accessing more than 5 unique files
void list_unauthorized_accesses(FILE *log) {
    struct log_entry entry;
    int unauthorized_access_counts[MAX_USERS] = {0}; 
    char accessed_files[MAX_USERS][MAX_FILES][MAX_FILENAME_LENGTH] = {{{0}}};
    int unique_file_count[MAX_USERS] = {0};

    while (fscanf(log, "%d %s %s %s %d %d %s", 
                  &entry.uid, entry.file, entry.date, entry.timestamp, 
                  &entry.access_type, &entry.action_denied, entry.fingerprint) == 7) {
        
        if (entry.uid < 0 || entry.uid >= MAX_USERS) {
            fprintf(stderr, "Warning: User ID %d out of bounds, skipping entry.\n", entry.uid);
            continue;
        }

        if (entry.action_denied == 1) { 
            int found = 0;
            for (int i = 0; i < unique_file_count[entry.uid]; i++) {
                if (strcmp(entry.file, accessed_files[entry.uid][i]) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found && unique_file_count[entry.uid] < MAX_FILES) { 
                strncpy(accessed_files[entry.uid][unique_file_count[entry.uid]], entry.file, MAX_FILENAME_LENGTH);
                unique_file_count[entry.uid]++;
            }
        }
    }

    printf("Malicious users (attempted unauthorized access to more than 5 files):\n");
    for (int i = 0; i < MAX_USERS; i++) {
        if (unique_file_count[i] > 5) {
            printf("User ID: %d, Unauthorized File Accesses: %d\n", i, unique_file_count[i]);
        }
    }
}

// List modifications for a specified file
void list_file_modifications(FILE *log, char *file_to_scan) {
    struct log_entry entry;
    int modification_counts[MAX_USERS] = {0};
    char last_fingerprint[MAX_FILENAME_LENGTH] = "";  // Adjusted size to MAX_FILENAME_LENGTH

    while (fscanf(log, "%d %s %s %s %d %d %s", 
                  &entry.uid, entry.file, entry.date, entry.timestamp, 
                  &entry.access_type, &entry.action_denied, entry.fingerprint) == 7) {
        
        if (entry.uid < 0 || entry.uid >= MAX_USERS) {
            fprintf(stderr, "Warning: User ID %d out of bounds, skipping entry.\n", entry.uid);
            continue;
        }

        if (strcmp(entry.file, file_to_scan) == 0 && entry.access_type == 2) {
            if (strcmp(last_fingerprint, entry.fingerprint) != 0) {
                modification_counts[entry.uid]++;
                strncpy(last_fingerprint, entry.fingerprint, sizeof(last_fingerprint) - 1);
            }
        }
    }

    printf("Modifications for file: %s\n", file_to_scan);
    for (int i = 0; i < MAX_USERS; i++) {
        if (modification_counts[i] > 0) {
            printf("User ID: %d, Modifications: %d\n", i, modification_counts[i]);
        }
    }
}

int main(int argc, char *argv[]) {
    int ch;
    FILE *log;

    if (argc < 2) usage();

    if ((log = fopen("./file_logging.log", "r")) == NULL) {
        printf("Error opening log file \"%s\"\n", "./file_logging.log");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:m")) != -1) {
        switch (ch) {        
            case 'i':
                list_file_modifications(log, optarg);
                break;
            case 'm':
                list_unauthorized_accesses(log);
                break;
            default:
                usage();
        }
    }

    fclose(log);
    return 0;
}
