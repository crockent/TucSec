#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define MAX_USERS 1000
#define MAX_FILES 100
#define MAX_FILENAME_LENGTH 256

typedef struct log_entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */


}LOG;

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

void get_user_log_entry(LOG* log_entry, FILE* logfile) {
    log_entry->file = malloc(sizeof(char) * 50);
    log_entry->fingerprint = malloc(sizeof(char) * 50);
    
    // Use a buffer to hold the date string
    char date_buffer[50];
    char day[4], mon[4], n[3], year[5];

    fscanf(logfile, "%d %s %s %s %s %s %s %d %d %s", 
           &(log_entry->uid), log_entry->file, 
           day, mon, n, year, 
           date_buffer,  // use buffer for date
           &(log_entry->access_type), &(log_entry->action_denied), 
           log_entry->fingerprint);

    // Combine day, month, number and year into a single string
    snprintf(date_buffer, sizeof(date_buffer), "%s %s %s %s", day, mon, n, year);
    log_entry->date = time(NULL); // or parse from date_buffer if needed
}



int check_user(int* users, int uid, int count) {
    for (int i = 0; i < count; i++) {
        if (users[i] == uid) {
            return i; // Return the index if user exists
        }
    }
    return -1; // User not found
}

void list_unauthorized_accesses(FILE *log) {
    // Move to the end to find the size
    fseek(log, 0, SEEK_END);
    int size = ftell(log);
    fseek(log, 0, SEEK_SET);

    // Allocate memory for entries
    LOG *log_entry = malloc(size * sizeof(LOG)); // Changed to LOG
    if (!log_entry) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    // Arrays for malicious users and deny counts
    int *mal_users = malloc(size * sizeof(int));
    int *denies = calloc(size, sizeof(int));
    if (!mal_users || !denies) {
        fprintf(stderr, "Memory allocation failed\n");
        free(log_entry);
        return;
    }

    int entry_count = 0; 

    // Read entries from log
    while (!feof(log)) {
        if (entry_count >= size) {
            size *= 2;
            log_entry = realloc(log_entry, size * sizeof(LOG));
            mal_users = realloc(mal_users, size * sizeof(int));
            denies = realloc(denies, size * sizeof(int));
            if (!log_entry || !mal_users || !denies) {
                fprintf(stderr, "Memory allocation failed\n");
                free(log_entry);
                free(mal_users);
                free(denies);
                return;
            }
        }

        get_user_log_entry(&log_entry[entry_count], log); // Corrected to pass a LOG*

        // Check for unauthorized access
        if (log_entry[entry_count].action_denied == 1) {
            int user_index = check_user(mal_users, log_entry[entry_count].uid, entry_count);
            if (user_index != -1) {
                denies[user_index]++;
            } else {
                mal_users[entry_count] = log_entry[entry_count].uid;
                denies[entry_count]++;
            }
        }
        entry_count++;
    }

    // Print users with more than 5 denies
    for (int i = 0; i < entry_count; i++) {
        if (denies[i] > 5) {
            printf("User ID: %d\n", mal_users[i]);
        }
    }

    // Free allocated memory
    free(log_entry);
    free(mal_users);
    free(denies);
}

// List modifications for a specified file
/*void list_file_modifications(FILE *log, char *file_to_scan) {
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
}*/

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
                //list_file_modifications(log, optarg);
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
