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
    // Allocate enough space for strings
    log_entry->file = malloc(sizeof(char) * 256);  // Increased size
    log_entry->fingerprint = malloc(sizeof(char) * 256);  // Increased size
    if (!log_entry->file || !log_entry->fingerprint) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Use a buffer to hold the date string
    char date_buffer[50];
    char day[4], mon[4], n[3], year[5];

    if (fscanf(logfile, "%d %s %s %s %s %s %s %d %d %s",
           &(log_entry->uid), log_entry->file, 
           day, mon, n, year, 
           date_buffer,  // use buffer for date
           &(log_entry->access_type), &(log_entry->action_denied), 
           log_entry->fingerprint) != 10) { // Ensure we read all expected values
        fprintf(stderr, "Log entry format is invalid\n");
        exit(EXIT_FAILURE);
    }

    // Optionally: parse date_buffer if needed, currently set to time(NULL)
    log_entry->date = time(NULL); // Adjust this line if you need actual date parsing
}

int check(int *users,int user){
	int size = sizeof(users)/sizeof(user);
	for(int i=0; i<size;i++){
		if(users[i]==user);
			return i;
	}
	return -1;
}

void list_unauthorized_accesses(FILE *log) {
    // Move to the end to find the size
    fseek(log, 0, SEEK_END);
    long size = ftell(log);
    fseek(log, 0, SEEK_SET);

    // Allocate memory for entries
    LOG** log_entry_list = malloc(size * sizeof(LOG*)); // Changed to LOG
    if (!log_entry_list) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    // Arrays for malicious users and deny counts
    int mal_users[size];
    int denies[size];
    memset(denies,0,sizeof(denies));
    if (!mal_users || !denies) {
        fprintf(stderr, "Memory allocation failed\n");
        free(log_entry_list);
        return;
    }

    int entry_count = 0;
    int j=0;

    // Read entries from log
    while (!feof(log)) {
    	log_entry_list[j]= malloc(size * sizeof(LOG));
    	get_user_log_entry(log_entry_list[j],log);
    	if(log_entry_list[j]->action_denied==1){
    		int exists = check(mal_users,log_entry_list[j]->uid);
    		if(exists==-1){
    			mal_users[entry_count]= log_entry_list[j]->uid;
    			denies[entry_count]++;
    			entry_count++;
    		}else denies[exists]++;
    	}
    	j++;
    }


    for(int i=0; i<entry_count; i++){
    	if(denies[i]>5){
    		printf("user id: %d\n", mal_users[i]);
    	}
    }

    for(int i =0; i<size; i++){
    	free(log_entry_list[i]);
    }
    free(log_entry_list);
    return;
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
