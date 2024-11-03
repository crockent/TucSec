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

	char* date; /* file access date */
	char* time; /* file access time */

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
    log_entry->time = malloc(sizeof(char)*20);
    log_entry->date = malloc(sizeof(char)*20);
    if (!log_entry->file || !log_entry->fingerprint) {
        printf("Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Use a buffer to hold the date string
    char date_buffer[50];

    if (fscanf(logfile, "%d %s %s %s %d %d %s",
           &(log_entry->uid), log_entry->file, 
           log_entry->date,
           log_entry->time, // use buffer for date
           &(log_entry->access_type), &(log_entry->action_denied), 
           log_entry->fingerprint) != 10) { // Ensure we read all expected values
        printf("Log entry format is invalid\n");
        exit(EXIT_FAILURE);
    }

   
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
        printf("Memory allocation failed\n");
        return;
    }

    // Arrays for malicious users and deny counts
    int mal_users[size];
    int denies[size];
    memset(denies,0,sizeof(denies));
    if (!mal_users || !denies) {
        printf("Memory allocation failed\n");
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




void list_file_modifications(FILE *log, const char *file_to_scan) {	
    fseek(log, 0, SEEK_END); 
    int size = ftell(log); 
    fseek(log, 0, SEEK_SET); 

    LOG** log_list = malloc(size * sizeof(LOG*));  
    int real_size = 0;

    char *real_path = realpath(file_to_scan, NULL);
    if (!real_path) {
        perror("Error resolving file path");
        free(log_list);
        return;
    }

    while (!feof(log)) {
        LOG *temp_log = malloc(sizeof(LOG));
        get_user_log_entry(temp_log, log);
        
        if (strcmp(real_path, temp_log->file) == 0) {
            log_list[real_size++] = temp_log;
        } else {
            free(temp_log);  // Free entry if it's not the target file
        }
    }

    free(real_path);  // Free resolved path after use

    if (real_size == 0) {
        printf("file not found\n");
        free(log_list);
        return;
    }

    int *users = malloc(real_size * sizeof(int));
    int *mods = calloc(real_size, sizeof(int));
    
    if (!users || !mods) {
        perror("Memory allocation failed");
        free(log_list);
        free(users);
        free(mods);
        return;
    }

    char *hash_value = log_list[0]->fingerprint;
    users[0] = log_list[0]->uid;
    mods[0] = 1;
    int index = 1;

    for (int i = 1; i < real_size; i++) {
        char *temp_value = log_list[i]->fingerprint;
        if (strcmp(temp_value, hash_value) != 0) {
            int check_user = check(users, log_list[i]->uid);
            if (check_user != -1) {  // User exists in list
                mods[check_user]++;
            } else {
                users[index] = log_list[i]->uid;
                mods[index++] = 1;
            }
            hash_value = log_list[i]->fingerprint;
        }
    }

    // Display results
    for (int i = 0; i < index; i++) {
        printf("User %d modified the file %d times\n", users[i], mods[i]);
    }

    // Free allocated memory
    for (int i = 0; i < real_size; i++) {
        free(log_list[i]);
    }
    free(log_list);
    free(users);
    free(mods);
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


