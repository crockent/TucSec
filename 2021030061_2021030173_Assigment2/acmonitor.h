#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct log_entry {
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char* date; /* file access date */
	char* time; /* file access time */

	char *fingerprint; /* file fingerprint */
	char* filename;

}Entry;

void usage(void);
void get_log_entry(Entry* log_entry, FILE* logfile);
int check_user(int array[], int user);
void list_unauthorized_accesses(FILE *log);
void list_file_modifications(FILE *log, char *file_to_scan);
