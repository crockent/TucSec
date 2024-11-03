#include"acmonitor.h"

void
usage(void)
{	
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );
	exit(1);
}

void get_log_entry(Entry* log_entry, FILE* logfile){
	log_entry->filename = malloc(sizeof(char)*50);
	log_entry->fingerprint = malloc(sizeof(char)*50);
	log_entry->date = malloc(sizeof(char)*20);
	log_entry->time = malloc(sizeof(char)*20);
	char day[4], mon[4], n[3], year[5];
	//fscanf(logfile, "%d %s", &(log_entry->uid), log_entry->filename);

	fscanf(logfile, "%d %s %s %s %s %s %s %d %d %s", &(log_entry->uid), log_entry->filename, day, mon, n, year, log_entry->time, &(log_entry->access_type), &(log_entry->action_denied), log_entry->fingerprint);
	strcat(log_entry->date, day);
	strcat(log_entry->date, " ");
	strcat(log_entry->date, mon);
	strcat(log_entry->date, " ");
	strcat(log_entry->date, n);
	strcat(log_entry->date, " ");
	strcat(log_entry->date, year);
	//fscanf(logfile, "%s %d %d %s", log_entry->time, &(log_entry->access_type), &(log_entry->action_denied), log_entry->fingerprint);
	//printf("here %s\n", log_entry->fingerprint);
}

int check_user(int array[], int user){
	int size = sizeof(array) / sizeof(user);
	for(int i=0;i<size;i++){
		if(array[i] == user)
			return i;
	}
	return -1;	//not found
}


void 
list_unauthorized_accesses(FILE *log)
{
	fseek(log, 0, SEEK_END); 
	int size = ftell(log); 
	fseek(log, 0, SEEK_SET); 

	Entry** log_list = malloc(size*sizeof(Entry*));

	int mal_users[size];
	int denies[size]; 
	memset(denies, 0, sizeof(denies));	//all elements set to 0
	int index = 0;
	int i = 0;
	while(!feof(log)){
		log_list[i] = malloc(sizeof(Entry));
		get_log_entry(log_list[i], log);
		if(log_list[i]->action_denied == 1){
			int user_exists = check_user(mal_users, log_list[i]->uid);
			if(user_exists != -1){	//user exists in mal_list
				denies[user_exists]++;
			}
			else{
				mal_users[index] = log_list[i]->uid;
				denies[index]++;
				index++;
			}
		}
		i++;
	}

	for(int i = 0;i<index;i++){
		if(denies[i] > 7){
			printf("user id: %d\n", mal_users[i]);
		}
	}



	for(int i = 0;i<size;i++){
		free(log_list[i]);
	}
	free(log_list);
	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{	
	fseek(log, 0, SEEK_END); 
	int size = ftell(log); 
	fseek(log, 0, SEEK_SET); 

	Entry** log_list = malloc(size*sizeof(Entry*));
	
	int real_size = 0;
	while(!feof(log)){
		Entry* temp_log = malloc(sizeof(Entry));
		get_log_entry(temp_log, log);
		//printf("%s\n", temp_log->filename);
		if(strcmp(realpath(file_to_scan, NULL), temp_log->filename) == 0){
			log_list[real_size] = malloc(sizeof(Entry));
			log_list[real_size] = temp_log;
			real_size++;
		}
		//free(temp_log);
	}

	if(real_size == 0){
		printf("file not found\n");
		return ;
	}

	int users[real_size];
	int mods[real_size]; 
	memset(mods, 0, sizeof(mods));	//all elements set to 0
	char* hash_value = log_list[0]->fingerprint;
	users[0] = log_list[0]->uid;
	mods[0]++;
	int index = 1;
	for(int i = 0;i<real_size;i++){
		char* temp_value = log_list[i]->fingerprint;
		if(strcmp(temp_value, hash_value) != 0){
			int check = check_user(users, log_list[i]->uid);
			if(check != -1){	//user exists in list
				mods[check]++;
			}
			else{
				users[index] = log_list[i]->uid;
				mods[index]++;
				index++;
			}
		hash_value = log_list[i]->fingerprint;
		}
	}

	for(int i=0;i<index; i++){
		printf("user id: %d modified the file %d times\n", users[i], mods[i]);
	}


	for(int i = 0;i<real_size;i++){
		free(log_list[i]);
	}
	free(log_list);
	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
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
	argc -= optind;
	argv += optind;	
	
	return 0;
}
