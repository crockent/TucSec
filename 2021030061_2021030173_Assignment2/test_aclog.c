#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "logger.h"

int main()
{
    int i;
    size_t bytes;
    FILE *file;
    char filenames[10][7] = {
        "file_0", "file_1", "file_2", "file_3", "file_4",
        "file_5", "file_6", "file_7", "file_8", "file_9"};

    // Step 1: Create files and write initial content
    printf("Creating files and writing initial content...\n");
    for (i = 0; i < 10; i++)
    {
        file = fopen(filenames[i], "w+");
        if (file == NULL)
        {
            printf("fopen error on file %s\n", filenames[i]);
        }
        else
        {
            bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
            fclose(file);

            // Remove write permissions for user on file_8
            if (i == 4 || i == 5 || i == 6 || i == 7 || i == 8 || i == 9)
            {
                if (chmod(filenames[i], S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) != 0)
                {
                    printf("Failed to remove write permissions for user on %s: %s\n", filenames[i], strerror(errno));
                }
                else
                {
                    printf("Removed write permissions for user on %s\n", filenames[i]);
                }
            }
        }
    }

    // Step 2: Attempt unauthorized access (read-only access on write-restricted files)
    printf("Attempting unauthorized access on files...\n");
    for (i = 0; i < 10; i++)
    {
        file = fopen(filenames[i], "w"); // Open as write-only
        if (file == NULL)
        {
            printf("Unauthorized access attempt for %s\n", filenames[i]);
        }
        else
        {
            fclose(file);
        }
    }

    // Step 3: Modify specific files multiple times
    printf("Modifying files multiple times...\n");
    for (i = 0; i < 5; i++)
    {
        file = fopen("file_0", "a"); // Open file_0 in append mode
        if (file != NULL)
        {
            bytes = fwrite("extra_data", strlen("extra_data"), 1, file);
            fclose(file);
        }
    }

    for (i = 0; i < 3; i++)
    {
        file = fopen("file_1", "a"); // Open file_1 in append mode
        if (file != NULL)
        {
            bytes = fwrite("extra_data", strlen("extra_data"), 1, file);
            fclose(file);
        }
    }

    printf("Testing completed.\n");
    return 0;
}
