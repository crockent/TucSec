#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>

void printHelp() {
    printf("Options:\n\
    -i path Path to the input file\n\
    -o path Path to the output file\n\
    -k path Path to the key file\n\
    -g length Perform RSA key-pair generation given a key length “length”\n\
    -d Decrypt input and store results to output.\n\
    -e Encrypt input and store results to output.\n\
    -a Compare the performance of RSA encryption and decryption with three\n\
    different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n\
    -h This help message\n");
}

//Function generates a prime number
void generatePrime(mpz_t prime, int length) {

    gmp_randstate_t state;

    // Initialize GMP variables (allocate memory)
    mpz_init(prime);
    gmp_randinit_default(state);

    // Generate a random number with given length
    mpz_urandomb(prime, state, length);

    mpz_setbit(prime, length - 1);


    // Find the next prime number greater than or equal to the generated number
    mpz_nextprime(prime, prime);

    gmp_randclear(state);
}

int generateRSAKeyPair(int length,mpz_t file_n,mpz_t priv_num, mpz_t public_num){
    mpz_t p;
    mpz_t q;

    //allocating memory for p and q
    mpz_init(p);
    mpz_init(q);

    //create the two prime numbers 
    generatePrime(p,length/2);
    generatePrime(q,length/2);

    //Now that we have the prime num P and the prime Num Q we calculate n
    mpz_t n;
    mpz_init(n);
    mpz_mul(n,p,q);

    //calculate Euler’s totient function
    mpz_t lambda;
    mpz_init(lambda);
    mpz_t p_minus_1, q_minus_1;
    mpz_init_set(p_minus_1, p);
    mpz_init_set(q_minus_1, q);
    mpz_sub_ui(p_minus_1, p_minus_1, 1);
    mpz_sub_ui(q_minus_1, q_minus_1, 1);
    mpz_mul(lambda, p_minus_1, q_minus_1);
    //find e that satisfies the conditions
    mpz_t e;
    mpz_init_set_ui(e, 65537);//internet said this is a common value so we trust

    mpz_t gcd_res;
    mpz_init(gcd_res);
    mpz_gcd(gcd_res,lambda,e);
    while(mpz_cmp_ui(gcd_res, 1) != 0) {
        mpz_nextprime(e, e);
        mpz_gcd(gcd_res, lambda, e);
    }
    mpz_clear(gcd_res);

    //calculate d
    mpz_t d;
    mpz_init(d);
    mpz_invert(d,e,lambda);

    mpz_init_set(file_n, n);
    mpz_init_set(public_num, e);
    mpz_init_set(priv_num, d);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(d);

    return 0;

}

int generateRSAKeyPairToFile(int length){
    //Specify file names for the keys
    char *pubKeyPath = "public_length.key";
    char *privKeyPath = "private_length.key";
   
    mpz_t n, e, d;
    generateRSAKeyPair(length, n, d, e);

    //Open the file
    FILE *file = fopen(privKeyPath, "w");
    if(file == NULL) {
        perror("Error opening file\n");
        return -1;
    }

    gmp_fprintf(file, "%Zd %Zd\n", n, d);       //Write the private key to the file

    fclose(file);       //Close the file

    //Open the file
    file = fopen(pubKeyPath, "w");
    if(file == NULL) {
        perror("Error opening file\n");
        return -1;
    }   

    gmp_fprintf(file, "%Zd %Zd\n",n, e);     //Write the public key to the file

    fclose(file);       //Close the file
    return 0;
}


void encrypt(mpz_t cipher_text, mpz_t message, mpz_t e, mpz_t n) {
    mpz_powm(cipher_text, message, e, n);
    //return 0;
}

void decrypt(mpz_t message, mpz_t cipher_text, mpz_t d, mpz_t n) {
    mpz_powm(message, cipher_text, d, n);
    //return 0;
}

int file_encrypt(char *inFile, char *outFile, char *keyFile) {
    FILE *in = fopen(inFile, "r");
    if (in == NULL) {
        perror("Error opening input file\n");
        return -1;
    }
    
    FILE *key = fopen(keyFile, "r");
    if (key == NULL) {
        perror("Error opening key file\n");
        return -1;
    }

    // Get the public key from the file
    mpz_t n, e;
    mpz_init(n);
    mpz_init(e);
    gmp_fscanf(key, "%Zd %Zd", n, e);

    // Read the input message as a string
    char message[256];  // Adjust the size as needed
    if (fgets(message, sizeof(message), in) == NULL) {
        perror("Error reading input message\n");
        return -1;
    }

      printf("Message: ");
    for (int i = 0; message[i] != '\0'; ++i) { // Loop until the null terminator is found
        printf("%c", message[i]);
    }
    printf("\n"); // Print a newline after the message

    // Remove newline character if present
    message[strcspn(message, "\n")] = 0;

    // Convert the string to a numeric representation
    mpz_t text;
    mpz_init(text);
    mpz_set_ui(text, 0);  // Initialize the variable to 0

    // Convert each character to its ASCII value and build the integer
    for (size_t i = 0; message[i] != '\0'; i++) {
        mpz_mul_ui(text, text, 256); // Shift left by 8 bits (or multiply by 256)
        mpz_add_ui(text, text, (unsigned char)message[i]); // Add the ASCII value
    }


    FILE *out = fopen(outFile, "w");
    if (out == NULL) {
        perror("Error opening output file\n");
        return -1;
    }

    mpz_t cipher_text;
    mpz_init(cipher_text);
    // Encrypt the text
    encrypt(cipher_text, text, e, n);

    mpz_out_str(out, 10, cipher_text);
    gmp_printf("Cipher: %Zd\n", cipher_text);

    // Free the memory and close the files
    mpz_clear(cipher_text);
    fclose(out);
    fclose(in);
    fclose(key);
    mpz_clear(text);
    mpz_clear(n);
    mpz_clear(e);

    return 0;
}


int file_decrypt(char *inFile, char *outFile, char *keyFile) {
    // Opening the input file
    FILE *in = fopen(inFile, "r");
    if (in == NULL) {
        perror("Error opening input file\n");
        return -1;
    }
    
    // Opening the key file
    FILE *key = fopen(keyFile, "r");
    if (key == NULL) {
        perror("Error opening key file\n");
        return -1;
    }

    mpz_t n;
    mpz_init(n);
    mpz_t d;
    mpz_init(d);
    gmp_fscanf(key, "%Zd %Zd", n, d);

    // Opening the output file
    FILE *out = fopen(outFile, "w");
    if (out == NULL) {
        perror("Error opening output file\n");
        return -1;
    }

    mpz_t cipher_text;
    mpz_init(cipher_text);
    mpz_inp_str(cipher_text, in, 10); // Get the cipher_text from input file
    gmp_printf("Cipher: %Zd\n", cipher_text);
    
    mpz_t decrypted_text;
    mpz_init(decrypted_text);
    
    // Decrypt the cipher text
    decrypt(decrypted_text, cipher_text, d, n);

    // Convert the decrypted text (numeric) back to string
    char message[256];  // Adjust the size as needed
    size_t index = 0;
    mpz_t temp;
    mpz_init(temp);

    // While the decrypted_text is greater than 0, extract characters
    while (mpz_cmp_ui(decrypted_text, 0) > 0) {
        // Get the least significant byte
        unsigned char char_value = mpz_fdiv_r_ui(temp, decrypted_text, 256); // Get the last byte
        mpz_fdiv_q_ui(decrypted_text, decrypted_text, 256); // Remove the last byte from decrypted_text
        
        // Add the character to the message array
        message[index++] = char_value;  // Store the character
    }
    
    // Null-terminate the string
    message[index] = '\0';

    // Write the decrypted message to the output file
    fprintf(out, "%s\n", message);
    printf("Message: ");
    for (int i = 0; message[i] != '\0'; ++i) { // Loop until the null terminator is found
        printf("%c", message[i]);
    }   

    // Free memory and close files
    mpz_clear(cipher_text);
    fclose(in);
    fclose(key);
    fclose(out);
    mpz_clear(decrypted_text);
    mpz_clear(temp);
    mpz_clear(n);
    mpz_clear(d);

    return 0;
}





long getMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);  // Get resource usage for the calling process
    return usage.ru_maxrss*1024;  // Return max resident set size (memory usage) in kilobytes
}


void performance(char *outFile) {
    int lengths[] = {1024, 2048, 4096};
    int length_num = sizeof(lengths) / sizeof(lengths[0]);

    FILE *perf_file = fopen(outFile, "w");
    if (perf_file == NULL) {
        perror("Error opening performance file\n");
        return;
    }

    for (int i = 0; i < length_num; i++) {
        int length = lengths[i];

        // Generate RSA Key Pair
        mpz_t n, e, d;
        mpz_init(n);
        mpz_init(e);
        mpz_init(d);
        generateRSAKeyPair(length, n, d, e);  // Generate keys

        char publicFile[50]; // Buffer to hold the filename
        sprintf(publicFile, "public_%d", lengths[i]); // Format the filename

        FILE *savefile_pub = fopen(publicFile, "w"); // Open the file
        if (savefile_pub == NULL) { // Check if the file opened successfully
            perror("Error opening public key file file\n");
            return;
        }
        gmp_fprintf(savefile_pub, "%Zd %Zd\n",n,e);

        char privFile[50]; // Buffer to hold the filename
        sprintf(privFile, "private_%d", lengths[i]); // Format the filename

        FILE *savefile_priv = fopen(privFile, "w"); // Open the file
        if (savefile_priv == NULL) { // Check if the file opened successfully
            perror("Error opening private key file file\n");
            return;
        }
        gmp_fprintf(savefile_priv, "%Zd %Zd\n",n,d);

        FILE *testFile = fopen("test.txt", "r"); // Open the file
        if (testFile == NULL) { // Check if the file opened successfully
            perror("Error opening test.txt file\n");
            return;
        }


        mpz_t cipher_text, plain_text;
        mpz_init(cipher_text);
        mpz_init(plain_text);

        gmp_fscanf(testFile, "%Zd", plain_text);
        // Measure encryption time and memory usage
        long memory_before_encrypt = getMemoryUsage(); // Memory before encryption
        clock_t start_time = clock();
        encrypt(cipher_text, plain_text, n, e);  // Encrypt the message
        clock_t end_time = clock();
        double encrypt_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC; // Convert to seconds
        long memory_after_encrypt = getMemoryUsage();  // Memory after encryption

        long peak_memory_encrypt = memory_after_encrypt - memory_before_encrypt;

        // Measure decryption time and memory usage
        mpz_t decrypted_text;
        mpz_init(decrypted_text);

        long memory_before_decrypt = getMemoryUsage(); // Memory before decryption
        start_time = clock(); // Reset start time for decryption
        decrypt(decrypted_text, cipher_text,n, d);  // Decrypt the cipher text
        end_time = clock();
        double decrypt_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC; // Convert to seconds
        long memory_after_decrypt = getMemoryUsage();  // Memory after decryption

        long peak_memory_decrypt = memory_after_decrypt - memory_before_decrypt;

        // Output the performance metrics
        fprintf(perf_file, "Key Length: %d bits\n", length);
        fprintf(perf_file, "Encryption Time: %.6f seconds\n", encrypt_time);
        fprintf(perf_file, "Decryption Time: %.6f seconds\n", decrypt_time);
        fprintf(perf_file, "Peak Memory Usage (Encryption): %ld Bytes\n", peak_memory_encrypt);  // Convert to Bytes
        fprintf(perf_file, "Peak Memory Usage (Decryption): %ld Bytes\n", peak_memory_decrypt);  // Convert to Bytes
        fprintf(perf_file, "-------------------------------------\n");

        // Clear GMP variables
        mpz_clear(n);
        mpz_clear(e);
        mpz_clear(d);
        mpz_clear(cipher_text);
        mpz_clear(plain_text);
        mpz_clear(decrypted_text);

        fclose(savefile_priv);
        fclose(savefile_pub);
    }

    fclose(perf_file);
}


int main(int argc, char **argv) {
    /*
        potisions of ops on byte:

        0: inputfile 
        1: outpufile
        2: keyfile
        3: key_length
        4: Decrypt 
        5: Enrypt
        6: Comparison

    */
    int flags = 0;

    char *inFile, *outFile, *keyFile;
    int keyLength = 0;

    int opt;
    while((opt = getopt(argc, argv, "i:o:k:g:a:deh")) != -1) {
        switch(opt) {
            case 'i':
                inFile = optarg;
                flags = flags | 0b00000001;
                break;
            case 'o':
                outFile = optarg;
                flags = flags | 0b00000010;
                break;
            case 'k':
                keyFile = optarg;
                flags = flags | 0b00000100;
                break;
            case 'g':
                keyLength = atoi(optarg);
                flags = flags | 0b00001000;
                break;
            case 'd':
                flags = flags | 0b00010000;
                break;
            case 'e':
                flags = flags | 0b00100000;
                break;
            case 'a':
                outFile = optarg;
                flags = flags | 0b01000000;
                break;
            case 'h':
                printHelp();
                return 0;
                break;
            default:
                printHelp();
                return 0;
                break;
        }
    }

    int check_op = flags & 0b00110000;  // Mask for encryption and decryption flags
    if (check_op == 0b00110000) {
    printf("Error: Cannot encrypt and decrypt at the same time\n");
    return -1;
    }

    if((flags ^ 0b00100111) == 0) {
        printf("Encrypting\n");
        file_encrypt(inFile, outFile, keyFile);
    }else if((flags ^ 0b00010111) == 0) {
        printf("Decrypting\n");
        file_decrypt(inFile, outFile, keyFile);
    } else if ((flags ^ 0b00001000) == 0) {
        printf("Generating key\n");
        generateRSAKeyPairToFile(keyLength);
    } else if ((flags ^ 0b01000000) == 0) {
        printf("Benchmarking\n");
        performance(outFile);
    }

    return 0;
}

