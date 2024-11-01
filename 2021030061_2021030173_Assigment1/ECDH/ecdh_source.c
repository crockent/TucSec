#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>

void printHelp() {
    printf("Options:\n\
    -o path  Path to output file\n\
    -a key   Alice's private key (32 bytes in hex)\n\
    -b key   Bob's private key (32 bytes in hex)\n\
    -h       This help message\n");
}

// Function to convert hex string to binary and pad shorter inputs
int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);

    // Ensure hex string doesn't exceed expected length (64 characters)
    if (hex_len > bin_len * 2) {
        return -1; // Too long
    }

    // Pad the beginning with zeros if the input is shorter
    memset(bin, 0, bin_len);
    for (size_t i = 0; i < hex_len; i++) {
        sscanf(hex + i, "%1hhx", &bin[(i + bin_len * 2 - hex_len) / 2] + (i % 2 == 0 ? 0 : 1));
    }
    return 0;
}

void print_hex(const char *label, unsigned char *bin, size_t bin_len) {
    printf("%s", label);
    for (size_t i = 0; i < bin_len; i++) {
        printf("%02x", bin[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    // Initialize libsodium
    if (sodium_init() == -1) {
        return 1;  // libsodium initialization failed
    }

    // Variables for command-line arguments
    char *output_path = NULL;
    char *alice_private_key_hex = NULL;
    char *bob_private_key_hex = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "o:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            case 'a':
                alice_private_key_hex = optarg;
                break;
            case 'b':
                bob_private_key_hex = optarg;
                break;
            case 'h':
            default:
                printHelp();
                return 0;
        }
    }
    // Define Alice's keys
    unsigned char Alice_private_key[32];  // Buffer for Alice's private key
    unsigned char Alice_public_key[32];   // Buffer for Alice's public key

    // If Alice's private key is provided, convert from hex to binary
    if (alice_private_key_hex) {
        if (hex_to_bin(alice_private_key_hex, Alice_private_key, sizeof(Alice_private_key)) != 0) {
            printf("Invalid Alice's private key.\n");
            return 1;
        }
    } else {
        // Generate Alice's private key
        randombytes_buf(Alice_private_key, sizeof(Alice_private_key));
        printf("Generated Alice's private key.\n");
    }

    // Compute Alice's public key
    crypto_scalarmult_base(Alice_public_key, Alice_private_key);

    // Define Bob's keys
    unsigned char Bob_private_key[32];    // Buffer for Bob's private key
    unsigned char Bob_public_key[32];     // Buffer for Bob's public key

    // If Bob's private key is provided, convert from hex to binary
    if (bob_private_key_hex) {
        if (hex_to_bin(bob_private_key_hex, Bob_private_key, sizeof(Bob_private_key)) != 0) {
            printf("Invalid Bob's private key.\n");
            return 1;
        }
    } else {
        // Generate Bob's private key
        randombytes_buf(Bob_private_key, sizeof(Bob_private_key));
        printf("Generated Bob's private key.\n");
    }

    // Compute Bob's public key
    crypto_scalarmult_base(Bob_public_key, Bob_private_key);

    // Compute shared secrets
    unsigned char S_A[32];  // Alice's shared secret
    unsigned char S_B[32];  // Bob's shared secret

    // Alice computes shared secret using her private key and Bob's public key
    if (crypto_scalarmult(S_A, Alice_private_key, Bob_public_key) != 0) {
        printf("Error computing Alice's shared secret.\n");
        return 1;
    }

    // Bob computes shared secret using his private key and Alice's public key
    if (crypto_scalarmult(S_B, Bob_private_key, Alice_public_key) != 0) {
        printf("Error computing Bob's shared secret.\n");
        return 1;
    }

    // Compare shared secrets
    if (memcmp(S_A, S_B, 32) == 0) {
        printf("Shared secrets match!\n");

        // Save the result to the output file
        if (output_path) {
            FILE *output_file = fopen("ecdh.txt", "w+");
            if (output_file == NULL) {
                printf("Error opening output file.\n");
                return 1;
            }
            fprintf(output_file, "Alice's Public Key: \n");
            for (int i = 0; i < 32; i++) {
                fprintf(output_file, "%02x", Alice_public_key[i]);
            }
            fprintf(output_file, "\nBob's Public Key: \n");
            for (int i = 0; i < 32; i++) {
                fprintf(output_file, "%02x", Bob_public_key[i]);
            }
            fprintf(output_file, "\nAlice's Shared Secret: \n");
            for (int i = 0; i < 32; i++) {
                fprintf(output_file, "%02x", S_A[i]);
            }
            fprintf(output_file, "\nBob's Shared Secret: \n");
            for (int i = 0; i < 32; i++) {
            fprintf(output_file, "%02x", S_B[i]);
            }
            fprintf(output_file, "\n");
            fclose(output_file);
        }
    } else {
        printf("Shared secrets don't match.\n");
    }

    return 0;
}
