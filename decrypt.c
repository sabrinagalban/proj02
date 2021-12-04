#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include "simplified_des.h"

void decrypt_file(char *encrypted_filename, char *output_filename, uint16_t key, uint8_t num_rounds);

void print_usage(char *prog_name) {
	printf("usage: %s -o output_file [-n num_rounds] -k key input_file\n", prog_name);
}

int main(int argc, char **argv) {
	extern char *optarg;
	extern int optind;
	int option = -1;

	char *output_filename = NULL;

	bool set_key = false;
	uint16_t key = 0xFFFF;

	int num_rounds = 2; // default to 2 rounds

	while((option = getopt(argc, argv, "o:k:n:")) != -1) {
		switch(option){
			case 'o': 
				output_filename = optarg;
				break;
			case 'k':
				if (sscanf(optarg, "0x%hx\n", &key) != 1) {
					printf("Invalid value for -k option\n");
					print_usage(argv[0]);
					exit(1);
				}
				else if (strlen(optarg) > 5 || key > 0x1FF) {
					printf("Invalid key value (must be 0x0 - 0x1FF)\n");
					print_usage(argv[0]);
					exit(1);
				}
				set_key = true;
				break;
			case 'n':
				if (sscanf(optarg, "%d\n", &num_rounds) != 1) {
					printf("Invalid value for -n option\n");
					print_usage(argv[0]);
					exit(1);
				}
				else if (num_rounds < 1 || num_rounds > 9) {
					printf("Invalid number of rounds (must be 1 - 9)\n");
					print_usage(argv[0]);
					exit(1);
				}
				break;
			case '?': //used for some unknown options
				print_usage(argv[0]);
				exit(1);
				break;
		}
	}

	// check for missing required options and incorrect number of arguments
	if (optind == argc) {
		printf("Missing input filename.\n");
		print_usage(argv[0]);
		exit(1);
	}
	else if (optind != (argc - 1)) {
		printf("Too many arguments\n");
		print_usage(argv[0]);
		exit(1);
	}
	else if (output_filename == NULL) {
		printf("Missing -o option\n");
		print_usage(argv[0]);
		exit(1);
	}
	else if (!set_key) {
		printf("Missing -k option\n");
		print_usage(argv[0]);
		exit(1);
	}

	char *input_filename = argv[optind];

	printf("Simplfied DES Decryptor\n");
	printf("\tOutput File: %s\n", output_filename);
	printf("\tKey: 0x%hX\n", key);
	printf("\tNumber of rounds: %d\n", num_rounds);
	printf("\nDecrypting file: %s ...\n", input_filename);

	decrypt_file(input_filename, output_filename, key, num_rounds);

	return 0;
}

/**
 * Decrypts a file using the Simplified DES encryption algorithm.
 *
 * The encrypted file will begin with an (unencrypted) byte of data that says
 * how much padding (0, 1, or 2 bytes) was added to the end of the file before
 * encrypting.
 *
 * @note The key uses only 9 of the available 16 bits. The 7 most significant
 * bits should be ignored.
 *
 * @param encrypted_filename The filename of the file with encrypted data.
 * @param output_filename The filename where to write the decrypted version of
 * 			the file.
 * @param key The 9-bit encryption key.
 * @param num_rounds The number of rounds for decryption.
 */
void decrypt_file(char *encrypted_filename, char *output_filename, uint16_t key, uint8_t num_rounds) {
	FILE *input_file = fopen(encrypted_filename, "rb");
	if (input_file == NULL) {
		printf("error: could not open file %s\n", encrypted_filename);
		return;
	}

	FILE *output_file = fopen(output_filename, "wb");
	if (output_file == NULL) {
		printf("error: could not open file %s\n", output_filename);
		return;
	}

	// get size of the input file
	fseek(input_file, 0, SEEK_END);
	long int file_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);

	if (file_size % 3 != 1) {
		printf("Error: Input file doesn't not appear to be in the correct format.\n");
		return;
	}

	// Keep track of how many 3-byte reads we'll need to make from the file to
	// get all of the data.
	long int remaining_reads = (file_size - 1) / 3;

	// read in the amount of padding (for use at the end)
	uint8_t padding = 0;
	int num_read = fread(&padding, 1, 1, input_file);

	uint8_t *keys = generate_round_keys(key, num_rounds);

	while (!feof(input_file)) {
		uint32_t input_val = 0;

		num_read = fread(&input_val, 1, 3, input_file);
		remaining_reads--;

		uint8_t output_val = 3; // the size of the output (3 bytes)
	
		if (num_read == 3) {
			// Step 1: Split the 3 bytes of the encrypted data in two halves
			uint16_t l_half = input_val >> 12;
			uint16_t r_half = input_val & 0xFFF;

			// Step 2: Decrypt both halves of the block
			uint16_t l_decrypted = decrypt(l_half, keys, num_rounds);
			uint16_t r_decrypted = decrypt(r_half, keys, num_rounds);

			// Step 3: Combine the blocks into a 3 byte single value
			uint32_t decrypted_data = (l_decrypted << 12) | r_decrypted;

			// Step 4: Adds padding to the end
			if (remaining_reads == 0) {
				output_val -= padding;
			}

			// Writing the combined value to output file
			fwrite(&decrypted_data, 1, output_val, output_file);

		}
		else if (num_read == 0 && ferror(input_file)) {
			printf("Error reading file. Exiting program.\n");
			exit(1);
		}
	}

	free(keys);

	fclose(input_file);
	fclose(output_file);
}
