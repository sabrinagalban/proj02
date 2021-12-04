#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>

#include "simplified_des.h"


void encrypt_file(char *input_filename, char *output_filename, uint16_t key, uint8_t num_rounds);

void print_usage(char *prog_name) {
	printf("usage: %s -o output_file [-n num_rounds] -k key input_file\n", prog_name);
}

int main(int argc, char** argv) {

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

	printf("Simplfied DES Encryptor\n");
	printf("\tOutput File: %s\n", output_filename);
	printf("\tKey: 0x%hX\n", key);
	printf("\tNumber of rounds: %d\n", num_rounds);
	printf("\nEncrypting file: %s ...\n", input_filename);

	encrypt_file(input_filename, output_filename, key, num_rounds);
	return 0;
}


/**
 * Encrypts a file using the Simplified DES encryption algorithm.
 *
 * If the input file size (in bytes) is not a multiple of 3, padding is added
 * to the end of the file to make the size a multiple of 3 and thus ensure the
 * cipher has only 12-bit blocks to work with.
 * The file where the encrypted version is written begins with a 1 byte value
 * indicating how many bytes of data (0, 1, or 2) needed to be added as
 * padding at the end.
 *
 * @note The key uses only 9 of the available 16 bits. The 7 most significant
 * bits should be ignored.
 *
 * @param input_filename The filename of the file to encrypt.
 * @param output_filename The filename where to write the encrypted version of
 * 			the file.
 * @param key The 9-bit encryption key.
 * @param num_rounds The number of rounds for decryption.
 */
void encrypt_file(char *input_filename, char *output_filename, uint16_t key, uint8_t num_rounds) {
	// WARNING: DO NOT MODIFY THIS FUNCTION IN ANY WAY!
	
	// Open the input and output files in binary mode.
	FILE *input_file = fopen(input_filename, "rb");
	if (input_file == NULL) {
		printf("error: could not open file %s\n", input_filename);
		return;
	}
	FILE *output_file = fopen(output_filename, "wb");
	if (output_file == NULL) {
		printf("error: could not open file %s\n", output_filename);
		return;
	}

	// Find the size of the input file
	fseek(input_file, 0, SEEK_END);
	long int input_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);

	// Determine the amount of padding we'll need to add at the end.
	uint8_t leftover = (input_size % 3);
	uint8_t padding = 0;
	if (leftover > 0) {
		padding = 3 - leftover;
	}

	// Write the amount of padding to the beginning of the output file.
	fwrite(&padding, 1, 1, output_file);

	uint8_t *keys = generate_round_keys(key, num_rounds);

	while (!feof(input_file)) {
		uint32_t unencrypted_data = 0;

		// Read 3 bytes (i.e. 24 bits) at a time, which will give us two full
		// 12-bit blocks to encrypt.
		int num_read = fread(&unencrypted_data, 1, 3, input_file);

		if (num_read == 0 && ferror(input_file)) {
			// Had a file reading error so quit the program
			printf("Error reading file. Exiting!\n");
			exit(1);
		}

		else if (num_read > 0) {
			// We were able to read in some data so let's encrypt it and write it out
			//printf("input val (2 blocks): %x\n", unencrypted_data);

			// extract the two 12-bit blocks for encryption
			uint16_t block1 = unencrypted_data & 0xFFF;
			uint16_t block2 = unencrypted_data >> 12;

			uint16_t encrypted_block1 = encrypt(block1, keys, num_rounds);
			uint16_t encrypted_block2 = encrypt(block2, keys, num_rounds);

			// Combine the two encrypted blocks into one 3-byte value and
			// write that to the output file. 
			uint32_t output_val = encrypted_block1 | (encrypted_block2 << 12);
			//printf("writing encrypted data: %x\n", output_val);
			fwrite(&output_val, 1, 3, output_file);
		}
	}

	free(keys);

	fclose(input_file);
	fclose(output_file);
}
