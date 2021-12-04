#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "simplified_des.h"

// defining constants
#define block_size 12	// the size of the block of the array
#define k_length 9	// the length of the keys

// These are used in the confuse function and convert 4 bit values into
// different 3 bit values
const uint8_t s1_box[16] = { 5, 2, 1, 6, 3, 4, 7, 0, 1, 4, 6, 2, 0, 7, 5, 3 };
const uint8_t s2_box[16] = { 4, 0, 6, 5, 7, 1, 3, 2, 5, 3, 0, 7, 6, 2, 1, 4}; 

/**
 * This function will expand a 6 bit code of data into 8 bits it will do it such that
 * if the data given each bit is ordered 123456 the new value returned is 12434356
 *
 * @param input is the 6 bit of data that is passed in 
 *
 * @return the expabnded 8 bit value
 */
uint8_t expand(uint8_t input) {
	// this statement breaks the input up with masks then shifts them to the
	// correct spot 1 or 2 bits at a time then does an or statement to bring
	// them all together
	return ((input & 48) << 2) | ((input & 4) << 3) | ((input & 12) <<1) | ((input & 8)>>1) | (input & 3);
}

/**
 * This function takes an 8 bit and turn the first 4 bits into the
 * corresponding 3 bits from s_1 box as well as the last 4 bits through s_2
 * box it then concatenates this in the same order they were given
 *
 * @param input this is the 8 bit value to be confused 
 *
 * @return the 6 bit value that was gotten through the process above
 */
uint8_t confuse(uint8_t input) {
	return (s1_box[input >> 4] << 3) | s2_box[input & 15];
}

/**
 * This function does a feistel round by running through the feistel function 
 * 
 * @param key the key generated for this round that needs to be used in the
 * function
 * @param input the 6 bit value that will go through the feistel function
 *
 * @return the value that is created from the feistel equation
 */
uint8_t feistel(uint8_t input, uint8_t key) {
	return confuse(expand(input) ^ key);
}

/**
 * This function does an entire round of the encryption, It moves the right
 * bits to the left and does the feisel function of the right bits xor the
 * left bits
 *
 * @param key the key that will be used in this round 
 * @param input the input value that is given to this function from the
 * previous round
 *
 * @return the value that is used for the next round or the final encrypted
 * int
 */
uint16_t feistel_round(uint16_t input, uint8_t key) {
	return ((input & 63) << 6) | (feistel(input & 63, key) ^ (input >> 6));
}

/**
 * This function will take in a 9-bit master key then generate the requested number of round keys.
 * 
 * @note if thenhumber of rounds is greater than 9 (k_length) then no keys will be generate and will return
 *  NULL immeadiately.
 *
 * @param original_key the original key
 * @param num_rounds the number of rounds
 *
 * @return round_keys the generated round keys.
 */
uint8_t *generate_round_keys(uint16_t original_key, unsigned int num_rounds) {	
	if (num_rounds > k_length) { 
		return NULL;
	}

	// allocating enough space for the array to store the round keys and the masks
	uint8_t *round_keys = calloc(num_rounds, sizeof(uint8_t));

	// bitwise left shift or adds zeros to the leftmost side, casted into an integer
	uint32_t l_mask = (int)(pow(2, k_length - 1) - 1) << 1;

	// bitwise right shift, esentially undos the l_mask pr adds zeroes to the rightmost side
	uint32_t r_mask = l_mask << k_length;

	// This for loop generates the requested number of round keys
	for (unsigned int i = 0; i < num_rounds; i++) {

		// for each key, the original key is applied with the mask then, shifted to match one another
		uint32_t l_key = (original_key & l_mask) << (k_length + i);
		uint32_t r_key = (original_key & r_mask) << i;

		// adds both sides of the key, shifts them to the correct pos then adds them into an index in the array
		round_keys[i] = (l_key | r_key) >> (k_length + 1);

		// shifts the masks by 1, adding padding for the next iteration
		l_mask = l_mask >> 1;
		r_mask = r_mask >> 1;
	}

	// if the number of rounds is greater then k_length = 9, then return null
	return round_keys;
}

/**
 * This function will encrypt the data passed into it. The data is split into two halves
 * then shifted to match the required size, combined then return the unencrypted data.
 *
 * @param unencrypted_data the unencrypted data file
 * @param round_keys the keys generated for the number of rounds
 * @param num_rounds the number of rounds
 *
 * @return unencrypted_data the unencrypted data file
 */
uint16_t encrypt(uint16_t unencrypted_data, uint8_t *round_keys, int num_rounds) {
	int i;
	// for loop to iterate through the number of rounds
	for (i = 0; i < num_rounds; i++) {
		unencrypted_data = feistel_round(unencrypted_data, round_keys[i]);
	}

	// 32 bit value is split in half and shifted to match size
	uint16_t l_encrypted = (unencrypted_data & 0x03F) << 6;		// shift left 6 because only using 24 bits
	uint16_t r_encrypted = (unencrypted_data & 0xFC0) >> 6;		// shift right 6 because only using 24 bits

	// combinging the two halves into one
	unencrypted_data = l_encrypted | r_encrypted;
	return unencrypted_data;
}

/**
 * This function will decrypt the datafile that is passed into it. Similiar to the encrypt function,
 * the data is split into two halves, shifted to match the required size, combined then return the
 * decrypted data.
 *
 * @param encrypted_data the encrypted_data file
 * @param round_keys the keys generated for the number of rounds
 * @param num_rounds the number of rounds
 *
 * @return encrypted_data the encrypted data file
 */
uint16_t decrypt(uint16_t encrypted_data, uint8_t *round_keys, int num_rounds) {
	int i;
	// for loop to iterate through the number of rounds
	for (i = num_rounds-1; i >= 0; i--) {
		encrypted_data = feistel_round(encrypted_data, round_keys[i]);
	}
	
	// splits the 32 bit input_val into two then utilizes only lower 24 bits
	uint16_t l_unencrypted = (encrypted_data & 0x03F) << 6;		// shift left 6 because only using 24 bits
	uint16_t r_unencrypted = (encrypted_data & 0xFC0) >> 6;		// shift right 6 because only using 24 bits

	// combining the two halves into one
	encrypted_data = l_unencrypted | r_unencrypted;
	return encrypted_data;
}

