/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

#include "simple_crypto.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Datatype for our nonce 
typedef uint64_t nonce_t;

typedef struct {
    uint32_t component_id;
    nonce_t nonce1;
    nonce_t nonce2;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

// Data structure for holding the attestation data

// Key to help encrypt AT data with AP's public key
RsaKey AP_PUB_FOR_AT;

// Component private key for communication
RsaKey COMP_PRIV;
WC_RNG COMP_rng;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(nonce_t expected_nonce2, command_message* command);
void process_scan(void);
void process_validate(nonce_t nonce2, command_message* command);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_send(volatile uint8_t* buffer, uint8_t len) {
    // Use components public key to send messages yay
    // Hash the original buffer first, and append this to the message
    uint8_t encrypt_buffer[MAX_I2C_MESSAGE_LEN-1];
    uint8_t hash_out[HASH_SIZE];
    // constant K interlinked
    volatile int ret = 0;

    ret = wc_RsaPublicEncrypt(buffer, len, encrypt_buffer, sizeof(encrypt_buffer), &AP_PUB_FOR_AT, &COMP_rng);
    if(ret < 0) {
         return -1;
    }
     
    // Returns length encrypted so this should work
    send_packet_and_ack(ret, encrypt_buffer); 
    
    goto skip;

    // Send another message that digests the plaintext for message integrity
    if (hash(buffer, len , hash_out) != 0) {
         return -1;
    }

    send_packet_and_ack(sizeof(hash_out), hash_out);

skip:

    return ret;
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(volatile uint8_t* buffer) {
    // Use AP's private key to decrypt and validate the message 
    // Expect two messages.. the ciphertext and the hash
    uint8_t decrypted_buffer[MAX_I2C_MESSAGE_LEN-1]; 
    uint8_t hash_out[HASH_SIZE];
    volatile int preserved_len = 0;
    volatile int len = 0;

    // The ciphertext
    preserved_len = len = wait_and_receive_packet(buffer);

    if(len > sizeof(decrypted_buffer)) {
        LED_On(LED1);
        return -1;
    }

    len = wc_RsaPrivateDecrypt(buffer, len ,
                            decrypted_buffer, sizeof(decrypted_buffer), &COMP_PRIV );
    if (len < 0) {
        LED_On(LED1);
        return -1;
    }

    goto skip;

    // The hash
    wait_and_receive_packet(buffer);

    if (hash(decrypted_buffer, len, hash_out) != 0) {
                LED_On(LED1);
                return -1;
    }

    if (strcmp((char*)hash_out, (char*)buffer)) {
                LED_On(LED1);
                return -1;
    }
skip:
    bzero(buffer, preserved_len);
    memcpy(buffer, decrypted_buffer, len);
    
    return len;
}

typedef struct {
	int rand;
	int timestamp;
} plain_nonce;

nonce_t generate_nonce()
{
	plain_nonce plain;
	uint8_t hash_out[HASH_SIZE];

	plain.rand = rand();
	plain.timestamp = time(NULL);

	if (hash(&plain, sizeof(plain), hash_out) != 0) {
		printf("Error: hash\n");
	}

    return *((nonce_t *)(hash_out));
}

// Structure to hold the encrypted data
typedef struct {
    uint8_t AT_ECUST[RSA_KEY_LENGTH];
    uint8_t AT_ELOCA[RSA_KEY_LENGTH];
    uint8_t AT_EDATE[RSA_KEY_LENGTH];
} attestation_data;

uint8_t AT_DATA_DIGEST[HASH_SIZE];



// Encrypted AT Data
attestation_data encrypted_AT;

int init_at_pub_key(RsaKey* key, uint8_t* DER_Key, int len)
{
    int ret = 0;
    unsigned int idx = 0;

    // Initialize key structure
    ret = wc_InitRsaKey(key, NULL);
    if(ret < 0) { return -1;}

    // Use existing public key to finalize the creation of our pub
    ret = wc_RsaPublicKeyDecode(DER_Key, &idx, key, len);
    if(ret < 0) { return -1;}

    //print_debug("Generated pub key for attestation data\n");

    return 0;
}

int init_comp_priv_key(RsaKey* key, uint8_t* DER_Key, int len)
{
    int ret = 0;
    unsigned int idx = 0;

    // Initialize key structure
    ret = wc_InitRsaKey(key, NULL);
    if(ret < 0) { 
        return -1;
    }

    // Use existing public key to finalize the creation of our pub
    ret = wc_RsaPrivateKeyDecode(DER_Key, &idx, key, len);
    if(ret < 0) { 
        return -1;
    }

    //print_debug("Generated pub key for attestation data\n");

    return 0;
}

int encrypt_AT()
{
    int P_SIZE[] = {sizeof(ATTESTATION_LOC), sizeof(ATTESTATION_DATE), sizeof(ATTESTATION_CUSTOMER)};
    uint8_t* P_DATA[] = {(uint8_t*)ATTESTATION_LOC, (uint8_t*)ATTESTATION_DATE, (uint8_t*)ATTESTATION_CUSTOMER};
    uint8_t* E_DATA[] = {encrypted_AT.AT_ELOCA, encrypted_AT.AT_EDATE, encrypted_AT.AT_ECUST};
    int total_size = P_SIZE[0] + P_SIZE[1] + P_SIZE[2];
    int ret = 0;
    int i = 0;

    // If any of the attestation data's sizes are greater than the key length than
    // we must fail the encryption and quit
    if(P_SIZE[0]  > RSA_KEY_LENGTH ||
       P_SIZE[1]  > RSA_KEY_LENGTH ||
       P_SIZE[2]  > RSA_KEY_LENGTH) {
        printf("Failed to encrypt attestation data due to rsa length, bye bye");
        return -1;
    }
    // hash and store the hash value result in the digest global variable
    hash(P_DATA, total_size, AT_DATA_DIGEST);
    
    for (;i < 3;i++) { 
         ret = wc_RsaPublicEncrypt(P_DATA[i], P_SIZE[i], E_DATA[i], RSA_KEY_LENGTH, &AP_PUB_FOR_AT, &COMP_rng);
         if(ret < 0) { return -1;}
    }
    
    return 0;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;
    static nonce_t nonce2 = 0;
    

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot(nonce2, command);
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        nonce2 = generate_nonce();
        process_validate(nonce2, command);
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot(nonce_t expected_nonce2, command_message* command) {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
	if (expected_nonce2 == 0) {
        printf("nonce2 is not generated\n");
        return;
	}

    nonce_t nonce2;
    memcpy(&nonce2, command->params, sizeof(nonce2));
    
    if (expected_nonce2 != nonce2) 
    {
        printf("Could not validate AP\n");
        return;
    }

    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);

    secure_send(transmit_buffer, len);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    nonce_t nonce1;
    command_message* cmd = (command_message*) receive_buffer;
    memcpy(&nonce1, cmd->params, sizeof(nonce1));

    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    packet->nonce1 = nonce1;
    secure_send(transmit_buffer, sizeof(validate_message));
}

void process_validate(nonce_t nonce2, command_message* command) {
    // The AP requested a validation. Respond with the Component ID
    nonce_t nonce1;
    memcpy(&nonce1, command->params, sizeof(nonce1));

    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    packet->nonce1 = nonce1;
    packet->nonce2 = nonce2;
    secure_send(transmit_buffer, sizeof(validate_message));
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    int i = 0;
    int copied = 0;
    // Since we're bottlenecked with i2c message size, send exactly 4 messages
    // AT_CUST, AT_LOC, AT_DATE, HASH DIGEST
    uint8_t* DATA[4] = {encrypted_AT.AT_ECUST, encrypted_AT.AT_ELOCA, encrypted_AT.AT_EDATE, AT_DATA_DIGEST};

    for(; i < 4; i++)
    {
        memset(transmit_buffer, 0 , sizeof(transmit_buffer));
        if(i == 3)
        {   
            copied = HASH_SIZE;
            memcpy(transmit_buffer, DATA[i], HASH_SIZE);
        } else {
            copied = MAX_I2C_MESSAGE_LEN;
            memcpy(transmit_buffer, DATA[i], MAX_I2C_MESSAGE_LEN); // Fix the size here
        }
        
        secure_send(transmit_buffer, copied);
    }
    return;
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();

    // Enable library's randomness generator
    MXC_TRNG_Init();
   
   // Initialize the Randomizer :P
    if(wc_InitRng(&COMP_rng) < 0) { 
         return -1;
    }
   
    // Encrypt component's AT data with AP's public key
    if (init_at_pub_key(&AP_PUB_FOR_AT, (uint8_t*)AP_PUB_AT, sizeof(AP_PUB_AT)) < 0
    || encrypt_AT() < 0 )
    {
        return -1;
    }
    
    // Initialize COMP public key for communication
    if (init_comp_priv_key(&COMP_PRIV ,(uint8_t*)COMP1_PRIV, sizeof(COMP1_PRIV)) < 0)
    {
        return -1;
    }
   
    // Seed our random number generator using build time secret
    srand((unsigned int)COMP_SEED);

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    if (board_link_init(addr) != E_NO_ERROR)
    {
         return -1;
    }
    
    LED_On(LED2);

    while (1) {
        secure_receive(receive_buffer);

        component_process_cmd();
    }
}

