/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_crypto.h"

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

int init_ap_priv_key(RsaKey* key, uint8_t* DER_Key, int len);
int init_comp_pub_key(RsaKey* key, uint8_t* DER_Key, int len);
/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 2 bytes to be send
// along with the opcode through board_link. This is only utilized by
// COMPONENT_CMD_VALIDATE and COMPONENT_CMD_BOOT currently.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Datatype for our nonce 
typedef uint64_t nonce_t;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
    nonce_t nonce1;
    nonce_t nonce2;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

// Stores the private key for the AP AT Data
RsaKey AP_AT_PRIV;
WC_RNG AP_rng;

// Stores the public key for the COMP Data and secure communication
RsaKey COMP_PUB;

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, volatile uint8_t* buffer, volatile uint8_t len) {
    // Use components public key to send messages yay
    // Hash the original buffer first, and append this to the message
    uint8_t encrypt_buffer[MAX_I2C_MESSAGE_LEN-1]; // regardless of input, rsa ciphertext will be equal to the modulus
    uint8_t hash_out[HASH_SIZE];
    volatile int preserved_len = 0;
    int ret = 0;

    if(len > RSA_KEY_LENGTH)
    {
         print_error("Encryption key is too small for payload, CRITICAL FAIL\n");
         return ERROR_RETURN;
    }

    ret = wc_RsaPublicEncrypt(buffer, len, encrypt_buffer, sizeof(encrypt_buffer), &COMP_PUB, &AP_rng);
    if(ret < 0) { 
         print_error("Public encryption failed - CRITICAL string is: %s and return is :%d and len is :%d!!!\n", buffer, ret, len);
         return ERROR_RETURN;
    }
    
    // Naturally, our function fails if the length exceeds the size of the i2c message bus which is 255
    preserved_len = send_packet(address, (uint8_t)ret, encrypt_buffer); 
    if(preserved_len < 0) { 
         // print_error("Packet failed to send! %d \n", preserved_len); Don't print this out, messes with list output
         return ERROR_RETURN;
    }
    
    goto skip;
    // Send out an acknowledge check here
    
    // Send another message that digests the plaintext for message integrity
    if (hash(buffer, len , hash_out) != 0) {
		print_error("Error: hash\n");
    }

    ret = send_packet(address, (uint8_t)sizeof(hash_out), hash_out);
    if(ret < 0) { 
         print_error("Hash packet failed to send\n");
         return ERROR_RETURN;
    }

skip:
    return preserved_len;
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, volatile uint8_t* buffer) {
    // Use AP's private key to decrypt and validate the message 
    // Expect two messages.. the ciphertext and the hash
    uint8_t decrypted_buffer[MAX_I2C_MESSAGE_LEN-1];; 
    uint8_t hash_out[HASH_SIZE];
    volatile int preserved_len = 0;
    volatile int len = 0;

    // The ciphertext
    preserved_len = len = poll_and_receive_packet(address, buffer);

    if(len > sizeof(decrypted_buffer))
    {
        print_error("Received buffer is greater than expected and will overflow, aborted\n");
        return ERROR_RETURN;
    }

    len = wc_RsaPrivateDecrypt(buffer, len ,
                            decrypted_buffer, sizeof(decrypted_buffer), &AP_AT_PRIV );
    if (len < 0) {
        print_error("Decryption ERROR - Critical - %d \n", len);
        return ERROR_RETURN;
    }
   
    goto skip;
 
    // The hash
    poll_and_receive_packet(address, buffer);

    if (hash(decrypted_buffer, len, hash_out) != 0) {
		print_error("Error: hash\n");
    }

    if (strcmp((char*)hash_out, (char*)buffer)) {
        print_error("ERROR - Message has been vandalized\n");
        return ERROR_RETURN;
    }

skip:

    bzero(buffer, preserved_len);
    memcpy(buffer, decrypted_buffer, len);

    return len;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
int init(void) {

    // Enable global interrupts    
    __enable_irq();

    // Initializes true randomness to enable the random generator for RSA encryption
    MXC_TRNG_Init();

    // Seed our random number generator using build time secret
    srand((unsigned int)AP_SEED);

    // Generate private key here using wolfssl
    
    // For AT Data
    if( init_ap_priv_key(&AP_AT_PRIV, (uint8_t*)AP_PRIV_AT, sizeof(AP_PRIV_AT)) < 0) { 
        print_error("FAILED to initialize key for private component, CRITICAL!\n");
        return -1; 
    }

    // Initialize the Randomizer for private communication :P
    int ret = wc_InitRng(&AP_rng); 
    if(ret != 0) { 
         print_error("Randomizer failed to initialize - suffer \n");
         return -2; 
    }

    // For Comp Data 
    if( init_comp_pub_key(&COMP_PUB, (uint8_t*)COMP1_PUB, sizeof(COMP_PUB)) < 0) { 
        print_error("FAILED to initialize key for public component, CRITICAL!\n");
        return -3; 
    }


    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();

    return 0;
}

int init_ap_priv_key(RsaKey* key, uint8_t* DER_Key, int len)
{
    int ret = 0;
    unsigned int idx = 0;

    // Initialize key structure
    ret = wc_InitRsaKey(key, NULL);
    if(ret < 0) { 
        print_error(" Error initializing RsaKey \n");
        return ERROR_RETURN;
    }

    // Use existing public key to finalize the creation of our pub
    ret = wc_RsaPrivateKeyDecode(DER_Key, &idx, key, len);
    if(ret < 0) { 
        print_error(" Error adding existing pub key in RsaKey \n");
        return ERROR_RETURN;
    }

    print_debug("Generated pub key for attestation data\n");

    return 0;
}

int init_comp_pub_key(RsaKey* key, uint8_t* DER_Key, int len)
{
    int ret = 0;
    unsigned int idx = 0;

    // Initialize key structure
    ret = wc_InitRsaKey(key, NULL);
    if(ret < 0) { 
        print_error(" Error initializing RsaKey \n");
        return ERROR_RETURN;    
    }

    // Use existing public key to finalize the creation of our pub
    ret = wc_RsaPublicKeyDecode(DER_Key, &idx, key, len);
    if(ret < 0) { 
        print_error(" Error adding existing pub key in RsaKey \n");
        return ERROR_RETURN;
    }

    //print_debug("Generated pub key for attestation data\n");

    return 0;
}


typedef struct {
	int rand;
	int timestamp;
} plain_nonce;

nonce_t generate_nonce(void)
{
	plain_nonce plain;
	uint8_t hash_out[HASH_SIZE];

	plain.rand = rand();
	plain.timestamp = time(NULL);

	if (hash(&plain, sizeof(plain), hash_out) != 0) {
		print_debug("Error: hash\n");
	}

    return *((nonce_t *)(hash_out));
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
	// TODO: secure_send(addr, transmit, sizeof(command_message)) doesn't work because:
    //   sizeof(command_message) : 256
    //   uint8_t len: 0-255
    int result = secure_send(addr, transmit, sizeof(nonce_t) + 1); // sizeof(nonce) + sizeof(opcode)
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = secure_receive(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components(void) {
    // Print out provisioned component IDs
    int count = flash_status.component_cnt;
  
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];


    for (int i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);

        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Generate nonce1 for validating component
        const nonce_t nonce1 = generate_nonce();

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        memcpy(command->params, &nonce1, sizeof(nonce_t)); // Request the component to send this nonce1 back

        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("command failed\n");
            continue;
        }

        validate_message* validate = (validate_message*) receive_buffer;

        // Remake validate_message structure
        if (validate->nonce1 != nonce1) {
            print_error("nonce1 value: %u invalid\n", validate->nonce1);
            continue;
        }
          
        // Success, device is present
        print_info("F>0x%08x\n", validate->component_id);

        if(validate->component_id == flash_status.component_ids[i]) {
                count--; 
        }
    }

    if(count != 0){
       print_error("List failed\n");
       return ERROR_RETURN;
    }

    print_success("List\n");
    return SUCCESS_RETURN;
  
}



int validate_components(nonce_t *nonce2) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Generate nonce1 for validating component
        const nonce_t nonce1 = generate_nonce();

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        memcpy(command->params, &nonce1, sizeof(nonce_t)); // Request the component to send this nonce1 back

        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;

        // Remake validate_message structure
        if (validate->nonce1 != nonce1) {
            print_error("nonce1 value: %u invalid\n", validate->nonce1);
            return ERROR_RETURN;
        }
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
        nonce2[i] = validate->nonce2;
    }
    return SUCCESS_RETURN;
}

int boot_components(nonce_t *nonce2) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        memcpy(command->params, &nonce2[i], sizeof(nonce_t)); // Send back original nonce sent back from comp
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    int i = 0;
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // customer, location, date
    uint8_t plaintext_attest[3][MAX_I2C_MESSAGE_LEN];
    uint8_t HASH_DIGEST[HASH_SIZE];
    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command first, we'll be expecting exactly 4 messages
    secure_send(addr, transmit_buffer, sizeof(command));
    for(; i < 4; i++)
    {
         bzero(receive_buffer, sizeof(receive_buffer)); // Clean our buffer to not mess with the hash check
         int len = secure_receive(addr, receive_buffer);
         if (len == ERROR_RETURN) {
            print_error("Could not attest component\n");
            return ERROR_RETURN;
         }
         // Hash comes last 
         if(i == 3)
         {
            memcpy(HASH_DIGEST, receive_buffer, sizeof(HASH_DIGEST));
            break;
         }
         wc_RsaPrivateDecrypt(receive_buffer, sizeof(receive_buffer),
                            plaintext_attest[i], MAX_I2C_MESSAGE_LEN, &AP_AT_PRIV );
                                               //sizeof(plaintext_attest[0]) 
    }

    uint8_t hash_test[HASH_SIZE];
    
    hash(plaintext_attest, sizeof(plaintext_attest), hash_test);

    if (memcmp(hash_test, HASH_DIGEST, HASH_SIZE) != 0)
    {
        print_error("Failure to verify the integrity of attestation data\n");
        return ERROR_RETURN;
    }

    bzero(receive_buffer, sizeof(receive_buffer));
    sprintf((char*)receive_buffer,"CUST>%s\nLOC>%s\nDATE>%s\n", plaintext_attest[0], plaintext_attest[1], plaintext_attest[2]);
    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    //"LOC>%s\nDATE>%s\nCUST>%s\n"
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot(void) {
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin(void) {
    char buf[PIN_BUFSIZE]; // Should be generated by deployment
    uint8_t hash_out[HASH_SIZE];
    char hash_to_string[HASH_SIZE*2];
    int i;

    recv_input("Enter pin: ", buf, sizeof(buf));

    if (hash(buf, sizeof(buf), hash_out) != 0) {
	print_error("Error: hash\n");
        return ERROR_RETURN;
    }
    
    for(i = 0; i < 32; i++)
    {
        sprintf(&hash_to_string[i*2], "%02x", hash_out[i]);
    }
    
    // Compares the hashes!
    if (!strcmp((char*)hash_to_string, PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }

    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token(void) {
    char buf[TOKEN_BUFSIZE];
    uint8_t hash_out[HASH_SIZE];
    char hash_to_string[HASH_SIZE*2];
    int i;
    
    recv_input("Enter token: ", buf, sizeof(buf));

    if (hash(buf, sizeof(buf), hash_out) != 0) {
	print_error("Error: hash\n");
        return ERROR_RETURN;
    }

    for(i = 0; i < 32; i++)
    {
        sprintf(&hash_to_string[i*2], "%02x", hash_out[i]);
    }


    if (!strcmp((char*)hash_to_string, TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }

    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot(void) {
    nonce_t nonce2[flash_status.component_cnt];
    if (validate_components(nonce2)) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components(nonce2)) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
#define REP_BUFSIZE 50
void attempt_replace(void) {
    char buf[REP_BUFSIZE];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, REP_BUFSIZE);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, REP_BUFSIZE);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
#define ATTEST_BUFSIZE 50
void attempt_attest(void) {
    char buf[ATTEST_BUFSIZE];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf, ATTEST_BUFSIZE);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/
#define CMD_BUFSIZE 100

int main(void) {
    // Initialize board
    if (init() != 0) {
        return 1;
    }

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    LED_On(LED1); // Checkpoint
    // Handle commands forever
    char buf[CMD_BUFSIZE];
    while (1) {
        recv_input("Enter Command: ", buf, CMD_BUFSIZE-1);
        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
