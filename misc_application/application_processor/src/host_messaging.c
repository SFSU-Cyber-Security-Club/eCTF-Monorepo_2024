/**
 * @file host_messaging.c
 * @author Frederich Stine
 * @brief eCTF Host Messaging Implementation 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "host_messaging.h"

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *msg, char *buf, int buf_len) {
    int index = 0;
    print_debug(msg);
    fflush(0);
    print_ack();
    fgets(buf, buf_len, stdin);
    // Terminate the string to prevent the input from being misunderstood
    index = strcspn(buf, "\r\n");
    if (index > buf_len || index < 0)
    {
       index = buf_len
    }
    buf[index] = 0;
    puts("");
}

// Prints a buffer of bytes as a hex string
void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
