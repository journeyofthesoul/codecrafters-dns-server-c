#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

endpoint_t* parseEndpoint(char *argv[]) {
    char *colon_pos;
    char ip_str[16]; // Sufficient for IPv4 (e.g., "255.255.255.255" + null terminator)
    int upstreamDnsPort;

    printf("Upstream DNS Server details: %s\n", argv[2]);

    colon_pos = strchr(argv[2], ':');
    if (colon_pos == NULL) {
        printf("Error: Invalid format, no colon found.\n");
        return NULL;
    }

    // Extract IP address
    int ip_len = colon_pos - argv[2];
    if (ip_len >= sizeof(ip_str)) {
        printf("Error: IP address too long.\n");
        return NULL;
    }
    strncpy(ip_str, argv[2], ip_len);
    ip_str[ip_len] = '\0'; // Null-terminate the string

    // Extract and convert port
    upstreamDnsPort = atoi(colon_pos + 1); // +1 to start after the colon

    printf("IP Address: %s\n", ip_str);
    printf("Port: %d\n", upstreamDnsPort);

    endpoint_t* endpoint = (endpoint_t*)malloc(sizeof(endpoint_t));

    strncpy(endpoint->address, ip_str, sizeof(ip_str));
    endpoint->port = upstreamDnsPort;

    return endpoint;
}

// Function to print bytes in hex format
void printHexArray(const unsigned char *data, int length) {
    printf("uint8_t data[%d] = { ", length);
    for (int i = 0; i < length; i++) {
        printf("%02X", data[i]);
        if (i < length - 1) {
            printf(" ");
        }
    }
    printf(" };\n");
}

// Function to concatenate two unsigned char arrays
unsigned char* concatenateArrays(const unsigned char* arr1, int size1, const unsigned char* arr2, int size2) {
    // Calculate the total size of the new array
    int totalSize = size1 + size2;

    // Allocate memory for the new array
    unsigned char* newArray = (unsigned char*)malloc(totalSize * sizeof(unsigned char));

    // Check if memory allocation was successful
    if (newArray == NULL) {
        perror("Memory allocation failed");
        return NULL;
    }

    // Copy elements from the first array
    memcpy(newArray, arr1, size1 * sizeof(unsigned char));

    // Copy elements from the second array, starting after the first array's elements
    memcpy(newArray + size1, arr2, size2 * sizeof(unsigned char));

    return newArray;
}
