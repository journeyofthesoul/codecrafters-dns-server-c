#ifndef UTILS_H
#define UTILS_H

typedef struct endpoint {
    char address[256];
    int port;
} endpoint_t;

endpoint_t* parseEndpoint(char *argv[]);
void printHexArray(const unsigned char *data, int length);
unsigned char* concatenateArrays(const unsigned char* arr1, int size1, const unsigned char* arr2, int size2);

#endif // UTILS_H