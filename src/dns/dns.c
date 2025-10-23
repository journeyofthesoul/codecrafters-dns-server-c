
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dns.h"
#include "../utils/utils.h"

int getDomainsFromQuery(unsigned char* buffer, int numberOfDomains, unsigned char** listOfDomains, int* lengthsOfDomains) {
    int domainIndex = 12;
	int originalIndex = 0;
    for (int i = 0; i < numberOfDomains; i++) {
        printf("\nPrinting %dth Domain: \n", i);
        for (int size=0, cumulativeSize=0, j=0; buffer[domainIndex] != '\0'; domainIndex++) {
            // printf("(%d)", domainIndex);
            if((size == 0) && ((unsigned char)(buffer[domainIndex]) >> 6 == 0x03)) {
                printf("\nMessage Compression Detected in DNS Query\n");
                originalIndex = domainIndex + 2;
                domainIndex = ((unsigned char)buffer[domainIndex] & 0x3F) * 256 + (unsigned char)buffer[domainIndex + 1];
            }
            printf("%02X ", (unsigned char)buffer[domainIndex]);
            if ((size == 0) && (cumulativeSize == 0)) {
                size = (int)buffer[domainIndex];
                cumulativeSize += size;
                listOfDomains[i] = (unsigned char *)malloc((500) * sizeof(unsigned char));
                listOfDomains[i][j] = (unsigned char)buffer[domainIndex];
                j++;
            } else if (size == 0) {
                size = (int)buffer[domainIndex];
                cumulativeSize += size;
                // listOfDomains[i] = (unsigned char *)realloc(listOfDomains[i], (cumulativeSize + 1) * sizeof(unsigned char));
                listOfDomains[i][j] = (unsigned char)buffer[domainIndex];
                j++;
            } else {
                listOfDomains[i][j] = (unsigned char)buffer[domainIndex];
                j++;
                size--;
            }

            if (buffer[domainIndex + 1] == '\0') {
                // unsigned char *tempArray = (unsigned char *)realloc(listOfDomains[i], (j + 1) * sizeof(unsigned char));
                // if (tempArray == NULL) {
                // 	perror("Failed to reallocate memory");
                // 	free(listOfDomains[i]); // Free the original memory block if reallocation fails
                // 	return 1;
                // }
                // listOfDomains[i] = tempArray; 
                lengthsOfDomains[i] = j + 1;
                listOfDomains[i][j] = '\0';
                printf("\nRecap %dth Domain: \n", i);
                printHexArray(listOfDomains[i], j + 1);
            }
        }
        if (domainIndex < originalIndex) {
            domainIndex = originalIndex;
        } else {
            domainIndex += 5; // Skip the null byte and QTYPE (2 bytes) and QCLASS (2 bytes)
        }
    }

    return domainIndex;
}