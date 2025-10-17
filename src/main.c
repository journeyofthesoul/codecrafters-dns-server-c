#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

unsigned char* createDnsHeader(const char* header_items);
void print_hex_array(const unsigned char *data, int length);
unsigned char* concatenateArrays(const unsigned char* arr1, int size1, const unsigned char* arr2, int size2);

int main() {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    printf("Logs from your program will appear here!\n");

    // Uncomment this block to pass the first stage
    int udpSocket, client_addr_len;
    struct sockaddr_in clientAddress;
	
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
	    printf("Socket creation failed: %s...\n", strerror(errno));
	    return 1;
    }
	
    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
	    printf("SO_REUSEPORT failed: %s \n", strerror(errno));
	    return 1;
    }
	
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET ,
        .sin_port = htons(2053),
        .sin_addr = { htonl(INADDR_ANY) },
    };
	
    if (bind(udpSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    int bytesRead, numberOfDomains;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);
   
    int domainIndex = 12;
	int originalIndex = 0;
	// Declare a double pointer to char (or unsigned char for raw bytes)
	unsigned char **listOfDomains;
    while (1) {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

		domainIndex = 12; // Reset domainIndex for each new query
		originalIndex = 0; // Reset originalIndex for each new query
		buffer[bytesRead] = '\0';
        printf("\n\nReceived %d bytes: %s\n", bytesRead, buffer);
	    print_hex_array(buffer, sizeof(buffer));

		numberOfDomains = (int)buffer[4] * 256 + (int)buffer[5];
		listOfDomains = (unsigned char **)malloc(numberOfDomains * sizeof(unsigned char *));
		int lengthsOfDomains[numberOfDomains];
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
					print_hex_array(listOfDomains[i], j + 1);
				}
			}
			if (domainIndex < originalIndex) {
				domainIndex = originalIndex;
			} else {
				domainIndex += 5; // Skip the null byte and QTYPE (2 bytes) and QCLASS (2 bytes)
			}
		}
   
        // Create an empty response
        // unsigned char* response = createDnsHeader("Base DNS Header");
	    unsigned char dnsHeaders[] = {
			buffer[0], buffer[1], // ID = 1234
			buffer[2] | 0x80, (buffer[3] & 0xf0) + 0x04, // Flags = QR=1, rest 0
			buffer[4], buffer[5], // QDCOUNT = 1
			buffer[4], buffer[5], // ANCOUNT = 1
			0x00, 0x00, // NSCOUNT = 0
			0x00, 0x00 // ARCOUNT = 0
		};
        int sizeDnsHeaders = sizeof(dnsHeaders) / sizeof(dnsHeaders[0]);
		printf("\nSizeof DNS Headers %d bytes\n", sizeDnsHeaders);
		printf("Printing DNS Headers: \n");
		print_hex_array(dnsHeaders, sizeDnsHeaders);

	    unsigned char dnsQuestionSuffix[] = {
			0x00, 0x01, // A
			0x00, 0x01  // IN
		};
;
		unsigned char* partialDnsQuestion = NULL;
		unsigned char* dnsQuestion = NULL;
		int cumulativeLength = 0;
		for (int i = 0; i < numberOfDomains; i++) {
			partialDnsQuestion = concatenateArrays(listOfDomains[i], lengthsOfDomains[i], dnsQuestionSuffix, sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]));
			dnsQuestion = concatenateArrays(dnsQuestion, cumulativeLength, partialDnsQuestion, lengthsOfDomains[i] + sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]));
			cumulativeLength += lengthsOfDomains[i] + sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]);
			free(partialDnsQuestion);
		}

        int sizeDnsQuestion = cumulativeLength;
		printf("\nSizeof DNS Question %d bytes\n", sizeDnsQuestion);
		printf("Printing Question: \n");
		print_hex_array(dnsQuestion, sizeDnsQuestion);

		unsigned char dnsAnswerSuffix[] = {
			0x00, 0x01, // A
			0x00, 0x01,  // IN
			0x00, 0x00,
			0x0b, 0xb8, // TTL = 3000
			0x00, 0x04, // RDLENGTH = 4
			0x08, 0x08,
			0x08, 0x08
		};

		unsigned char* partialDnsAnswer = NULL;
		unsigned char* dnsAnswer = NULL;
		cumulativeLength = 0;
		for (int i = 0; i < numberOfDomains; i++) {
			partialDnsAnswer = concatenateArrays(listOfDomains[i], lengthsOfDomains[i], dnsAnswerSuffix, sizeof(dnsAnswerSuffix) / sizeof(dnsAnswerSuffix[0]));
			dnsAnswer = concatenateArrays(dnsAnswer, cumulativeLength, partialDnsAnswer, lengthsOfDomains[i] + sizeof(dnsAnswerSuffix) / sizeof(dnsAnswerSuffix[0]));
			cumulativeLength += lengthsOfDomains[i] + sizeof(dnsAnswerSuffix) / sizeof(dnsAnswerSuffix[0]);
			free(partialDnsAnswer);
		}

        int sizeDnsAnswer = cumulativeLength;
		printf("\nSizeof DNS Answer %d bytes\n", sizeDnsAnswer);
		printf("Printing Answer: \n");
		print_hex_array(dnsAnswer, sizeDnsAnswer);

		// Free each individual row (sub-array)
		for (int i = 0; i < numberOfDomains; i++) {
			free(listOfDomains[i]);
			listOfDomains[i] = NULL; // Set pointer to NULL after freeing (good practice)
		}

		// Free the array of pointers itself
		free(listOfDomains);
		listOfDomains = NULL; // Set the main pointer to NULL

		unsigned char* responseTmp = concatenateArrays(dnsHeaders, sizeDnsHeaders, dnsQuestion, sizeDnsQuestion);

		unsigned char* response = concatenateArrays(responseTmp, sizeDnsHeaders + sizeDnsQuestion, dnsAnswer, sizeDnsAnswer);
		free(responseTmp);
		free(dnsQuestion);
		free(dnsAnswer);
		free(listOfDomains);

		// unsigned char response[64] = {
		// 	buffer[0], buffer[1], // ID = 1234
		// 	buffer[2] | 0x80, (buffer[3] & 0xf0) + 0x04, // Flags = QR=1, rest 0
		// 	0x00, 0x01, // QDCOUNT = 1
		// 	0x00, 0x01, // ANCOUNT =1
		// 	0x00, 0x00, // NSCOUNT = 0
		// 	0x00, 0x00, // ARCOUNT = 0
		// 	0x0c, 
		// 	0x63, 0x6f, 
		// 	0x64, 0x65, 
		// 	0x63, 0x72, 
		// 	0x61, 0x66, 
		// 	0x74, 0x65, 
		// 	0x72, 0x73, 
		// 	0x02, 0x69, 
		// 	0x6f,
		// 	0x00,
		// 	0x00, 0x01, // A
		// 	0x00, 0x01,  // IN
		// 	0x0c, 
		// 	0x63, 0x6f, 
		// 	0x64, 0x65, 
		// 	0x63, 0x72, 
		// 	0x61, 0x66, 
		// 	0x74, 0x65, 
		// 	0x72, 0x73, 
		// 	0x02, 0x69, 
		// 	0x6f,
		// 	0x00,
		// 	0x00, 0x01, // A
		// 	0x00, 0x01,  // IN
		// 	0x00, 0x00,
		// 	0x0b, 0xb8, // TTL = 3000
		// 	0x00, 0x04, // RDLENGTH = 4
		// 	0x08, 0x08,
		// 	0x08, 0x08
		// };
   
       // Send response
	   int responseSize = sizeDnsHeaders + sizeDnsQuestion + sizeDnsAnswer;
		printf("\nResponse Size is: %d\n", responseSize);
		printf("Printing Response Hex values of characters:\n");
		for (int i = 0; i < responseSize; i++) {
			printf("%02X ", (unsigned char)response[i]); // Print each character as a 2-digit uppercase hex value
		}
       if (sendto(udpSocket, response, responseSize, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
           perror("Failed to send response");
       }
	   free(response);
	}
   
    close(udpSocket);

    return 0;
}


// Function to print bytes in hex format
void print_hex_array(const unsigned char *data, int length) {
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


// Backup

// unsigned char response[64] = {
// 			buffer[0], buffer[1], // ID = 1234
// 			buffer[2] | 0x80, (buffer[3] & 0xf0) + 0x04, // Flags = QR=1, rest 0
// 			0x00, 0x01, // QDCOUNT = 1
// 			0x00, 0x01, // ANCOUNT =1
// 			0x00, 0x00, // NSCOUNT = 0
// 			0x00, 0x00, // ARCOUNT = 0
// 			0x0c, 
// 			0x63, 0x6f, 
// 			0x64, 0x65, 
// 			0x63, 0x72, 
// 			0x61, 0x66, 
// 			0x74, 0x65, 
// 			0x72, 0x73, 
// 			0x02, 0x69, 
// 			0x6f,
// 			0x00,
// 			0x00, 0x01, // A
// 			0x00, 0x01,  // IN
// 			0x0c, 
// 			0x63, 0x6f, 
// 			0x64, 0x65, 
// 			0x63, 0x72, 
// 			0x61, 0x66, 
// 			0x74, 0x65, 
// 			0x72, 0x73, 
// 			0x02, 0x69, 
// 			0x6f,
// 			0x00,
// 			0x00, 0x01, // A
// 			0x00, 0x01,  // IN
// 			0x00, 0x00,
// 			0x0b, 0xb8, // TTL = 3000
// 			0x00, 0x04, // RDLENGTH = 4
// 			0x08, 0x08,
// 			0x08, 0x08
// 		};
   
//        // Send response
// 	   int arraySize = sizeof(response) / sizeof(response[0]);

// 		printf("Hexadecimal values of characters:\n");
// 		for (int i = 0; i < arraySize; i++) {
// 			printf("%02X ", (unsigned char)response[i]); // Print each character as a 2-digit uppercase hex value
// 		}
//        if (sendto(udpSocket, response, 64, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
//            perror("Failed to send response");
//        }