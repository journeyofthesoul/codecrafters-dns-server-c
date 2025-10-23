#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "utils/utils.h"
#include "dns/dns.h"

int main(int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    endpoint_t* endpoint = NULL;
    struct sockaddr_in upstreamDnsAddr;

    if ((argc == 3) && (strcmp(argv[1], "--resolver") == 0)) {
        endpoint = parseEndpoint(argv);
        if (endpoint == NULL) {
            printf("Failed to parse endpoint. Exiting.\n");
            return 1;
        }
        printf("Using upstream DNS server at %s:%d\n", endpoint->address, endpoint->port);

        // Forward DNS query to upstream DNS server
        memset(&upstreamDnsAddr, 0, sizeof(upstreamDnsAddr));
        upstreamDnsAddr.sin_family = AF_INET;
        upstreamDnsAddr.sin_port = htons(endpoint->port);
        inet_pton(AF_INET, endpoint->address, &upstreamDnsAddr.sin_addr);
    }

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
   
	// Declare a double pointer to char (or unsigned char for raw bytes)
	unsigned char **listOfDomains;
    unsigned char **listOfQuestions;
    unsigned char **listOfAnswers;
    while (1) {

        if (argc == 1) {
            printf("Running as Standalone Mode\n");
            memset(buffer, 0, sizeof(buffer));

            // Receive data
            bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
            if (bytesRead == -1) {
                perror("Error receiving data");
                break;
            }

            buffer[bytesRead] = '\0';
            printf("\n\nReceived %d bytes: %s\n", bytesRead, buffer);
            printHexArray(buffer, sizeof(buffer));

            numberOfDomains = (int)buffer[4] * 256 + (int)buffer[5];
            int lengthsOfDomains[numberOfDomains];
            listOfDomains = (unsigned char **)malloc(numberOfDomains * sizeof(unsigned char *));
            getDomainsFromQuery(buffer, numberOfDomains, listOfDomains, lengthsOfDomains);
    
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
            printHexArray(dnsHeaders, sizeDnsHeaders);

            unsigned char dnsQuestionSuffix[] = {
                0x00, 0x01, // A
                0x00, 0x01  // IN
            };
            
            unsigned char* partialDnsQuestion = NULL;
            unsigned char* dnsQuestion = NULL;
            int cumulativeLength = 0;
            for (int i = 0; i < numberOfDomains; i++) {
                partialDnsQuestion = concatenateArrays(listOfDomains[i], lengthsOfDomains[i], dnsQuestionSuffix, sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]));
                dnsQuestion = concatenateArrays(dnsQuestion, cumulativeLength, partialDnsQuestion, lengthsOfDomains[i] + sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]));
                cumulativeLength += lengthsOfDomains[i] + sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]);
                free(partialDnsQuestion);
                partialDnsQuestion = NULL;
            }

            int sizeDnsQuestion = cumulativeLength;
            printf("\nSizeof DNS Question %d bytes\n", sizeDnsQuestion);
            printf("Printing Question: \n");
            printHexArray(dnsQuestion, sizeDnsQuestion);

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
                partialDnsAnswer = NULL;
            }

            int sizeDnsAnswer = cumulativeLength;
            printf("\nSizeof DNS Answer %d bytes\n", sizeDnsAnswer);
            printf("Printing Answer: \n");
            printHexArray(dnsAnswer, sizeDnsAnswer);

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
            responseTmp = NULL;
            free(dnsQuestion);
            dnsQuestion = NULL;
            free(dnsAnswer);
            dnsAnswer = NULL;
            free(listOfDomains);
            listOfDomains = NULL;
    
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
            response = NULL;
        } else if ((argc == 3) && (strcmp(argv[1], "--resolver") == 0)) {
            printf("Running as Forwarder Mode\n");
            memset(buffer, 0, sizeof(buffer));
            // Receive data
            bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
            if (bytesRead == -1) {
                perror("Error receiving data");
                break;
            }

            buffer[bytesRead] = '\0';
            printf("\n\nReceived %d bytes: %s\n", bytesRead, buffer);
            printHexArray(buffer, sizeof(buffer));

            numberOfDomains = (int)buffer[4] * 256 + (int)buffer[5];
            int lengthsOfDomains[numberOfDomains];
            listOfDomains = (unsigned char **)malloc(numberOfDomains * sizeof(unsigned char *));
            getDomainsFromQuery(buffer, numberOfDomains, listOfDomains, lengthsOfDomains);

            listOfAnswers = (unsigned char **)malloc(numberOfDomains * sizeof(unsigned char *));
            listOfQuestions = (unsigned char **)malloc(numberOfDomains * sizeof(unsigned char *));
            int sizeOfAnswers[numberOfDomains];
            int sizeOfQuestions[numberOfDomains];

            unsigned char dnsHeaders[12];
            int sizeDnsHeaders = sizeof(dnsHeaders) / sizeof(dnsHeaders[0]);
            // Create header for upstream query
            dnsHeaders[0] = buffer[0];
            dnsHeaders[1] = buffer[1];
            dnsHeaders[2] = 0x00; // Upstream DNS Server does not support recursion
            dnsHeaders[3] = buffer[3];
            dnsHeaders[4] = 0x00;
            dnsHeaders[5] = 0x01;
            dnsHeaders[6] = buffer[6];
            dnsHeaders[7] = buffer[7];
            dnsHeaders[8] = buffer[8];
            dnsHeaders[9] = buffer[9];
            dnsHeaders[10] = buffer[10];
            dnsHeaders[11] = buffer[11];

            unsigned char dnsQuestionSuffix[] = {
                0x00, 0x01, // A
                0x00, 0x01  // IN
            };
            unsigned char upstreamBuffer[512];
            for (int i = 0; i < numberOfDomains; i++) {
                memset(upstreamBuffer, 0, sizeof(upstreamBuffer));
                
                listOfQuestions[i] = concatenateArrays(listOfDomains[i], lengthsOfDomains[i], dnsQuestionSuffix, sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]));
                sizeOfQuestions[i] = lengthsOfDomains[i] + sizeof(dnsQuestionSuffix) / sizeof(dnsQuestionSuffix[0]);

                printf("Printing DNS Headers to Upstream DNS Server\n");
                printHexArray(dnsHeaders, sizeDnsHeaders);
                // Send DNS Query to Upstream Server and push to local variable
                unsigned char* upstreamQuery = concatenateArrays(dnsHeaders, sizeDnsHeaders, listOfQuestions[i], sizeOfQuestions[i]);
                if (sendto(udpSocket, upstreamQuery, sizeDnsHeaders + sizeOfQuestions[i], 0,
                    (struct sockaddr*)&upstreamDnsAddr, sizeof(upstreamDnsAddr)) < 0) {
                    perror("sendto Upstream DNS server failed");
                    continue;
                }
                printf("Printing Query to Upstream DNS Server\n");
                printHexArray(upstreamQuery, sizeDnsHeaders + sizeOfQuestions[i]);

                // Receive DNS response from upstream server
                ssize_t r = recvfrom(udpSocket, upstreamBuffer, 512, 0, NULL, NULL);
                if (r < 0) {
                    perror("recvfrom Upstream DNS server failed");
                    continue;
                }
                upstreamBuffer[r] = '\0';
                printf("Printing Response from Upstream DNS Server\n");
                printHexArray(upstreamBuffer, r);

                // Parse DNS Answer from upstream server and store in local variable
                listOfAnswers[i] = (unsigned char*)malloc((r - (sizeDnsHeaders + sizeOfQuestions[i])) * sizeof(unsigned char));
                sizeOfAnswers[i] = r - (sizeDnsHeaders + sizeOfQuestions[i]);
                memcpy(listOfAnswers[i], &upstreamBuffer[sizeDnsHeaders + sizeOfQuestions[i]], sizeOfAnswers[i] * sizeof(unsigned char));
                printf("Printing Parsed Answer from the Upstream DNS Server\n");
                printHexArray(listOfAnswers[i], sizeOfAnswers[i]);

                free(upstreamQuery);
                upstreamQuery = NULL;
            }

            unsigned char* response = dnsHeaders;
            int cumulativeSize = sizeDnsHeaders;
            for (int i = 0; i < numberOfDomains; i++) {
                unsigned char* responseTmp = concatenateArrays(response, cumulativeSize, listOfQuestions[i], sizeOfQuestions[i]);
                if (response != dnsHeaders) {
                    free(response);
                }
                response = responseTmp;
                cumulativeSize += sizeOfQuestions[i];
            }
            // printf("Printing QuestionSet\n");
            // printHexArray(response, cumulativeSize);

            for (int i = 0; i < numberOfDomains; i++) {
                unsigned char* responseTmp = concatenateArrays(response, cumulativeSize, listOfAnswers[i], sizeOfAnswers[i]);
                free(response);
                response = responseTmp;
                cumulativeSize += sizeOfAnswers[i];
            }
            // printf("Printing AnswerSet\n");
            // printHexArray(response, cumulativeSize);

            // Set response headers
            response[2] = buffer[2] | 0x80;
            response[3] = (buffer[3] & 0xf0) + 0x04; // Flags = QR=1, rest 0
            response[4] = buffer[4];
            response[5] = buffer[5];
            response[6] = buffer[4];
            response[7] = buffer[5];
    
            // Send response
            int responseSize = cumulativeSize;
            printf("\nResponse Size is: %d\n", responseSize);
            printf("Printing Response Hex values of characters:\n");
            for (int i = 0; i < responseSize; i++) {
                printf("(%d)%02X ", i, (unsigned char)response[i]); // Print each character as a 2-digit uppercase hex value
            }
            // Send DNS response back to original client
            if (sendto(udpSocket, response, responseSize, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
                perror("Failed to send response");
            }

            free(response); // responseTmp should also be freed here as they are the same pointer
            response = NULL;

            for (int i = 0; i < numberOfDomains; i++) {
                free(listOfQuestions[i]);
                listOfQuestions[i] = NULL;
                free(listOfAnswers[i]);
                listOfAnswers[i] = NULL;
                free(listOfDomains[i]);
                listOfDomains[i] = NULL;
            }

            free(listOfQuestions);
            listOfQuestions = NULL;
            free(listOfAnswers);
            listOfAnswers = NULL;
            free(listOfDomains);
            listOfDomains = NULL;

            printf("\nForwarded DNS query and response.\n");
        }
	}
   
    if (endpoint != NULL)
        free(endpoint);

    close(udpSocket);

    return 0;
}