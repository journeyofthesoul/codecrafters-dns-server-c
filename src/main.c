#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

unsigned char* createDnsHeader(const char* header_items);

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
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(2053),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(udpSocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}

   int bytesRead;
   char buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);
   
   while (1) {
       // Receive data
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }
   
       buffer[bytesRead] = '\0';
       printf("Received %d bytes: %s\n", bytesRead, buffer);
   
       // Create an empty response
    //    unsigned char* response = createDnsHeader("Base DNS Header");

		unsigned char response[33] = {
			0x04, 0xd2, // ID = 1234
			0x80, 0x00, // Flags = QR=1, rest 0
			0x00, 0x01, // QDCOUNT = 1
			0x00, 0x00, // ANCOUNT =0
			0x00, 0x00, // NSCOUNT = 0
			0x00, 0x00, // ARCOUNT = 0
			0x0c, 
			0x63, 0x6f, 
			0x64, 0x65, 
			0x63, 0x72, 
			0x61, 0x66, 
			0x74, 0x65, 
			0x72, 0x73, 
			0x02, 0x69, 
			0x6f,
			0x00,
			0x00, 0x01, // A
			0x00, 0x01  // IN
		};
   
       // Send response
       if (sendto(udpSocket, response, 33, 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == -1) {
           perror("Failed to send response");
       }
   }
   
   close(udpSocket);

    return 0;
}

unsigned char* createDnsHeader(const char* header_items) {

	static unsigned char response[12] = {
        0x04, 0xd2, // ID = 1234
        0x80, 0x00, // Flags = QR=1, rest 0
        0x00, 0x00, // QDCOUNT = 0
        0x00, 0x00, // ANCOUNT =0
        0X00, 0X00, // NSCOUNT = 0
        0X00, 0X00  // ARCOUNT = 0
    };

    if (header_items == NULL) {
        // Handle allocation failure
        return response;
    }

    return response;
}