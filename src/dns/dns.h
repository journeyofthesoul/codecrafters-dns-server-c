#ifndef DNS_H
#define DNS_H

int getDomainsFromQuery(unsigned char* buffer, int numberOfDomains, unsigned char** listOfDomains, int* lengthsOfDomains);

#endif // DNS_H