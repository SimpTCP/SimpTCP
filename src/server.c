/*! \file server.c 
 * \brief A simple server in the internet domain using simpTCP
 *  The port number is passed as an argument 
 * \mainpage Projet Développement de SimpTCP
 * \section Vue  Diagramme des structures de données du projet SimpTCP
 * \image html StructureDonnees.jpg 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <simptcp_api.h>
#include <simptcp_entity.h>


/*!
 *  \def DEFAULT_LOCAL_UDP_PORT
 * \brief default udp port number used by simptcp protocol entity
 * Caution: At the server side, the local udp port number must be equal
 * to the port number associated with the listening simptcp socket
 */
#define DEFAULT_LOCAL_UDP_PORT 15556

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        return 1;
    }

    /* launch simptcp protocol entity */
    if(start_simptcp(DEFAULT_LOCAL_UDP_PORT))
    {
        fprintf(stderr, "Unable to launch simptcp_entity\n");
        return 1;
    }

    /* create a simptcp/IPv4 socket */
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SIMPTCP);
    if (sockfd < 0)
    {
        error("ERROR opening socket");
        return 1;
    }

    /* prepare the server's well-known socket address (IP+port number) */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    /* assign the server's well-known socket address (IP+port number) */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        error("ERROR on binding");
        return 1;
    }
 
    /* prepare the socket to accept incoming connection requests */
    listen(sockfd,5);

    /* wait for incoming connection requests from clients */
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0)
    {
        error("ERROR on accept");
        return 1;
    }

    /* read the message sent by the client connected to this socket*/
    bzero(buffer,256);
    n = read(newsockfd,buffer,255);
    if (n < 0)
    {
        error("ERROR reading from socket");
        return 1;
    }

    printf("Here is the message: %s\n",buffer);

    close(newsockfd);
    printf("CIAO");
    return 0; 
}
