/*! \file simptcp_lib.c
    \brief Defines the functions that gather the actions performed by a simptcp protocol entity in 
    reaction to events (system calls, simptcp packet arrivals, timeouts) given its state at a point in time  (closed, ..established,..). 
    
    \author{DGEI-INSAT 2010-2011}
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>              /* for errno macros */
#include <sys/socket.h>
#include <netinet/in.h>         /* for htons,.. */
#include <arpa/inet.h>
#include <unistd.h>             /* for usleep() */
#include <sys/time.h>           /* for gettimeofday,..*/

#include <libc_socket.h>
#include <simptcp_packet.h>
#include <simptcp_entity.h>
#include "simptcp_func_var.c"    /* for socket related functions' prototypes */
#include <term_colors.h>        /* for color macros */
#define __PREFIX__              "[" COLOR("SIMPTCP_LIB", BRIGHT_RED) " ] "
#include <term_io.h>

#ifndef __DEBUG__
#define __DEBUG__               1
#endif


/*! \fn char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state)
* \brief renvoie une chaine correspondant a l'etat dans lequel se trouve un socket simpTCP. Utilisee a des fins d'affichage
* \param state correspond typiquement au champ socket_state de la structure #simptcp_socket qui indirectement identifie l'etat dans lequel le socket se trouve et les fonctions qu'il peut appeler depuis cet etat
* \return chaine de carateres correspondant a l'etat dans lequel se trouve le socket simpTCP
*/
char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state)
{
    if (state == &  simptcp_socket_states.closed)
    {
            return "CLOSED";
    }
    else if (state == & simptcp_socket_states.listen)
    {
        return "LISTEN";
    }
    else if (state == & simptcp_socket_states.synsent)
    {
        return "SYNSENT";
    }
    else if (state == & simptcp_socket_states.synrcvd)
	{
        return "SYNRCVD";
    }
    else if (state == & simptcp_socket_states.established)
	{
        return "ESTABLISHED";
    }
    else if (state == & simptcp_socket_states.closewait)
	{
        return "CLOSEWAIT";
    }
    else if (state == & simptcp_socket_states.finwait1)
    {
        return "FINWAIT1";
    }
    else if (state == & simptcp_socket_states.finwait2)
	{
        return "FINWAIT2";
    }
    else if (state == & simptcp_socket_states.closing)
	{
        return "CLOSING";
    }
    else if (state == & simptcp_socket_states.lastack)
	{
        return "LASTACK";
    }
    else if (state == & simptcp_socket_states.timewait)
	{
        return "TIMEWAIT";
    }
    else
    {
        assert(0);
    }
}

/**
 * \brief called at socket creation 
 * \return the first sequence number to be used by the socket
 * \todo: randomize the choice of the sequence number to fit TCP behaviour..
 */
unsigned int get_initial_seq_num()
{
    CALLED(__func__);
    return 15;
}

/*!
* \brief Initialise les champs de la structure #simptcp_socket
* \param sock pointeur sur la structure simptcp_socket associee a un socket simpTCP 
* \param lport numero de port associe au socket simptcp local 
*/
void init_simptcp_socket(struct simptcp_socket *sock, unsigned int lport)
{
    CALLED(__func__);
    assert(sock != NULL);

    lock_simptcp_socket(sock);

    /* Initialization code */
    sock->socket_type = unknown;
    sock->new_conn_req=NULL;
    sock->pending_conn_req=0;
    
    /* set simpctp local socket address */
    memset(&(sock->local_simptcp), 0, sizeof (struct sockaddr));
    sock->local_simptcp.sin_family = AF_INET;
    sock->local_simptcp.sin_addr.s_addr = htonl(INADDR_ANY);
    sock->local_simptcp.sin_port = lport;
    memset(&(sock->remote_simptcp), 0, sizeof (struct sockaddr));

    sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);

    /* protocol entity sending side */
    sock->socket_state_sender = -1; 
    sock->next_seq_num = get_initial_seq_num();
    memset(sock->out_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);   
    sock->out_len = 0;
    sock->nbr_retransmit = 0;

    /* protocol entity receiving side */
    sock->socket_state_receiver = -1;
    sock->next_ack_num = 0;
    memset(sock->in_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);   
    sock->in_len = 0;
    
    /* MIB statistics initialisation  */
    sock->simptcp_send_count = 0; 
    sock->simptcp_receive_count = 0; 
    sock->simptcp_in_errors_count = 0; 
    sock->simptcp_retransmit_count = 0;

    /* Init timer value */
    sock->timer_duration = 1000; 
    pthread_mutex_init(&(sock->mutex_socket), NULL);
    unlock_simptcp_socket(sock);
}



/*! \fn int create_simptcp_socket()
* \brief cree un nouveau socket SimpTCP et l'initialise. 
* parcourt la table de  descripteur a la recheche d'une entree libre. S'il en trouve, cree
* une nouvelle instance de la structure simpTCP, la rattache a la table de descrpteurs et l'initialise. 
* \return descripteur du socket simpTCP cree ou une erreur en cas d'echec
*/
int create_simptcp_socket()
{
    CALLED(__func__);
    int fd;

    /* get a free simptcp socket descriptor */
    for (fd=0;fd< MAX_OPEN_SOCK;fd++)
    {
        if ((simptcp_entity.simptcp_socket_descriptors[fd]) == NULL)
        { 
            /* this is a free descriptor */
            /* Allocating memory for the new simptcp_socket */
            simptcp_entity.simptcp_socket_descriptors[fd] =  (struct simptcp_socket *) malloc(sizeof(struct simptcp_socket));
            if (!simptcp_entity.simptcp_socket_descriptors[fd])
            {
                return -ENOMEM;
            }

            /* initialize the simptcp socket control block with local port number set to 15000+fd */
            init_simptcp_socket(simptcp_entity.simptcp_socket_descriptors[fd],15000+fd);
            simptcp_entity.open_simptcp_sockets++;
      
            /* return the socket descriptor */
            return fd;
        }
    } /* for */

    /* The maximum number of open simptcp socket reached  */
    return -ENFILE; 
}

/*! \fn void print_simptcp_socket(struct simptcp_socket *sock)
* \brief affiche sur la sortie standard les variables d'etat associees a un socket simpTCP 
* Les valeurs des principaux champs de la structure simptcp_socket d'un socket est affichee a l'ecran
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
void print_simptcp_socket(struct simptcp_socket *sock)
{
    DPRINTF("----------------------------------------\n");
    DPRINTF("local simptcp address: %s:%hu \n",inet_ntoa(sock->local_simptcp.sin_addr),ntohs(sock->local_simptcp.sin_port));
    DPRINTF("remote simptcp address: %s:%hu \n",inet_ntoa(sock->remote_simptcp.sin_addr),ntohs(sock->remote_simptcp.sin_port));   
    DPRINTF("socket type      : %d\n", sock->socket_type);
    DPRINTF("socket state: %s\n",simptcp_socket_state_get_str(sock->socket_state) );
    if (sock->socket_type == listening_server)
    {
        DPRINTF("pending connections : %d\n", sock->pending_conn_req);
    }
    DPRINTF("sending side \n");
    DPRINTF("sender state       : %d\n", sock->socket_state_sender);
    DPRINTF("transmit  buffer occupation : %d\n", sock->out_len);
    DPRINTF("next sequence number : %u\n", sock->next_seq_num);
    DPRINTF("retransmit number : %u\n", sock->nbr_retransmit);
    DPRINTF("Receiving side \n");
    DPRINTF("receiver state       : %d\n", sock->socket_state_receiver);
    DPRINTF("Receive  buffer occupation : %d\n", sock->in_len);
    DPRINTF("next ack number : %u\n", sock->next_ack_num);
    DPRINTF("send count       : %lu\n", sock->simptcp_send_count);
    DPRINTF("receive count       : %lu\n", sock->simptcp_receive_count);
    DPRINTF("receive error count       : %lu\n", sock->simptcp_in_errors_count);
    DPRINTF("retransmit count       : %lu\n", sock->simptcp_retransmit_count);
    DPRINTF("----------------------------------------\n");
}


/*! \fn int lock_simptcp_socket(struct simptcp_socket *sock)
* \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
* Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
* l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
* Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
* Avant tout  acces en ecriture a ces variables, l'appel a cette fonction permet 
* 1- si le semaphore est disponible (unlocked) de placer le semaphore dans une etat indisponible 
* 2- si le semaphore est indisponible, d'attendre jusqu'a ce qu'il devienne disponible avant de le "locker"
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
int lock_simptcp_socket(struct simptcp_socket *sock)
{
    CALLED(__func__); 
    if (!sock)
    {
        return -1;
    }
    return pthread_mutex_lock(&(sock->mutex_socket));
}

/*! \fn int unlock_simptcp_socket(struct simptcp_socket *sock)
* \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
* Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
* l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
* Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
* Après un acces "protege" en ecriture a ces variables, l'appel a cette fonction permet de liberer le semaphore 
* \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
*/
int unlock_simptcp_socket(struct simptcp_socket *sock)
{
    CALLED(__func__);
    if (!sock)
    {
        return -1;
    }
    return pthread_mutex_unlock(&(sock->mutex_socket));
}

/*! \fn void start_timer(struct simptcp_socket * sock, int duration)
 * \brief lance le timer associe au socket en fixant l'instant ou la duree a mesurer "duration" sera ecoulee (champ "timeout" de #simptcp_socket)
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \param duration duree a mesurer en ms
*/
void start_timer(struct simptcp_socket * sock, int duration)
{
    CALLED(__func__);
    struct timeval t0;
    assert(sock!=NULL);
    gettimeofday(&t0,NULL);
    sock->timeout.tv_sec=t0.tv_sec + (duration/1000);
    sock->timeout.tv_usec=t0.tv_usec + (duration %1000)*1000;  
}

/*! \fn void stop_timer(struct simptcp_socket * sock)
 * \brief stoppe le timer en reinitialisant le champ "timeout" de #simptcp_socket
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
void stop_timer(struct simptcp_socket * sock)
{
    CALLED(__func__);
    assert(sock!=NULL);
    sock->timeout.tv_sec=0;
    sock->timeout.tv_usec=0; 
}

/*! \fn int has_active_timer(struct simptcp_socket * sock)
 * \brief Indique si le timer associe a un socket simpTCP est actif ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si timer actif, 0 sinon
 */
int has_active_timer(struct simptcp_socket * sock)
{
    return (sock->timeout.tv_sec!=0) || (sock->timeout.tv_usec!=0);
}

/*! \fn int is_timeout(struct simptcp_socket * sock)
 * \brief Indique si la duree mesuree par le timer associe a un socket simpTCP est actifs'est ecoulee ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si duree ecoulee, 0 sinon
 */
int is_timeout(struct simptcp_socket * sock)
{
    struct timeval t0;
    assert(sock!=NULL);
    /* make sure that the timer is launched */
    assert(has_active_timer(sock));
    gettimeofday(&t0,NULL);
    return ((sock->timeout.tv_sec < t0.tv_sec) ||  ((sock->timeout.tv_sec == t0.tv_sec) && (sock->timeout.tv_usec < t0.tv_usec)));
}

/*! \fn int simptcp_socket_send_out_buffer(struct simptcp_socket* sock)
 * \brief Envoie sock->out_buffer à sock->remote_udp en passant par la socket udp cd simptcp_entity
 * \param sock pointeur sur un socket SimTCP
 * \return 0 si toutes les données ont été envoyées, -1 sinon.
 */
int simptcp_socket_send_out_buffer(struct simptcp_socket* sock)
{
    CALLED(__func__);
    DPRINTF("Send packed (%d bytes) : \n", sock->out_len);
    simptcp_lprint_packet(sock->out_buffer);

    int ret = -1;
    ssize_t nsend = libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0, (struct sockaddr*) &(sock->remote_udp), sizeof(struct sockaddr));
    lock_simptcp_socket(sock);
    if(nsend != -1 && nsend == sock->out_len)
    {
        sock->simptcp_send_count++;
        ret = 0;
    }
    unlock_simptcp_socket(sock);
    return ret;
}

/*! \fn int simptcp_socket_resend_out_buffer(struct simptcp_socket* sock)
 * \brief Renvoie au remote_simptcp le packet present dans le out_buffer, incremente simptcp_retransmit_count et nbr_retransmit
 * \param sock pointeur sur un socket SimTCP
 * \return 0 si toutes les données ont été envoyées, -1 sinon.
 */
int simptcp_socket_resend_out_buffer(struct simptcp_socket *sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    sock->simptcp_retransmit_count++;
    sock->nbr_retransmit++;
    unlock_simptcp_socket(sock);
    return simptcp_socket_send_out_buffer(sock);
}

/*** socket state dependent functions ***/


/*********************************************************
 * closed_state functions *
 *********************************************************/

/*! \fn int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);

    int ret = -1;
    lock_simptcp_socket(sock);

    // le socket est forcement un client
    sock->socket_type = client;
    // on met à jour le remote simptcp
    memcpy(&(sock->remote_simptcp), addr, len);
    simptcp_create_packet_syn(sock);

    // il faut créer le remote_udp
    memset(&(sock->remote_udp), 0, sizeof(struct sockaddr_in));
    sock->remote_udp.sin_family = AF_INET;
    sock->remote_udp.sin_port = htons(15556);
    memcpy(&(sock->remote_udp.sin_addr), &(((struct sockaddr_in*) addr)->sin_addr), sizeof(struct in_addr));

    // on créé le syn et on l'envoie
    sock->next_ack_num = sock->next_seq_num + 1;
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->synsent);
    unlock_simptcp_socket(sock);
    simptcp_socket_send_out_buffer(sock);

    start_timer(sock, sock->timer_duration);

    // wait until syn ack received
    while(sock->nbr_retransmit <= 3 &&  sock->socket_state != &(simptcp_entity.simptcp_socket_states->established)){}
 
    if(sock->socket_state == &(simptcp_entity.simptcp_socket_states->established))
    {
        ret = 0;
    }
    else
    {
        errno = ETIMEDOUT;
    }

    return ret;
}

/*! \fn int closed_simptcp_socket_state_passive_open(struct simptcp_socket* sock, int n)
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{ 
    CALLED(__func__);

    lock_simptcp_socket(sock);
    sock->socket_type = listening_server;
    sock->pending_conn_req = 0;
    sock->max_conn_req_backlog = n;
    sock->new_conn_req = malloc(n*sizeof(struct simptcp_socket*));
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->listen);
    unlock_simptcp_socket(sock);

    return 0;
}

/*! \fn int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return ENOTCONN;
}


/*! \fn ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return ENOTCONN;
}


/*! \fn ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return ENOTCONN;
}

/**
 * called when application calls close
 */

/*! \fn  int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return ENOTCONN;
}

/*! \fn  int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return ENOTCONN;
}

/*! 
 * \fn void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
}


/*********************************************************
 * listen_state functions *
 *********************************************************/

/*! \fn int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;  
}

/**
 * called when application calls listen
 */
/*! \fn int listen_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return positif (fd) si succes, -1 si erreur/echec
 */
int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    int ret = -1;

    // on attend qu'un client soit en attente
    while(sock->pending_conn_req == 0){}
    lock_simptcp_socket(sock);
    struct simptcp_socket* c = sock->new_conn_req[sock->pending_conn_req-1];
    simptcp_create_packet_syn_ack(c);
    c->socket_state = &(simptcp_entity.simptcp_socket_states->synsent);
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->synrcvd);
    unlock_simptcp_socket(sock);
    simptcp_socket_send_out_buffer(c);

    start_timer(sock, sock->timer_duration);

    while(c->nbr_retransmit <= 3 && c->socket_state != &(simptcp_entity.simptcp_socket_states->established)) {}

    if(c->socket_state == &(simptcp_entity.simptcp_socket_states->established))
    {
        
        lock_simptcp_socket(sock);
        simptcp_entity.simptcp_socket_descriptors[simptcp_entity.open_simptcp_sockets] = c;
        ret = simptcp_entity.open_simptcp_sockets++;
        sock->new_conn_req[sock->pending_conn_req-1] = NULL;
        sock->pending_conn_req--;
        unlock_simptcp_socket(sock);
        memcpy(addr, &(c->remote_udp), sizeof(struct sockaddr));
        DPRINTF("%d\n",ret );
    }
    else
    {
        errno = ETIMEDOUT;
    }
    return ret;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);

    char flags = simptcp_get_flags(buf);
    struct simptcp_socket *c;

    // on a un syn (ouverture de connexion)
    if(sock->socket_type == listening_server && sock->pending_conn_req < sock->max_conn_req_backlog && (flags & SYN))
    {
        c = malloc(sizeof(struct simptcp_socket));
        memcpy(&(c->remote_udp), &(sock->remote_udp), sizeof(struct sockaddr_in));
        memcpy(&(c->remote_simptcp), &(sock->remote_simptcp), sizeof(struct sockaddr_in));
        memcpy(&(c->local_simptcp), &(sock->local_simptcp), sizeof(struct sockaddr_in));
        c->next_ack_num = simptcp_get_seq_num(buf)+1;
        c->next_seq_num = 40;
        c->socket_type = client;
        lock_simptcp_socket(sock);
        sock->new_conn_req[sock->pending_conn_req] = c;
        sock->pending_conn_req++;
        unlock_simptcp_socket(sock);
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
}


/*********************************************************
 * synsent_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock,struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int synsent_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    char flags = simptcp_get_flags(buf);
    u_int16_t seq_num = simptcp_get_seq_num(buf);
    u_int16_t ack_num = simptcp_get_ack_num(buf);

    if((flags & SYN) && (flags & ACK) && sock->next_seq_num+1 == ack_num)
    {
        lock_simptcp_socket(sock);
        stop_timer(sock);
        sock->next_ack_num = seq_num+1;
        sock->next_seq_num++;
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->established);
        simptcp_create_packet_ack(sock);
        unlock_simptcp_socket(sock);
        simptcp_socket_send_out_buffer(sock);
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);

    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    // resent out buffer until socked is not etablished
    if(sock->socket_type == client && sock->nbr_retransmit <= 3 && sock->socket_state != &(simptcp_entity.simptcp_socket_states->established))
    {
        simptcp_socket_resend_out_buffer(sock);
        start_timer(sock, sock->timer_duration);
    }
}


/*********************************************************
 * synrcvd_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int synrcvd_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre 
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    struct simptcp_socket* c;
    char flags = simptcp_get_flags(buf);
    int i;

    if(sock->socket_type == listening_server && (flags & ACK))
    {
        for(i=0; i<sock->pending_conn_req; i++)
        {
            c = sock->new_conn_req[i];
            if(c->socket_state == &(simptcp_entity.simptcp_socket_states->synsent) && 
                c->remote_simptcp.sin_addr.s_addr == sock->remote_simptcp.sin_addr.s_addr &&
                c->remote_simptcp.sin_port == sock->remote_simptcp.sin_port &&
                c->next_seq_num+1 == simptcp_get_ack_num(buf))
            {

                c->next_ack_num = simptcp_get_seq_num(buf)+1;
                c->timer_duration = sock->timer_duration;
                c->next_seq_num++;
                c->socket_state = &(simptcp_entity.simptcp_socket_states->established);
                lock_simptcp_socket(sock);
                stop_timer(sock);
                sock->socket_state = &(simptcp_entity.simptcp_socket_states->established);
                unlock_simptcp_socket(sock);
                DPRINTF("New client etablished!\n");
                break;
            }
        }
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);

    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    struct simptcp_socket *c = sock->new_conn_req[sock->pending_conn_req-1];
    // resent out buffer until socked is not etablished
    if(sock->socket_type == listening_server && c != NULL && c->socket_type == client && c->nbr_retransmit <= 3 && c->socket_state == &(simptcp_entity.simptcp_socket_states->synsent))
    {
        simptcp_socket_resend_out_buffer(c);
        start_timer(sock, sock->timer_duration);
    }
}


/*********************************************************
 * established_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int established_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    int ret = -1;

    lock_simptcp_socket(sock);
    simptcp_create_packet_data(sock, buf, n);
    sock->socket_state_sender = wait_ack;
    unlock_simptcp_socket(sock);
    simptcp_socket_send_out_buffer(sock);

    start_timer(sock, sock->timer_duration);

    while(sock->socket_state_sender == wait_ack && sock->nbr_retransmit <= 3){}

    if(sock->socket_state_sender != wait_ack)
    {
        ret = 0;
    } else {
        errno = ECONNABORTED;
    }

    return ret;
}    
/**
 * called when application calls recv
 */
/*! \fn ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    while(sock->in_len == 0){}
    memcpy(buf, sock->in_buffer, sock->in_len);
    simptcp_create_packet_ack(sock);
    simptcp_socket_send_out_buffer(sock);
    int tmp = sock->in_len;
    lock_simptcp_socket(sock);
    memset(sock->in_buffer, 0, sock->in_len);
    sock->in_len = 0;
    unlock_simptcp_socket(sock);
    return tmp;
}

/**
 * called when application calls close
 */
/*! \fn  int established_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);

    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    // how est toujours SHUT_RDWR (fermeture des deux connexions)
    CALLED(__func__);
    int ret =-1;

    lock_simptcp_socket(sock);
    simptcp_create_packet_fin(sock);
    sock->socket_state_receiver = wait_ack;
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->finwait1);
    unlock_simptcp_socket(sock);

    simptcp_socket_send_out_buffer(sock);
    start_timer(sock, sock->timer_duration);

    // wait until fin ack or fin received
    while(sock->nbr_retransmit <= 3 &&  sock->socket_state != &(simptcp_entity.simptcp_socket_states->closed)){}
 
    if(sock->socket_state == &(simptcp_entity.simptcp_socket_states->closed))
    {
        ret = 0;
    }
    else
    {
        errno = ETIMEDOUT;
    }

    return ret;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    char flags = simptcp_get_flags(buf);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    if(flags == 0)
    {
        lock_simptcp_socket(sock);
        unsigned int leng = simptcp_get_total_len(buf)-simptcp_get_head_len(buf);
        memcpy(sock->in_buffer,buf+simptcp_get_head_len(buf), leng);
        sock->in_len = leng;
        sock->next_ack_num = simptcp_get_seq_num(buf)+1;
        unlock_simptcp_socket(sock);
        
    }
    else if(flags & ACK && simptcp_get_ack_num(buf) == sock->next_seq_num+1)
    {
        lock_simptcp_socket(sock);
        sock->next_seq_num = simptcp_get_ack_num(buf);
        sock->socket_state_sender = wait_message;
        unlock_simptcp_socket(sock);
    }
    else if(flags & FIN)
    {
        lock_simptcp_socket(sock);
        sock->next_ack_num = simptcp_get_seq_num(buf)+1;
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->closewait);
        simptcp_create_packet_ack(sock);
        unlock_simptcp_socket(sock);
        simptcp_socket_send_out_buffer(sock);
        start_timer(sock, 0);
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    if(sock->socket_type == client && sock->nbr_retransmit <= 3 && sock->socket_state_sender == wait_ack)
    {
        simptcp_socket_resend_out_buffer(sock);
        start_timer(sock, sock->timer_duration);
    }

}


/*********************************************************
 * closewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock,  struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int closewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);

    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \simule l'arret de la connexion par l'application
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    DPRINTF("On vient de simuler la fin de l'application\n");
    simptcp_create_packet_fin(sock);
    sock->socket_state= &(simptcp_entity.simptcp_socket_states->lastack);
    unlock_simptcp_socket(sock);
    simptcp_socket_send_out_buffer(sock);
    start_timer(sock, sock->timer_duration);
}


/*********************************************************
 * finwait1_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int finwait1_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    char flags = simptcp_get_flags(buf);

    if(flags & ACK && simptcp_get_ack_num(buf) == sock->next_seq_num+1)
    {
        lock_simptcp_socket(sock);
        sock->next_seq_num = simptcp_get_ack_num(buf);
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->finwait2);
        unlock_simptcp_socket(sock);
    }
    else if(flags & FIN)
    {
        lock_simptcp_socket(sock);
        sock->next_ack_num = simptcp_get_seq_num(buf)+1;
        simptcp_create_packet_ack(sock);
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->closing);
        unlock_simptcp_socket(sock);
        simptcp_socket_send_out_buffer(sock);
    } else {
        DPRINTF("%s : un-expected packet.\n", __func__);
    }

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);

    if(sock->nbr_retransmit <= 3 && sock->socket_state == &(simptcp_entity.simptcp_socket_states->finwait1))
    {
        simptcp_socket_resend_out_buffer(sock);
        start_timer(sock, sock->timer_duration);
    }
}


/*********************************************************
 * finwait2_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "fainwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int finwait2_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    char flags = simptcp_get_flags(buf);

    if(flags & FIN)
    {
        lock_simptcp_socket(sock);
        sock->next_ack_num = simptcp_get_seq_num(buf)+1;
        simptcp_create_packet_ack(sock);
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->timewait);
        unlock_simptcp_socket(sock);
        simptcp_socket_send_out_buffer(sock);
        start_timer(sock, 0);
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
}


/*********************************************************
 * closing_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int closing_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);
    char flags = simptcp_get_flags(sock->out_buffer);

    if(flags & ACK && simptcp_get_ack_num(buf) == sock->next_seq_num+1)
    {
        lock_simptcp_socket(sock);
        sock->next_seq_num = simptcp_get_ack_num(buf);
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
        unlock_simptcp_socket(sock);
    }

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);
    char flags = simptcp_get_flags(sock->out_buffer);

    if(sock->socket_state_receiver == wait_ack && !(flags&FIN))
    {
        lock_simptcp_socket(sock);
        simptcp_create_packet_fin(sock);
        sock->nbr_retransmit = 1;
        unlock_simptcp_socket(sock);
    }

    if(sock->nbr_retransmit <= 3)
    {
        simptcp_socket_resend_out_buffer(sock);
        start_timer(sock, sock->timer_duration);
    }

}


/*********************************************************
 * lastack_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int lastack_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
    char flags = simptcp_get_flags(buf);

    if(flags & ACK && simptcp_get_ack_num(buf) == sock->next_seq_num+1)
    {
        lock_simptcp_socket(sock);
        stop_timer(sock);
        sock->next_seq_num = simptcp_get_ack_num(buf);
        sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
        unlock_simptcp_socket(sock);
    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    CALLED(__func__);
    lock_simptcp_socket(sock);
    stop_timer(sock);
    unlock_simptcp_socket(sock);
    
    if(sock->nbr_retransmit <=3 && sock->socket_state == &(simptcp_entity.simptcp_socket_states->lastack))
    {
        simptcp_socket_resend_out_buffer(sock);
        start_timer(sock, sock->timer_duration);
    }
}


/*********************************************************
 * timewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */


/*! \fn int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls listen
 */
/*! \fn int timewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf  
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls close
 */
/*! \fn  int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
    CALLED(__func__);
    return -1;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
    CALLED(__func__);
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
    lock_simptcp_socket(sock);
    stop_timer(sock);
    sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);
    unlock_simptcp_socket(sock);
    CALLED(__func__);
}

