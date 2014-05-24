/*! \file simptcp_packet.c
*  \brief{Defines the simptcp header as well as the functions that handle simptcp packets}
* \author{DGEI-INSAT 2010-2011}
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>         /* for htons,.. */
#include <term_colors.h>        /* for colors */
#define __PREFIX__              "[" COLOR("SIMTCP_PKT", BRIGHT_GREEN) "  ] "
#include <term_io.h>            /* for printf() and perror() redefinition */

#include <simptcp_lib.h>
#include <simptcp_packet.h>     /* for simptcp packets*/


#ifndef __DEBUG__
#define __DEBUG__               1
#endif

/*
 * simptcp  generic header get/set functions
 */


/*! \fn void simptcp_create_packet(char *buffer, simptcp_generic_header *p)
 * \brief Cree un packet simptcp dans le buffer passe en parametre
 * en fonction de la structure header
 * \param buffer pointeur sur PDU simptcp
 * \param p pointeur sur structure du packet a creer
*/
void simptcp_create_packet(struct simptcp_socket *s, simptcp_generic_header *p)
{
	CALLED(__func__);
	s->nbr_retransmit = 0;
	char* buffer = s->out_buffer;
	simptcp_set_sport(buffer, p->sport);
	simptcp_set_dport(buffer, p->dport);
	simptcp_set_flags(buffer, p->flags);
	simptcp_set_seq_num(buffer, p->seq_num);
	simptcp_set_ack_num(buffer, p->ack_num);
	simptcp_set_head_len(buffer, p->header_len);
	simptcp_set_total_len(buffer, p->total_len);
	simptcp_set_win_size(buffer, p->window_size);
	simptcp_add_checksum(buffer, p->total_len);
}

/*! \fn void simptcp_create_packet_data(struct simptcp_socket *s, const void* data, size_t len)
 * \brief Cree un packet simptcp avec les données contenues dans *data.
 * \param s pointeur sur un simptcp_socket
 * \param data pointeur sur les données à envoyer
 * \param len taille des données à envoyer
*/
void simptcp_create_packet_data(struct simptcp_socket *s, const void* data, size_t len)
{
	CALLED(__func__);
	simptcp_generic_header h;
	h.sport = ntohs(s->local_simptcp.sin_port);
	h.dport = ntohs(s->remote_simptcp.sin_port);
	h.seq_num = s->next_seq_num;
	h.flags = 0;
	h.header_len = SIMPTCP_GHEADER_SIZE;
	h.window_size = SIMPTCP_MAX_SIZE;
	h.total_len = SIMPTCP_GHEADER_SIZE + len;
	memcpy(s->out_buffer + SIMPTCP_GHEADER_SIZE, data, len);
	simptcp_create_packet(s, &h);
	s->out_len = SIMPTCP_GHEADER_SIZE + len;
}

/*! \fn void simptcp_create_packet_syn(struct simptcp_socket *s)
 * \brief Cree un packet simptcp SYN dans le buffer du socket
 * \param s pointeur sur le socket
*/
void simptcp_create_packet_syn(struct simptcp_socket *s)
{
	CALLED(__func__);
	simptcp_generic_header h;
	h.sport = ntohs(s->local_simptcp.sin_port);
	h.dport = ntohs(s->remote_simptcp.sin_port);
	h.seq_num = s->next_seq_num;
	h.ack_num = 0;
	h.header_len = SIMPTCP_GHEADER_SIZE;
	h.flags = SYN;
	h.window_size = SIMPTCP_MAX_SIZE;
	h.total_len = SIMPTCP_GHEADER_SIZE;
	simptcp_create_packet(s, &h);
	s->out_len = SIMPTCP_GHEADER_SIZE;
}

/*! \fn void simptcp_create_packet_syn(struct simptcp_socket *d)
 * \brief Cree un packet simptcp SYN ACK dans le buffer du socket
 * \param s pointeur sur le socket
*/
void simptcp_create_packet_syn_ack(struct simptcp_socket *d)
{
	CALLED(__func__);
	simptcp_generic_header h;
	h.sport = ntohs(d->local_simptcp.sin_port);
	h.dport = ntohs(d->remote_simptcp.sin_port);
	h.seq_num = d->next_seq_num;
	h.ack_num = d->next_ack_num;
	h.header_len = SIMPTCP_GHEADER_SIZE;
	h.flags = SYN | ACK;
	h.window_size = SIMPTCP_MAX_SIZE;
	h.total_len = SIMPTCP_GHEADER_SIZE;
	simptcp_create_packet(d, &h);
	d->out_len = SIMPTCP_GHEADER_SIZE;
}

/*! \fn void simptcp_create_packet_syn(struct simptcp_socket *d)
 * \brief Cree un packet simptcp ACK dans le buffer du socket
 * \param s pointeur sur le socket
*/
void simptcp_create_packet_ack(struct simptcp_socket *d)
{
	CALLED(__func__);
	simptcp_generic_header h;
	h.sport = ntohs(d->local_simptcp.sin_port);
	h.dport = ntohs(d->remote_simptcp.sin_port);
	h.seq_num = d->next_seq_num;
	h.ack_num = d->next_ack_num;
	h.header_len = SIMPTCP_GHEADER_SIZE;
	h.flags = ACK;
	h.window_size = SIMPTCP_MAX_SIZE;
	h.total_len = SIMPTCP_GHEADER_SIZE;
	simptcp_create_packet(d, &h);
	d->out_len = SIMPTCP_GHEADER_SIZE;
}


/*! \fn void simptcp_set_sport(char * buffer, u_int16_t sport)
 * \brief initialise le champ sport (source port) du PDU SimpTCP a sport
 * \param buffer pointeur sur PDU simptcp 
 * \param sport numero de port source
*/
void simptcp_set_sport(char * buffer, u_int16_t sport)
{
	((simptcp_generic_header *)buffer)->sport = htons(sport);
}


/*! \fn u_int16_t simptcp_get_sport (const char *buffer)
* \brief renvoi la valeur du champ sport (source port) du PDU SimpTCP
* \param buffer pointeur sur PDU simptcp 
* \return numero de port source du PDU
*/
u_int16_t simptcp_get_sport(const char *buffer)
{
	return ntohs(((const simptcp_generic_header  *)buffer)->sport);
}


/*! \fn void simptcp_set_dport(char * buffer, u_int16_t dport)
 * \brief initialise le champ dport (destination port) du PDU SimpTCP a dport
 * \param buffer pointeur sur PDU simptcp 
 * \param dport numero de port destination
 */
void simptcp_set_dport(char *buffer, u_int16_t dport)
{
	((simptcp_generic_header *)buffer)->dport = htons(dport);
}


/*! \fn u_int16_t simptcp_get_dport (const char *buffer)
 * \brief renvoi la valeur du champ dport (destination port) du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return numero de port destination du PDU
 */
u_int16_t simptcp_get_dport(const char *buffer)
{
	return ntohs(((const simptcp_generic_header  *)buffer)->dport);
}


/*! \fn void simptcp_set_flags  (char *buffer, u_char flags)
 * \brief initialise le champ flags  du PDU SimpTCP a flags
 * \param buffer pointeur sur PDU simptcp 
 * \param flags englobe la valeur des 7 flags (#SYN, #ACK, ..)  
 */
void simptcp_set_flags(char *buffer, u_char flags)
{
	((simptcp_generic_header *) buffer)->flags = flags;
}


/*! \fn unsigned char simptcp_get_flags  (const char *buffer)
 * \brief renvoi la valeur du champ flags du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur des 7 flags (#SYN, #ACK, ..) 
 */
unsigned char simptcp_get_flags(const char *buffer)
{
	return ((const simptcp_generic_header *) buffer)->flags;
}


/*! \fn void simptcp_set_seq_num   (char *buffer, u_int16_t seq)
 * \brief initialise le champ seq_num  du PDU SimpTCP a seq
 * \param buffer pointeur sur PDU simptcp 
 * \param seq numero de sequence 
 */
void simptcp_set_seq_num(char *buffer, u_int16_t seq)
{
	((simptcp_generic_header *)buffer)->seq_num = htons(seq);
}

/*! \fn u_int16_t simptcp_get_seq_num (const char *buffer)
 * \brief renvoi la valeur du champ seq_num du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return numero de sequence transporte par le PDU
 */
u_int16_t simptcp_get_seq_num(const char *buffer)
{
	return ntohs(((const simptcp_generic_header  *)buffer)->seq_num);
}


/*! \fn void simptcp_set_ack_num   (char *buffer, u_int16_t ack)
 * \brief initialise le champ ack_num  du PDU SimpTCP a ack
 * \param buffer pointeur sur PDU simptcp 
 * \param ack numero d'acquittement   
 */
void simptcp_set_ack_num(char *buffer, u_int16_t ack)
{
	((simptcp_generic_header *)buffer)->ack_num = htons(ack);
}


/*! \fn u_int16_t  simptcp_get_ack_num  (const char *buffer)
 * \brief renvoi la valeur du champ flags du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur du champ numero d'acquittement du PDU
 */
u_int16_t simptcp_get_ack_num(const char *buffer)
{
	return ntohs(((const simptcp_generic_header  *)buffer)->ack_num);
}


/*! \fn void simptcp_set_head_len   (char *buffer, unsigned char hlen)
 * \brief initialise le champ header_len du PDU SimpTCP a hlen
 * \param buffer pointeur sur PDU simptcp 
 * \param hlen taille de l'en-tete
 */
void simptcp_set_head_len(char *buffer, unsigned char hlen)
{
	((simptcp_generic_header *) buffer)->header_len = hlen;
}


/*! \fn void simptcp_get_head_len   (const char *buffer)
 * \brief renvoi la valeur du champ header_len du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur du champ Header_len du PDU 
 */
unsigned char simptcp_get_head_len(const char *buffer)
{
	return ((const simptcp_generic_header *) buffer)->header_len;
}


/*! \fn void simptcp_set_total_len   (char *buffer, u_int16_t tlen)
 * \brief initialise le champ total_len du PDU SimpTCP a hlen
 * \param buffer pointeur sur PDU simptcp 
 * \param tlen taille totale du PDU, charge utile incluse
 */
void simptcp_set_total_len(char *buffer, u_int16_t tlen)
{ 
	((simptcp_generic_header *)buffer)->total_len = (tlen);
}


/*! \fn void simptcp_get_total_len   (const char *buffer)
 * \brief renvoi la valeur du champ total_len du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur du champ total_len du PDU 
 */
u_int16_t simptcp_get_total_len(const char *buffer)
{
	return (((const simptcp_generic_header  *)buffer)->total_len);
}


/*! \fn void simptcp_set_win_size   (char *buffer, u_int16_t size)
 * \brief initialise le champ window_size du PDU SimpTCP a size
 * \param buffer pointeur sur PDU simptcp 
 * \param size taille de la fenêtre de contrôle de flux  
 */
void simptcp_set_win_size(char *buffer, u_int16_t size)
{
	((simptcp_generic_header *)buffer)->window_size = (size);
}


/*! \fn u_int16_t simptcp_get_win_size  (const char *buffer)
 * \brief renvoi la valeur du champ window_size du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur du champ window_size du PDU
 */
u_int16_t simptcp_get_win_size(const char *buffer)
{
	return (((const simptcp_generic_header  *)buffer)->window_size);
}


/*! \fn void simptcp_get_checksum   (const char *buffer)
 * \brief renvoi la valeur du champ checksum du PDU SimpTCP
 * \param buffer pointeur sur PDU simptcp 
 * \return valeur du champ checksum du PDU  
 */
u_int16_t simptcp_get_checksum(const char *buffer)
{
	return (((const simptcp_generic_header  *)buffer)->checksum);
}


/*! \fn void simptcp_add_checksum (char *buffer, int len)
 *  \brief calculer le checksum sur le PDU et rajouter la valeur calculee \n 
 * au champ checksum du PDU Adds checksum to a simptcp_packet of legth len
 * \param buffer pointeur sur PDU simpTCP a envoyer
 * \param len taille totale du PDU simpTCP a envoyer
 */
void simptcp_add_checksum(char *buffer, int len)
{
	int i;
	u_int16_t checksum = 0;
	u_int16_t *buf = (u_int16_t *) buffer;
	simptcp_generic_header *header= (simptcp_generic_header *) buffer;

	/* if length is odd we pad with 0 */
	if (len % 2 != 0)
	{
		buffer[len] = 0;
		++len;
	}

	/* compute sender checksum */
	header->checksum = 0;
	for (i = 0; i < len / 2; i++)
	{
		checksum += buf[i];
	}
	/* add checksum */
	header->checksum = (checksum);
}



/*! \fn int simptcp_check_checksum(char *buffer, int len)
 *  \brief verifie la validite du champ checksum d'un PDU simpTCP recu
 * \param buffer pointeur sur PDU simpTCP a envoyer
 * \param len taille totale du PDU simpTCP a envoyer
 * \return 1 si checksum OK, 0 sinon 
 */
int simptcp_check_checksum(char *buffer, int len)
{
	CALLED(__func__);
	int i;
	u_int16_t checksum = 0;
	u_int16_t *buf = (u_int16_t *) buffer;
	int ret;
	const simptcp_generic_header *header = (const simptcp_generic_header *) buffer;

	// if length is odd we pad with 0
	if (len % 2 != 0)
	{
		buffer[len] = 0;
		++len;
	}

	/* compute receiver checksum */
	for (i = 0; i < len / 2; ++i)
	{
		if (i == 7) continue;     /* checksum is the 8th double byte word */ 
		checksum += buf[i];
	}
	/* check sender and receiver's checksum */
	ret = (checksum == (header->checksum));
	if(ret == 0)
	{
		DPRINTF("computed : %4x -- needed : %4x\n", checksum, header->checksum);
	}
   	return ret;
}


/*! \fn u_int16_t simptcp_extract_data (char * pdu, void * payload)
 *  \brief extrait la charge utile d'un PDU SimpTCP
 * \param pdu pointeur sur PDU simpTCP a envoyer
 * \param payload pointeur sur la charge utile
 * \return la taille en octets de la charge utile
 */
u_int16_t simptcp_extract_data (char * pdu, void * payload)
{
	CALLED(__func__);
	u_int16_t hlen = simptcp_get_head_len(pdu); /* data length */
	u_int16_t dlen = simptcp_get_total_len(pdu)-hlen; /* header length */

	if (dlen > 0) 
	{
	  memcpy(payload,(pdu+hlen),dlen);
	}
  	return dlen;
}

/*!
 * \fn void simptcp_lprint_packet (char * buf)
 * \brief Fonction pour afficher un paquet.
 *
 * Le paquet sera affiché sur la sortie standard dans la forme d'un datagramme.
 * Les Flags sont représentés par leur première lettre :\n
 * SYN -> S ; ACK -> A ; FIN -> F ; DT -> D ; RT -> R.\n
 * Le PDU est affiché de la maniere suivante :
 * <pre>
 * +----------------+-----------------+-------------------+
 * | Seqnum :    12 | Acknum :     0  | Flags : |S| | | | |
 * +----------------+-----------------+-------------------+
 * | Data :     Demande de connection | Checksum :  2036  |
 * +----------------------------------+-------------------+
 * </pre>
 * \param buf PDU SimpTCP a afficher
 */
void simptcp_lprint_packet (char * buf)
{
	CALLED(__func__);
	char sflags[128] = "";
	unsigned char hlen= simptcp_get_head_len(buf);
	unsigned char flags=simptcp_get_flags(buf);

	strcat(sflags, ((flags & SYN) == SYN) ? COLOR("S", GREEN) : COLOR("S", RED));
	strcat(sflags, "|");
	strcat(sflags, ((flags & ACK) == ACK) ? COLOR("A", GREEN) : COLOR("A", RED));
	strcat(sflags, "|");
	strcat(sflags, ((flags & RST) == RST) ? COLOR("R", GREEN) : COLOR("R", RED));

	DPRINTF("+----------------+-----------------+-------------------+\n");
	DPRINTF("| sport : %5hu  | dport : %5hu   | seqnum : %5hu    |\n", simptcp_get_sport(buf), simptcp_get_dport(buf), simptcp_get_seq_num(buf));
	DPRINTF("+----------------+-----------------+-------------------+\n");
	DPRINTF("| acknum : %5hu | hlen : %3hhu      | Flags : %10s     |\n", simptcp_get_ack_num(buf), hlen, sflags);
	DPRINTF("+----------------+-----------------+-------------------+\n");
	if (!flags)
	{
	  DPRINTF ("| DATA : %45s |\n",(buf+hlen));
	  DPRINTF ("+------------------------------------------------------+\n");
	}
}


/*!
* \fn void simptcp_print_packet (char * buf)
* \brief Fonction pour afficher de maniere synthetique, sur une ligne, un paquet.
* \param buf PDU SimpTCP a afficher
*/
void simptcp_print_packet (char * buf)
{
	char sflags[12] = "|";
	unsigned char hlen = simptcp_get_head_len(buf);
	unsigned int tlen = simptcp_get_total_len(buf);
	unsigned char flags = simptcp_get_flags(buf);

	strcat(sflags, ((flags & SYN) == SYN) ? COLOR("S", GREEN) : COLOR("S", RED));
	strcat(sflags, "|");
	strcat(sflags, ((flags & ACK) == ACK) ? COLOR("A", GREEN) : COLOR("A", RED));
	strcat(sflags, "|");
	strcat(sflags, ((flags & RST) == RST) ? COLOR("R", GREEN) : COLOR("R", RED));

	DPRINTF("Source port: %5hu, Destination port: %5hu, seqnum: %5hu\n acknum:%5hu, hlen: %3hhu, flags: %7s, tlen: %5hu\n ",simptcp_get_sport(buf),
	   simptcp_get_dport(buf),simptcp_get_seq_num(buf), 
	   simptcp_get_ack_num(buf),hlen,sflags,simptcp_get_total_len(buf));
	if (tlen != hlen)
	{ /* simptcp packet conveys data */
		DPRINTF("DATA: %35s \n",(buf+hlen));
	}
}
