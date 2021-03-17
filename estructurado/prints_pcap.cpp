#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

#include "prints_pcap.h"

//Estructuras para procesar las cabeceras del paquete entrante
struct sockaddr_in source, dest;


struct sockaddr_in print_icmp_packet(const u_char *Buffer, int Size)
{
        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;

        struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

        int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

        printf("\n\n***********************ICMP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer, Size);

        printf("Data Payload: \n");

        //Se imprimen los datos del paquete
        PrintData(Buffer + header_size, (Size - header_size));

        printf("\n###########################################################");
        
        return dest;
}

struct sockaddr_in print_tcp_packet(const u_char *Buffer, int Size)
{
        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;

        struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

        int header_size = sizeof(struct ethhdr) + iphdrlen + (tcph->doff) * 4;

        printf("\n\n***********************TCP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer, Size);

        printf("\n");
        printf("TCP Header\n");
        printf("   |-Source Port      : %u\n", ntohs(tcph->source));
        printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
        printf("   |-Sequence Number    : %u\n", ntohl(tcph->seq));
        printf("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
        printf("   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);

        //Se imprimen los datos del paquete
        printf("Data Payload: \n");
        PrintData(Buffer + header_size, Size - header_size);

        printf("\n###########################################################");

        return dest;
}

struct sockaddr_in print_udp_packet(const u_char *Buffer, int Size)
{

        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;

        struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

        int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

        printf("\n\n***********************UDP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer, Size);

        printf("\nUDP Header\n");
        printf("   |-Source Port      : %d\n", ntohs(udph->source));
        printf("   |-Destination Port : %d\n", ntohs(udph->dest));
        printf("   |-UDP Length       : %d\n", ntohs(udph->len));
        printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));

        //Se imprimen los datos del paquete
        printf("Data Payload\n");
        PrintData(Buffer + header_size, Size - header_size);

        printf("\n###########################################################");

        return dest;
}

//Funcion que accede y procesa los datos de la cabecera IP
void print_ip_header(const u_char *Buffer, int Size)
{
        //unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
        //iphdrlen = iph->ihl * 4;

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        printf("IP Header\n");
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
        printf("   |-TTL      : %d\n", (unsigned int)iph->ttl);
        printf("   |-Protocol : %d\n", (unsigned int)iph->protocol);
        printf("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
        printf("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));

        return;
}

//Funcion para imprimir los datos que contiene el paquete
void PrintData(const u_char *data, int Size)
{
        int i, j;
        for (i = 0; i < Size; i++)
        {
                if (i != 0 && i % 16 == 0)
                {
                        printf("         ");
                        for (j = i - 16; j < i; j++)
                        {
                                if (data[j] >= 32 && data[j] <= 128)
                                        printf("%c", (unsigned char)data[j]);

                                else
                                        printf(".");
                        }
                        printf("\n");
                }

                if (i % 16 == 0)
                        printf("   ");
                printf(" %02X", (unsigned int)data[i]);

                if (i == Size - 1)
                {
                        for (j = 0; j < 15 - i % 16; j++)
                        {
                                printf("   ");
                        }

                        printf("         ");

                        for (j = i - i % 16; j <= i; j++)
                        {
                                if (data[j] >= 32 && data[j] <= 128)
                                {
                                        printf("%c", (unsigned char)data[j]);
                                }
                                else
                                {
                                        printf(".");
                                }
                        }

                        printf("\n");
                }
        }
}
