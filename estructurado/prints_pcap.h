#ifndef _PRINTS_PCAP_H_
#define _PRINTS_PCAP_H_

//Funciones para procesar y acceder a las cabeceras
struct sockaddr_in print_icmp_packet(const u_char *, int);
struct sockaddr_in print_tcp_packet(const u_char *, int);
struct sockaddr_in print_udp_packet(const u_char *, int);
void print_ip_header(const u_char *, int);

//Funcion para imprimir el payload de un paquete
void PrintData(const u_char *, int);

#endif
