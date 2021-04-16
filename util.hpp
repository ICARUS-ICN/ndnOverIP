#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <vector>
#include <netinet/in.h>

namespace util
{
    //Funcion para procesar strings y separarlas de acuerdo al caracter especificado
    std::vector<std::string>
    split(const std::string &, char);

    //Funciones para procesar y acceder a las cabeceras del paquete IP capturado
    struct sockaddr_in print_icmp_packet(const unsigned char *, int);
    struct sockaddr_in print_tcp_packet(const unsigned char *, int);
    struct sockaddr_in print_udp_packet(const unsigned char *, int);
    struct sockaddr_in print_ip_header(const u_char *buffer, int size);

    //Funcion para imprimir el payload de un paquete por consola
    void PrintData(const unsigned char *, int);
}

#endif