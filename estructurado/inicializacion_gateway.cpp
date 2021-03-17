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
//#include <string>

/*#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

#include <chrono>
#include <ctime>*/

#include "inicializacion_gateway.h"
#include "prints_pcap.h"

//Funcion invocada para inicializar la tabla de encaminamiento del gateway
Entrada_encaminamiento *inicializacion_tabla()
{
        static Entrada_encaminamiento tabla_encaminamiento[20];

        //Se inicializa tabla de encaminamiento (por ahora solo ponemos una entrada conocida)
        Entrada_encaminamiento prueba;
        prueba.dir_ip = "1.2.3.5";
        prueba.prefijo_ndn = "/mired/nodoA";

        //Aqui es donde se inicializaria con el contenido del fichero correspondiente
        for (int i = 0; i < 1; i++)
        {
                tabla_encaminamiento[i] = prueba;
        }

        return tabla_encaminamiento;
}

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap()
{

        char *dev = NULL; // Interfaz que se va a usar
        pcap_if_t *interfaces;

        char *net;  //Direccion de la red (dotacion con puntos)
        char *mask; //Mascara de la red (dotacion con puntos)

        int ret; //codigo de retorno
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 netp;  //dir IP
        bpf_u_int32 maskp; //mascara de subred
        struct in_addr addr;
        struct bpf_program fp; //contenedor con el programa compilado del filtro aplicado

        /* Se buscan interfaces validas */
        //dev = pcap_lookupdev(errbuf); --> deprecated method
        if (pcap_findalldevs(&interfaces, errbuf) == -1)
        {
                printf("%s\n", errbuf);
                exit(1);
        }

        /* Se sabe de antemano que tendra dos interfaces: enp0s3 y enp0s8, en ese orden. 
        Se coge la segunda, que es la conectada al mundo "IP" puro */
        dev = (interfaces->next)->name;

        // Se comprueba si hubo un error
        if (dev == NULL)
        {
                printf("%s\n", errbuf);
                exit(1);
        }

        // Se muestra la interfaz escogida
        printf("DEV: %s\n", dev);

        // Se coge la direccion y mascara de la red
        ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

        //Se comprueba si hubo error
        if (ret == -1)
        {
                printf("%s\n", errbuf);
                exit(1);
        }

        // Se transforma la direccion y mascara de red a una formato legible
        addr.s_addr = netp;
        net = inet_ntoa(addr);
        if (net == NULL)
        {
                perror("inet_ntoa");
                exit(1);
        }
        printf("NET: %s\n", net);

        addr.s_addr = maskp;
        mask = inet_ntoa(addr);
        if (mask == NULL)
        {
                perror("inet_ntoa");
                exit(1);
        }
        printf("MASK: %s\n", mask);

        //Se comienza la captura en modo promiscuo
        pcap_t *descr;
        descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);

        if (descr == NULL)
        {
                printf("pcap_open_live(): %s\n", errbuf);
                exit(1);
        }

        /*Se compila el programa para el filtro de paquetes (solo se van a tomar paquetes IP provenientes del
        host 1.2.3.6, al cual sabemos que esta conectado el gateway)*/

        char filtro[30] = "ip and src host 1.2.3.6";
        //char filtro[30] = "ip and src net 1.2.3.4/30";
        if (pcap_compile(descr, &fp, filtro, 0, netp) == -1)
        {
                fprintf(stderr, "Error compilando el filtro\n");
                exit(1);
        }

        //Se aplica el filtro a la interfaz de captura
        if (pcap_setfilter(descr, &fp) == -1)
        {
                fprintf(stderr, "Error aplicando el filtro\n");
                exit(1);
        }

        return descr;
}
