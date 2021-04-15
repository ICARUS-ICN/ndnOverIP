#include "gateway.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <fstream>
#include <iostream>

// ************************************************** DEFINICION DE FUNCIONES **********************************************

//Funcion invocada para inicializar la tabla de encaminamiento del gateway a partir del fichero presente en el Escritorio con esta información
//Formato de cada linea del fichero que contiene la info de encaminamiento: <prefijo_ip> <nombreGateway>
std::vector<Entrada_encaminamiento> inicializacion_tabla()
{
    std::string linea;

    std::ifstream fichero("/home/mariel/Escritorio/tablaEncaminamiento.txt");
    if (fichero.fail())
    {
        std::cerr << "FILE does NOT exist!" << std::endl;
        exit(1);
    }

    std::vector<Entrada_encaminamiento> tabla;
    while (!fichero.eof())
    {
        std::getline(fichero, linea);
        if (!fichero.eof())
        {
            Entrada_encaminamiento entrada;
            std::vector<std::string> tokens = util::split(linea, ' ');
            entrada.prefijo_ip.s_addr = inet_addr(tokens.at(0).c_str());
            entrada.prefijo_ndn = tokens.at(1);
            tabla.push_back(entrada);
            std::cerr << "New entry added: " << tokens.at(0) << "--" << tokens.at(1) << std::endl;
        }
    }
    fichero.close();
    return tabla;
}

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap()
{

    char *dev = NULL; // Interfaz que se va a usar
    pcap_if_t *interfaces;
    pcap_if_t *device;
    char devs[100][100];

    char *net;  //Direccion de la red (notacion con puntos)
    char *mask; //Mascara de la red (notacion con puntos)

    int ret; //codigo de retorno
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;  //dir IP
    bpf_u_int32 maskp; //mascara de subred
    struct in_addr addr;
    struct bpf_program fp; //contenedor con el programa compilado del filtro aplicado

    /* Se buscan interfaces validas */
    if (pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    //Se muestran por consola los dispositivos disponibles para iniciar una captura
    int count = 1, n;
    int net_interface = 0;
    printf("Devices available: \n");
    for (device = interfaces; device != NULL; device = device->next)
    {
        net_interface = 0;
        pcap_addr_t *a;
        for (a = device->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                char *dir = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
                printf("%d. %s - %s\n", count, device->name, dir);
                net_interface = 1;
            }
        }
        if (net_interface == 0)
        {
            printf("%d. %s - %s\n", count, device->name, device->description);
        }

        if (device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }
        count++;
    }

    //Se pide que se introduzca en qué interfaz se desea capturar
    printf("Enter the number  of the device that you want to capture: ");
    while (scanf("%d", &n) != 1)
    {
        printf("Failed to read the number. Enter it again: \n");
    }
    dev = devs[n];

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
    std::string network(net);

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

    //char filtro[30] = "ip and src host 1.2.3.6";
    std::string filtro = "ip and src net ";
    filtro.append(network);  //ip and src net <net_dir>
    filtro.append(" mask "); //ip and src net <net_dir> mask
    filtro.append(mask);     //ip and src net <net_dir> mask <mask>
    if (pcap_compile(descr, &fp, filtro.c_str(), 0, netp) == -1)
    {
        std::cerr << "Error compiling the filter" << std::endl;
        exit(1);
    }

    //Se aplica el filtro a la interfaz de captura
    if (pcap_setfilter(descr, &fp) == -1)
    {
        std::cerr << "Error setting the filter" << std::endl;
        exit(1);
    }

    return descr;
}
