#ifndef GATEWAY_HPP
#define GATEWAY_HPP

#include "cola_paquetes.hpp"

#include <netinet/in.h>
#include <pcap.h>
#include <string>
#include <vector>

//Estructura que modela una entrada en la "tabla de encaminamiento" IP en la red NDN
typedef struct
{
    //std::string dir_ip;
    struct in_addr prefijo_ip;
    std::string prefijo_ndn;

} Entrada_encaminamiento;

//Representa la "tabla de encaminamiento" IP en la red NDN del gateway
extern std::vector<Entrada_encaminamiento> tabla_encaminamiento;

//Interfaz configurada para la captura de libpcap
extern pcap_t *interfaz_captura;

//Nombre del nodo gateway recibido como parametro por línea de comandos
extern std::string thisNodo;

//Representa la cola de paquetes IP del nodo que estan esperando a ser enviados por la red NDN
extern Cola_paquetes cola_paquetes_nodo;

//Funcion invocada para inicializar la tabla de encaminamiento del gateway a partir del fichero con esta información
std::vector<Entrada_encaminamiento> inicializacion_tabla();

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap();

#endif