#include <string>

#ifndef _PROCESADO_LIBPCAP_H_
#define _PROCESADO_LIBPCAP_H_

//Estructura que modela una entrada en la "tabla de encaminamiento" IP en la red NDN
typedef struct
{
        std::string dir_ip;
        std::string prefijo_ndn;

} Entrada_encaminamiento;

//Funcion invocada para inicializar la tabla de encaminamiento del gateway
Entrada_encaminamiento *inicializacion_tabla();

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap();

#endif