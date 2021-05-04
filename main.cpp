#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

#include <sys/socket.h>

#include "Producer.hpp"
#include "cola_paquetes.hpp"
#include "gateway.hpp"

std::vector<Entrada_encaminamiento> tabla_encaminamiento;

pcap_t *interfaz_captura;

std::string thisNodo;

int raw_socket;
struct sockaddr_in *addrDest;

Cola_paquetes cola_paquetes_nodo;

int main(int argc, char *argv[])
{
    //Inicializacion de la tabla de encaminamiento
    tabla_encaminamiento = inicializacion_tabla();

    //Configuracion interfaz captura libpcap
    interfaz_captura = configuracion_captura_libpcap();

    //Se coge el nombre del nodo el cual se recibe por línea de comandos
    std::string nombreNodo(argv[1]);
    thisNodo = nombreNodo;

    //Se abre el socket para enviar paquetes al mundo IP
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0)
    {
        std::cerr << "<<    Error creating socket to send IP packet!! " << std::endl;
        exit(-1);
    }
    std::cerr << "Socket created successfully! " << std::endl;

    try
    {
        ndn::gateway::Producer producer;
        producer.run(); //crea un hijo
    }
    catch (const std::exception &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        close(raw_socket);
        return 1;
    }

    return 0;
}
