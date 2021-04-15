#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>

#include "Producer.hpp"
#include "cola_paquetes.hpp"
#include "gateway.hpp"

std::vector<Entrada_encaminamiento> tabla_encaminamiento;

pcap_t *interfaz_captura;

std::string thisNodo;

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

    try
    {
        ndn::gateway::Producer producer;
        producer.run(); //crea un hijo
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
