#ifndef COLA_PAQUETES_HPP
#define COLA_PAQUETES_HPP

#include <boost/thread.hpp>

//Clase que modela un paquete IP esperando en la cola para ser enviado a través de la red NDN
class Paquete_cola
{
public:
    typedef std::vector<uint8_t> packet_t;

    Paquete_cola(const packet_t &&packet, int seqno) : packet(packet), seqno_paquete(seqno) {}

    const packet_t &getPacket() const
    {
        return packet;
    }
    int getSeqno() const
    {
        return seqno_paquete;
    }
    int getSize() const
    {
        return packet.size();
    }

private:
    packet_t packet;
    int seqno_paquete; //num de secuencia para identificarlo en la cola
};

//Clase que modela la cola de paquetes IP de un gateway, esperando a ser enviados a través de la red NDN
class Cola_paquetes
{
public:
    typedef Paquete_cola::packet_t packet_t;

    //Funcion para imprimir los datos que contiene un paquete
    void PrintData(const uint8_t *data, int Size);

    //Función para añadir un paquete a la cola del nodo: recibe los datos y el tamaño del paquete y lo guarda con el sqno correspondiente al estado actual del nodo
    int addPaquete(const uint8_t *p, int size);

    //Función para recuperar un paquete de la cola identificado por el num de seqno que recibe como parametro
    const packet_t &getPaquete(int seqno);

    //Función para recuperar el tamaño de un paquete de la cola identificado por el num de seqno que recibe como parametro
    int getPaqueteSize(int seqno)
    {
        return getPaquete(seqno).size();
    }

private:
    boost::mutex mtx_; //mutex para proteger tanto al seqno_nodo como a la cola en si
    std::vector<Paquete_cola> paquetes;
    int seqno_nodo = 1; //inicializado a 1: se ira incrementando en una unidad con cada paquete añadido a la cola
};

#endif