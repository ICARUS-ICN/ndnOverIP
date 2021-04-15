#ifndef COLA_PAQUETES_HPP
#define COLA_PAQUETES_HPP

#include <boost/thread.hpp>

//Clase que modela un paquete IP esperando en la cola para ser enviado a través de la red NDN
class Paquete_cola
{
private:
    const unsigned char *packet; //datos del paquete
    int size;                    //tamaño del paquete
    int seqno_paquete;           //num de secuencia para identificarlo en la cola

public:
    Paquete_cola(const unsigned char *p, int num, int sizeIp)
    {
        packet = p;
        seqno_paquete = num;
        size = sizeIp;
    }
    const unsigned char *getPacket() const
    {
        return packet;
    }
    int getSeqno() const
    {
        return seqno_paquete;
    }
    int getSize() const
    {
        return size;
    }
};

//Clase que modela la cola de paquetes IP de un gateway, esperando a ser enviados a través de la red NDN
class Cola_paquetes
{
public:
    //Funcion para imprimir los datos que contiene un paquete
    void PrintData(const unsigned char *data, int Size);

    //Función para añadir un paquete a la cola del nodo: recibe los datos y el tamaño del paquete y lo guarda con el sqno correspondiente al estado actual del nodo
    int addPaquete(const unsigned char *p, int size);

    //Función para recuperar un paquete de la cola identificado por el num de seqno que recibe como parametro
    const unsigned char *getPaquete(int seqno);

    //Función para recuperar el tamaño de un paquete de la cola identificado por el num de seqno que recibe como parametro
    int getPaqueteSize(int seqno);

    //Función para recuperar la cola completa de paquetes y hacer el procesado de recuperar uno concreto posteriormente
    std::vector<Paquete_cola> getCola();

private:
    boost::mutex mtx_; //mutex para proteger tanto al seqno_nodo como a la cola en si
    std::vector<Paquete_cola> paquetes;
    int seqno_nodo = 1; //inicializado a 1: se ira incrementando en una unidad con cada paquete añadido a la cola
};

#endif