#include "cola_paquetes.hpp"

#include <cstdio>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/ip.h>

void Cola_paquetes::PrintData(const unsigned char *data, int Size) const
{
    int i, j;
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    printf("%c", (unsigned char)data[j]);

                else
                    printf(".");
            }
            printf("\n");
        }

        if (i % 16 == 0)
            printf("   ");
        printf(" %02X", (unsigned int)data[i]);

        if (i == Size - 1)
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                printf("   ");
            }

            printf("         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    printf("%c", (unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }
            }

            printf("\n");
        }
    }
}

//Función para añadir un paquete a la cola del nodo: recibe los datos y el tamaño del paquete y lo guarda con el sqno correspondiente al estado actual del nodo
int Cola_paquetes::addPaquete(packet_t &&packet_data)
{
    const auto size = packet_data.size();

    boost::lock_guard<boost::mutex> mi_lock(mtx_); // operacion protegida por mutex

    struct iphdr *iph = (struct iphdr *)packet_data.data();
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packet_data.data() + iphdrlen);
    int header_size = iphdrlen + (sizeof(icmph)); // asumiendo que serán paquete ICMP

    //Imprimir por consola para comprobaciones
    std::cerr << "<< Content of PAYLOAD saved: " << std::endl;
    PrintData(packet_data.data() + header_size, (size - header_size));
    std::cerr << "<< Content of FULL packet saved: " << std::endl;
    PrintData(packet_data.data(), size);
    std::cerr << "<< Size of FULL packet saved: " << size << std::endl;

    packet_data.erase(packet_data.begin(), packet_data.begin() + header_size);
    Paquete_cola packet(std::move(packet_data), seqno_nodo);
    paquetes.push_back(packet);
    seqno_nodo += 1;
    return seqno_nodo; //devuelve el seqno_nodo+1 (el paquete se guardo en la cola con seqno --> Necesario para poder usarse en el Interest enviado)
}

//Función para recuperar un paquete de la cola identificado por el num de seqno que recibe como parametro
const Paquete_cola::packet_t &Cola_paquetes::getPaquete(int seqno) const
{
    boost::lock_guard<boost::mutex> mi_lock(mtx_); // operacion protegida por mutex

    for (const auto p : paquetes)
    {
        if (p.getSeqno() == seqno)
        {
            return p.getPacket();
        }
    }

    // If not found, return an empty packet. Should this be an exception?
    return Paquete_cola::packet_t();
}
