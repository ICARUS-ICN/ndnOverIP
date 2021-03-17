#define BOOST_BIND_NO_PLACEHOLDERS

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <string>

#include <boost/asio/io_service.hpp>
#include <boost/thread.hpp>
#include <boost/thread/scoped_thread.hpp>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

#include "prints_pcap.h"
#include "inicializacion_gateway.h"

//Representa la "tabla de encaminamiento" IP en la red NDN del gateway
Entrada_encaminamiento *tabla_encaminamiento;

//Interfaz configurada para la captura de libpcap
pcap_t *descr;

/********************************* PARTE DE MIGUEL ***********************************/

//Se ejecutara un hilo en bucle que reciba los paquetes a través de libpcap
//Cada vez que llegue uno, desde el hilo, se le pide a la función processEvents que llame a una función pasándole el paquete como parámetro

//processEvents es un envoltorio alrededor de la librería boost::asio (programacion asincrona de c++) --> Usar esta librería:
//      a) Declarar variable de método de tipo boost::asio::io_context --> Pasarle esta variable al constructor del Face --> Cambiar llamada a processEvents por variable_contexto.run()
//      b) Crear un hijo, al que le pasamos como parámetro un puntero a variable_contexto --> Desde el hilo ejecutamos variable_contexto.dispatch(callback...) cada vez que nos llega un paquete.

namespace
{

    //Comprueba si la direccion destino de un paquete IP recibido coincide con una entrada de su tabla
    //Devuelve el índice de la coincidencia o -1 si no hay
    int check_tabla_encaminamiento(char *dest_addr)
    {
        printf("Ip destino: %s\n", dest_addr);

        //Se pasa a recorrer la tabla de encaminamiento buscando coincidencias...
        //Por ahora parto de asumir que solo hay una entrada
        for (int i = 0; i < 1; i++)
        {
            if (tabla_encaminamiento[i].dir_ip.compare(dest_addr) == 0)
            {
                printf("La direccion IP de destino es alcanzable a traves de la red NDN!\n");
                return i;
            }
        }

        //Si se llega a este punto es que no hubo coincidencias en la tabla de encaminamiento
        printf("La direccion IP de destino NO es alcanzable a traves de la red NDN\n");

        return -1;
    }
    // Usada para el procesado del paquete IP entrante
    void pcap_callback(const u_char *packet, struct pcap_pkthdr *pkthdr)
    {
        std::cerr << "Preparado para procesar un paquete IP!" << std::endl;

        //Se apunta el puntero a la cabecera Ethernet al comienzo del paquete
        struct ether_header *eptr;
        eptr = (struct ether_header *)packet;

        printf("MAC origen: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
        printf("MAC destino: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

        //Comprobar que es un paquete IP
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        {
            printf("Es de tipo IP\n");
        }
        else
        {
            printf("NO es de tipo IP\n");
            return;
        }

        int size = pkthdr->len;

        //Se accede a la cabecera IP, ssaltandose la cabecera Ethernet
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

        //Tras el procesado de cabeceras se tendra la direccion de destino
        struct sockaddr_in dest;

        //Se comprueba el protocolo (los ping seran ICMP)
        switch (iph->protocol)
        {
        case 1:
            printf("Es ICMP\n");
            dest = print_icmp_packet(packet, size);
            break;
        case 6:
            printf("Es TCP\n");
            dest = print_tcp_packet(packet, size);
            break;
        case 17:
            printf("Es UDP\n");
            dest = print_udp_packet(packet, size);
            break;
        default:
            printf("Protocolo desconocido\n");
            return;
        }

        //Se pasa a aplicar la logica de la pasarela NDN
        printf("Comprobando IP destino....\n");
        char *dest_addr = inet_ntoa(dest.sin_addr);

        int entrada_tabla = check_tabla_encaminamiento(dest_addr);

        if (entrada_tabla >= 0)
        {
            std::string prefijo_envio = tabla_encaminamiento[entrada_tabla].prefijo_ndn;
            std::cout << ">> Prefijo NDN encontrado: " << prefijo_envio << std::endl;
        }

        return;
    }

    // Crear un hijo, al que le pasamos como parámetro un puntero a variable_contexto
    void pcap_reader(boost::asio::io_context *io_context)
    {
        //Se ejecutara un hilo en bucle que reciba los paquetes a través de libpcap
        while (true)
        {
            std::cerr << "Esperando a recibir un paquete del mundo IP...." << std::endl;
            //Actualmente el hilo, en vez de leer paquetes de libpcap, duerme 1 segundo y luego llama a un callback pasándole una cadena de texto.
            //Usar para esperar por un paquete con libpcap
            //boost::this_thread::sleep_for(boost::chrono::seconds{1});

            //Usar pcap_next para leer un paquete entrante: u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
            struct pcap_pkthdr pkthdr;
            const u_char *paquete = pcap_next(descr, &pkthdr);

            std::cerr << "Ha llegado un paquete del mundo IP...." << std::endl;

            //Cada vez que llegue uno, desde el hilo, se le pide a la función "processEvents" que llame a una función pasándole el paquete como parámetro
            // Desde el hilo ejecutamos variable_contexto.dispatch(callback...) cada vez que nos llega un paquete.
            io_context->dispatch(std::bind(pcap_callback, paquete, &pkthdr));
        }
    }
}

namespace ndn
{
    namespace gateway
    {

        class Producer
        {
        public:
            // Pasarle la variable de método de tipo boost::asio::io_context al constructor del Face
            Producer() : m_face(m_ioContext) {}

            void
            run()
            {
                // Iniciar un hilo representando los paquetes pcap entrantes. En nuestro caso, se usan numeros para representarlos
                // Crear un hijo, al que le pasamos como parámetro un puntero a variable_contexto
                boost::scoped_thread<> t{boost::thread(boost::bind(&pcap_reader, &m_ioContext))};

                //Respondera las Interest que lleguen con prefijo /mired/nodoB/ip/request
                m_face.setInterestFilter("/mired/nodoB/ip",
                                         bind(&Producer::onInterest, this, _1, _2),
                                         nullptr, // RegisterPrefixSuccessCallback is optional
                                         bind(&Producer::onRegisterFailed, this, _1, _2));

                //Se cambia la llamada a processEvents por variable_conexto.run()
                m_ioContext.run();
            }

        private:
            //Declarar variable de método de tipo boost::asio::io_context
            boost::asio::io_context m_ioContext;

            void
            onInterest(const InterestFilter &, const Interest &interest)
            {
                //Rol de Producer --> El gateway podrá recibir peticiones internas de la red NDN para direcciones IP que él conozca
                std::cout << ">> Interest arrived: " << interest << std::endl;

                static const std::string content("Hello, world!");

                // Create Data packet
                auto data = make_shared<Data>(interest.getName());
                data->setFreshnessPeriod(10_s);
                data->setContent(reinterpret_cast<const uint8_t *>(content.data()), content.size());

                // Sign Data packet with default identity
                m_keyChain.sign(*data);

                // Return Data packet to the requester
                std::cout << "<< Data sent: " << *data << std::endl;
                m_face.put(*data);
            }

            void
            onRegisterFailed(const Name &prefix, const std::string &reason)
            {
                std::cerr << "ERROR: Failed to register prefix '" << prefix
                          << "' with the local forwarder (" << reason << ")" << std::endl;
                m_face.shutdown();
            }

        private:
            Face m_face;
            KeyChain m_keyChain;
        };

        /*class Consumer
        {
        public:
            void
            run()
            {
                Name interestName("/mired/nodoA/ip/request/nodoB/seqno");
                interestName.appendVersion();

                Interest interest(interestName);
                interest.setCanBePrefix(false);
                interest.setMustBeFresh(true);
                interest.setInterestLifetime(6_s);

                std::cout << "Sending Interest " << interest << std::endl;
                m_face.expressInterest(interest,
                                       bind(&Consumer::onData, this, _1, _2),
                                       bind(&Consumer::onNack, this, _1, _2),
                                       bind(&Consumer::onTimeout, this, _1));

                // Bloqueo hasta recibir Data o timeout: para la primera Interest del procedimiento no se espera respuesta (timeout de 1ms)
                boost::chrono::milliseconds mili(1);
                m_face.processEvents(mili);
            }

        private:
            void
            onData(const Interest &, const Data &data) const
            {
                std::string time_received((char *)data.getContent().value(), data.getContent().value_size());
                std::cout << "Length of the Data Received: " << (std::to_string(data.getContent().value_size())) << std::endl;
                std::cout << "Received Time: " << time_received << std::endl;
            }

            void
            onNack(const Interest &, const lp::Nack &nack) const
            {
                std::cout << "Received Nack with reason " << nack.getReason() << std::endl;
            }

            void
            onTimeout(const Interest &interest) const
            {
                std::cout << "Timeout for " << interest << std::endl;
            }

        private:
            Face m_face;
        };*/

    } // namespace gateway
} // namespace ndn

int main(int argc, char **argv)
{
    //Inicializacion de la tabla de encaminamiento
    tabla_encaminamiento = inicializacion_tabla();

    //Configuracion interfaz captura libpcap
    descr = configuracion_captura_libpcap();

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
