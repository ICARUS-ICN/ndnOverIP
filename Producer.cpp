#include "Producer.hpp"
#include "util.hpp"

#include <iostream>
#include <tuple>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>

// This namespace holds functions that are only used by this module
namespace
{
    using namespace util;

    //Comprueba si la direccion destino de un paquete IP recibido coincide con una entrada de su tabla
    //Devuelve el índice de la coincidencia o -1 si no hay ninguna
    const Entrada_encaminamiento *check_tabla_encaminamiento(struct in_addr dest_addr)
    {
        //Se pasa a recorrer la tabla de encaminamiento buscando coincidencias...
        std::cerr << "Checking destination IP in the table: " << inet_ntoa(dest_addr) << std::endl;
        for (const auto &entry : tabla_encaminamiento)
        {
            if (entry.prefijo_ip.s_addr == dest_addr.s_addr)
            {
                std::cerr << "Destination IP is reachable through NDN network!" << std::endl;
                return &entry;
            }
        }
        //Si se llega a este punto es que no hubo coincidencias en la tabla de encaminamiento
        std::cerr << "Destination IP is NOT reachable through NDN network!" << std::endl;
        return nullptr;
    }

    // Usada para el procesado del paquete IP entrante
    // Have to use a shared_ptr because bind forbids std::move and unique_ptr :(
    void pcap_callback(std::shared_ptr<Cola_paquetes::packet_t> packetIP, struct pcap_pkthdr *pkthdr, ndn::Face *face)
    {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));

        std::cerr << "Ready to process an IP packet!" << std::endl;

        //Se apunta el puntero a la cabecera Ethernet al comienzo del paquete
        struct ether_header *eptr;
        eptr = (struct ether_header *)packetIP->data();

        //Comprobar que es un paquete IP
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        {
            std::cerr << "It is an IP packet!" << std::endl;
        }
        else
        {
            std::cerr << "It is NOT an IP packet!" << std::endl;
            return;
        }

        int size = pkthdr->len;
        packetIP->resize(size);

        //Se accede a la cabecera IP, saltandose la cabecera Ethernet
        struct iphdr *iph = (struct iphdr *)(packetIP->data() + sizeof(struct ethhdr));

        //Se comprueba el protocolo (los ping seran ICMP)
        switch (iph->protocol)
        {
        case 1:
            std::cerr << "It is ICMP!" << std::endl;
            dest = print_icmp_packet(packetIP->data(), size);
            break;
        case 6:
            std::cerr << "It is TCP!" << std::endl;
            dest = print_tcp_packet(packetIP->data(), size);
            break;
        case 17:
            std::cerr << "It is UDP!" << std::endl;
            dest = print_udp_packet(packetIP->data(), size);
            break;
        default:
            std::cerr << "Unknown protocol!" << std::endl;
            return;
        }

        //Se pasa a aplicar la logica de la pasarela NDN
        std::cerr << "Checking destination IP in the table..." << std::endl;

        // La siguiente variable contendra el contenido del paquete excluyendo la cabecera Ethernet
        packetIP->erase(packetIP->begin(), packetIP->begin() + sizeof(struct ethhdr));

        //Devuelve el indice de la entrada en la tabla que se corresponde con el prefijo destino
        auto entrada_tabla = check_tabla_encaminamiento(dest.sin_addr);

        if (entrada_tabla != nullptr)
        {
            std::string gateway_envio = entrada_tabla->prefijo_ndn;
            std::cerr << ">> NDN prefix found: " << gateway_envio << std::endl;

            //Se guarda el paquete en la cola, devolviendo el num de secuencia asignado
            int seqno_paquete = cola_paquetes_nodo.addPaquete(std::move(*packetIP)) - 1;
            std::cerr << "Packet saved in the queue of the gateway with sqno = " << seqno_paquete << std::endl;

            //Mandar INTEREST "/mired/<gateway_envio>/ip/request/<miNodo>/<seqno_paquete>"
            std::string interestName_saliente = "/mired/" + gateway_envio + "/ip/request/" + thisNodo + "/" + (std::to_string(seqno_paquete));
            ndn::Name interestName(interestName_saliente);
            interestName.appendVersion();

            ndn::Interest interes_peticion(interestName);
            interes_peticion.setCanBePrefix(false);
            interes_peticion.setMustBeFresh(true);

            std::cerr << "Sending Interest " << interes_peticion << std::endl;
            //En realidad esta Interest no espera ninguna respuesta
            face->expressInterest(interes_peticion,
                                  NULL,
                                  NULL,
                                  NULL);

            std::cerr << "Request Interest sent to the gateway!" << std::endl;
        }
        else
        {
            std::cerr << "IP prefix is no reachable through the NDN network!! " << std::endl;
        }

        return;
    }

    // Crear un hijo, al que le pasamos como parámetro un puntero a variable_contexto
    void pcap_reader(boost::asio::io_context *io_context, ndn::Face *face)
    {
        pcap_setnonblock(interfaz_captura, 0, NULL);
        //Se ejecutara un hilo en bucle que reciba los paquetes a través de libpcap
        while (true)
        {
            std::cerr << "Waiting for an IP packet..." << std::endl;

            //Usar pcap_next para leer un paquete entrante: u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
            struct pcap_pkthdr pkthdr;
            const u_char *paquete = pcap_next(interfaz_captura, &pkthdr);

            // Copy the packet contents to a new buffer, as pcap_next reuses its buffers
            auto packet = std::make_shared<Cola_paquetes::packet_t>();
            packet->assign(paquete, paquete + pkthdr.len);

            std::cerr << "A packet from the IPv4 world has arrived!" << std::endl;

            // Desde el hilo ejecutamos variable_contexto.dispatch(callback...) cada vez que nos llega un paquete.
            io_context->dispatch(bind(pcap_callback, packet, &pkthdr, face));
        }
    }
}

namespace ndn
{
    namespace gateway
    {

        void
        Producer::run()
        {
            // Iniciar un hilo representando los paquetes pcap entrantes. En nuestro caso, se usan numeros para representarlos
            // Crear un hijo, al que le pasamos como parámetro un puntero a variable_contexto
            boost::scoped_thread<> t{boost::thread(bind(&pcap_reader, &m_ioContext, &m_face))};

            //Respondera las Interest que lleguen con prefijo /mired/<mi_nodo>/ip/request --> Solicitud para enviarle un paquete IP
            m_face.setInterestFilter("/mired/" + thisNodo + "/ip/request",
                                     bind(&Producer::onInterest_request, this, _2),
                                     nullptr, // RegisterPrefixSuccessCallback is optional
                                     bind(&Producer::onRegisterFailed_request, this, _1, _2));

            //Respondera las Interest que lleguen con prefijo /mired/<mi_nodo>/ip/datagram --> Para enviar el paquete IP en el Data al otro gateway
            m_face.setInterestFilter("/mired/" + thisNodo + "/ip/datagram",
                                     bind(&Producer::onInterest_datagram, this, _2),
                                     nullptr, // RegisterPrefixSuccessCallback is optional
                                     bind(&Producer::onRegisterFailed_datagram, this, _1, _2));

            //Se cambia la llamada a processEvents por variable_conexto.run()
            m_ioContext.run();
        }

        void
        Producer::onInterest_request(const Interest &interest_request)
        {
            //Prefijo Interest = /mired/<mi_nodo>/ip/request/<gateway_origen>/<seqno_nodoOrigen>
            std::cerr << ">> Interest arrived: " << interest_request << std::endl;
            std::string interestName_entrante = (interest_request.getName()).toUri();

            std::vector<std::string> tokens = split(interestName_entrante, '/');
            std::string gateway_origen = tokens.at(5);
            std::string seqno_nodoOrigen = tokens.at(6);

            //Responde enviando Interest = /mired/<gateway_origen>/ip/datagram/<seqno_nodoOrigen>
            std::string interestName_saliente = "/mired/" + gateway_origen + "/ip/datagram/" + seqno_nodoOrigen;
            Name interestName(interestName_saliente);
            interestName.appendVersion();

            Interest interest(interestName);
            interest.setCanBePrefix(false);
            interest.setMustBeFresh(true);
            interest.setInterestLifetime(6_s);

            std::cerr << "Sending Interest Datagram to respond de request of an IP packet from other gateway: " << interest << std::endl;
            m_face.expressInterest(interest,
                                   bind(&Producer::onData, this, _2),
                                   bind(&Producer::onNack, this, _2),
                                   bind(&Producer::onTimeout, this, _1));
        }

        void
        Producer::onRegisterFailed_request(const Name &prefix, const std::string &reason)
        {
            std::cerr << "ERROR: Failed to register prefix '" << prefix
                      << "' with the local forwarder (" << reason << ")" << std::endl;
            m_face.shutdown();
        }

        //Interest de respuesta de un gateway al que previamente se le solicito el envio de un paquete IP (/mired/<this_gateway>/ip/datagram/<this_seqno>)
        //Responde con Data conteniendo el paquete IP previamente guardado en cola de paquetes y prefijo /mired/<this_gateway>/ip/datagram/<this_seqno>
        void
        Producer::onInterest_datagram(const Interest &interest_datagram)
        {
            std::cerr << ">> Interest arrived: " << interest_datagram << std::endl;

            //Se recupera el paquete IP de la cola de paquetes utilizando el seqno en la Interest
            std::string interestName_entrante = (interest_datagram.getName()).toUri();
            std::vector<std::string> tokens = split(interestName_entrante, '/');
            std::string seqno = tokens.at(5);

            const u_char *paquete = cola_paquetes_nodo.getPaquete(std::stoi(seqno)).data();
            int sizePaqueteCola = cola_paquetes_nodo.getPaqueteSize(std::stoi(seqno));

            // Intento de buscar el paquete solo 1 vez y devolver tupla con datos y size --> PROBLEMAS CON REFERENCIA
            //auto paqueteAndSize = cola_paquetes_nodo.getPaqueteAndSize(std::stoi(seqno));
            //const u_char *paquete = (std::get<0>(paqueteAndSize)).data();
            //int sizePaqueteCola = std::get<1>(paqueteAndSize);

            //Verificar que no hubo error extrayendo el paquete de la cola --> SI el tamaño == 0 no se encontró (dummy)
            if (sizePaqueteCola == 0)
            {
                std::cerr << ">> Error retrieving packet from the queue! " << std::endl;
            }
            else
            {
                // Create Data packet
                auto data = make_shared<Data>(interest_datagram.getName());
                data->setFreshnessPeriod(10_s);
                data->setContent(reinterpret_cast<const uint8_t *>(paquete), sizePaqueteCola);

                // Sign Data packet with default identity
                m_keyChain.sign(*data);

                // Return Data packet to the requester
                std::cerr << "<< Content of FULL IP packet sent in Data packet: " << std::endl;
                PrintData(paquete, sizePaqueteCola);
                std::cerr << "<< Size of FULL IP packet sent in Data packet: " << sizePaqueteCola << std::endl;
                m_face.put(*data);
            }
        }

        void
        Producer::onRegisterFailed_datagram(const Name &prefix, const std::string &reason)
        {
            std::cerr << "ERROR: Failed to register prefix '" << prefix
                      << "' with the local forwarder (" << reason << ")" << std::endl;
            m_face.shutdown();
        }

        //Llegada de un paquete IP confirmado previamente --> Paquete IP = Contenido del Data --> Enviar a la direccion IP correspondiente
        void
        Producer::onData(const Data &data) const
        {
            std::cerr << "IP packet received in DATA !!!" << std::endl;
            // //Extraer paquete del DATA
            const u_char *packet = (const u_char *)data.getContent().value();
            std::size_t size = data.getContent().value_size();
            std::cerr << "Size of the received IP packet: " << size << std::endl;
            std::cerr << "Content of the received Data: " << std::endl;
            PrintData(packet, size);

            // Se apunta el puntero a la cabecera IP al comienzo del paquete
            struct iphdr *iph = (struct iphdr *)(packet);
            struct sockaddr_in destIpData;
            memset(&destIpData, 0, sizeof(destIpData));
            destIpData.sin_addr.s_addr = iph->daddr;
            std::cerr << "Destination IP address on the received packet: " << inet_ntoa(destIpData.sin_addr) << std::endl;

            addrDest = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
            if (addrDest == NULL)
            {
                std::cerr << "Unable to allocate memory for the struct sockaddr_in! " << std::endl;
                close(raw_socket);
            }
            addrDest->sin_family = AF_INET;
            addrDest->sin_port = htons(3490); //NOT used (protocol IP)
            (addrDest->sin_addr).s_addr = destIpData.sin_addr.s_addr;

            socklen_t num_of_bytes = sendto(raw_socket, packet, size, 0,
                                            (struct sockaddr *)addrDest, sizeof(struct sockaddr_in));

            if (num_of_bytes == -1)
            {
                std::cerr << "Error sending RAW SOCKET!!! " << std::endl;
                free(addrDest);
            }
            else
            {
                std::cerr << "Raw socket sent successfully!" << std::endl;
                free(addrDest);
            }
        }

        void
        Producer::onNack(const lp::Nack &nack) const
        {
            std::cerr << "Received Nack with reason " << nack.getReason() << std::endl;
        }

        void
        Producer::onTimeout(const Interest &interest) const
        {
            std::cerr << "Timeout for " << interest << std::endl;
        }

    } // namespace gateway
} // namespace ndn
