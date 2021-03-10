
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <string>


#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

#include <chrono>
#include <ctime>


//Funcion invocada cada vez que se reciba un paquete en la interfaz abierta
void llegada_paquete(u_char *, const struct pcap_pkthdr* , const u_char* );

//Funciones para procesar y acceder a las cabeceras
void print_icmp_packet(const u_char *, int );
void print_tcp_packet(const u_char *, int );
void print_udp_packet(const u_char *, int);
void print_ip_packet(const u_char *, int);
void print_ip_header(const u_char *, int );


//Funcion para imprimir el payload de un paquete
void PrintData (const u_char *, int);

//Estructuras para procesar las cabeceras del paquete entrante
struct sockaddr_in source,dest;

//Funcion que intentara generar la pasarela en la red NDN para enviar el paquete IP
void check_tabla_encaminamiento(char *);


//Estructura que modela una entrada en la "tabla de encaminamiento" IP en la red NDN
typedef struct
{
        std::string dir_ip;
        std::string prefijo_ndn;

} Entrada_encaminamiento;


//Representa la "tabla de encaminamiento" IP en la red NDN del gateway
Entrada_encaminamiento tabla_encaminamiento[20];

//Parte de la libreria ndn-cxx
namespace ndn {

namespace gateway {

class Producer
{
public:
void
run()
{
        m_face.setInterestFilter("/clock/testApp",
                                 bind(&Producer::onInterest, this, _1, _2),
                                 nullptr,
                                 bind(&Producer::onRegisterFailed, this, _1, _2));
        m_face.processEvents();
}

private:
void
onInterest(const InterestFilter&, const Interest& interest)
{
        std::cout << ">> Interest arrived: " << interest << std::endl;

        auto hour = std::chrono::system_clock::now();
        std::time_t hour_time = std::chrono::system_clock::to_time_t(hour);
        std::cout << ">> Current time: " << std::ctime(&hour_time) << std::endl;

        static const std::string content(std::ctime(&hour_time));

        // Create Data packet
        auto data = make_shared<Data>(interest.getName());
        data->setFreshnessPeriod(10_s);
        data->setContent(reinterpret_cast<const uint8_t*>(content.data()), content.size());

        // Sign Data packet with default identity
        m_keyChain.sign(*data);


        // Return Data packet to the requester
        std::cout << "<< Data Packet sent: " << *data << std::endl;
        m_face.put(*data);
}

void
onRegisterFailed(const Name& prefix, const std::string& reason)
{
        std::cerr << "ERROR: Failed to register prefix '" << prefix
                  << "' with the local forwarder (" << reason << ")" << std::endl;
        m_face.shutdown();
}

private:
Face m_face;
KeyChain m_keyChain;
};

class Consumer
{
public:
void
primera_interest()
{
        Name interestName("/mired/nodoA/ip/request/nodoB/seqno");
        interestName.appendVersion();

        Interest interest(interestName);
        interest.setCanBePrefix(false);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(6_s);

        std::cout << "Sending Interest " << interest << std::endl;
        m_face.expressInterest(interest,
                               bind(&Consumer::onData, this,  _1, _2),
                               bind(&Consumer::onNack, this, _1, _2),
                               bind(&Consumer::onTimeout, this, _1));

        // Bloqueo hasta recibir Data o timeout: para la primera Interest del procedimiento no se espera respuesta (timeout de 1ms)
        boost::chrono::milliseconds mili(1);
        m_face.processEvents(mili);
}

private:
void
onData(const Interest&, const Data& data) const
{
        std::string time_received((char *) data.getContent().value(), data.getContent().value_size());
        std::cout << "Length of the Data Received: " << (std::to_string(data.getContent().value_size())) << std::endl;
        std::cout << "Received Time: " << time_received << std::endl;
}

void
onNack(const Interest&, const lp::Nack& nack) const
{
        std::cout << "Received Nack with reason " << nack.getReason() << std::endl;
}

void
onTimeout(const Interest& interest) const
{
        std::cout << "Timeout for " << interest << std::endl;
}

private:
Face m_face;
};

} // namespace gateway
} // namespace ndn

//Funcion invocada cada vez que se reciba un paquete en la interfaz abierta
void llegada_paquete(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){

        //Se lleva cuenta de los paquetes que se van recibiendo
        static int count = 0;
        count++;

        //Se apunta el puntero a la cabecera Ethernet al comienzo del paquete
        struct ether_header *eptr;
        eptr=(struct ether_header *) packet;
        printf("Paquete numero: %d\n", count);

        printf("MAC origen: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
        printf("MAC destino: %s\n", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

        //Comprobar que es un paquete IP
        if(ntohs (eptr->ether_type) == ETHERTYPE_IP) {
                printf("Es de tipo IP\n");
        }else{
                printf("NO es de tipo IP\n");
                return;
        }

        int size = pkthdr->len;

        //Se accede a la cabecera IP, ssaltandose la cabecera Ethernet
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));


        //Se comprueba el protocolo (los ping seran ICMP)
        switch(iph->protocol) {
        case 1:
                printf("Es ICMP\n");
                print_icmp_packet( packet, size);
                break;
        case 6:
                printf("Es TCP\n");
                print_tcp_packet(packet, size);
                break;
        case 17:
                printf("Es UDP\n");
                print_udp_packet(packet, size);
                break;
        default:
                printf("Protocolo desconocido\n");
                break;
        }

}

//Logica de la pasarela NDN
void check_tabla_encaminamiento(char *dest_addr){
        printf("Ip destino: %s\n", dest_addr);

        //Se pasa a recorrer la tabla de encaminamiento buscando coincidencias...
        //Por ahora parto de asumir que solo hay una entrada
        for(int i = 0; i<1; i++) {
                if(tabla_encaminamiento[i].dir_ip.compare(dest_addr) == 0) {
                        printf("La direccion IP de destino es alcanzable a traves de la red NDN!\n");
                        strd::string prefijo_envio = tabla_encaminamiento[i].prefijo_ndn;

                        try {
                                printf("Enviando Interest para solicitar enviar el paquete IP... \n\n");
                                ndn::gateway::Consumer consumer;
                                consumer.primera_interest();
                        }
                        catch (const std::exception& e) {
                                std::cerr << "ERROR: " << e.what() << std::endl;
                                return;
                        }

                        printf("Se espera recibir la Interest del otro Gateway...\n\n");
                        ndn::gateway::Producer producer;

                        //........................................
                        return;
                }
        }

        //Si se llega a este punto es que no hubo coincidencias en la tabla de encaminamiento
        printf("La direccion IP de destino NO es alcanzable a traves de la red NDN\n");

}


//Funcion que accede y procesa los datos de la cabecera IP
void print_ip_header(const u_char * Buffer, int Size)
{
        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
        iphdrlen =iph->ihl*4;

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        printf("IP Header\n");
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
        printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
        printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
        printf("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr) );
        printf("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr) );

        //Se pasa a aplicar la logica de la pasarela NDN
        printf("Comprobando IP destino....\n");
        char* dest_addr = inet_ntoa(dest.sin_addr);
        check_tabla_encaminamiento(dest_addr);

        return;
}

void print_icmp_packet(const u_char * Buffer, int Size)
{
        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;

        struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

        int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

        printf("\n\n***********************ICMP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer, Size);

        printf("Data Payload: \n");

        //Se imprimen los datos del paquete
        PrintData(Buffer + header_size, (Size - header_size) );

        printf("\n###########################################################");
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
        iphdrlen = iph->ihl*4;

        struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

        int header_size =  sizeof(struct ethhdr) + iphdrlen + (tcph->doff)*4;

        printf("\n\n***********************TCP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer,Size);

        printf("\n");
        printf("TCP Header\n");
        printf("   |-Source Port      : %u\n",ntohs(tcph->source));
        printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
        printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
        printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
        printf("   |-Header Length      : %d DWORDS or %d BYTES\n",(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);

        //Se imprimen los datos del paquete
        printf("Data Payload: \n");
        PrintData(Buffer + header_size, Size - header_size );

        printf("\n###########################################################");
}

void print_udp_packet(const u_char *Buffer, int Size)
{

        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
        iphdrlen = iph->ihl*4;

        struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

        int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

        printf("\n\n***********************UDP Packet*************************\n");

        //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
        print_ip_header(Buffer,Size);

        printf("\nUDP Header\n");
        printf("   |-Source Port      : %d\n", ntohs(udph->source));
        printf("   |-Destination Port : %d\n", ntohs(udph->dest));
        printf("   |-UDP Length       : %d\n", ntohs(udph->len));
        printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));

        //Se imprimen los datos del paquete
        printf("Data Payload\n");
        PrintData(Buffer + header_size, Size - header_size);

        printf("\n###########################################################");
}



//Funcion para imprimir los datos que contiene el paquete
void PrintData (const u_char * data, int Size)
{
        int i, j;
        for(i=0; i < Size; i++)
        {
                if( i!=0 && i%16==0)
                {
                        printf("         ");
                        for(j=i-16; j<i; j++)
                        {
                                if(data[j]>=32 && data[j]<=128)
                                        printf("%c",(unsigned char)data[j]);

                                else printf(".");
                        }
                        printf("\n");
                }

                if(i%16==0) printf("   ");
                printf(" %02X",(unsigned int)data[i]);

                if( i==Size-1)
                {
                        for(j=0; j<15-i%16; j++)
                        {
                                printf("   ");
                        }

                        printf("         ");

                        for(j=i-i%16; j<=i; j++)
                        {
                                if(data[j]>=32 && data[j]<=128)
                                {
                                        printf("%c",(unsigned char)data[j]);
                                }
                                else
                                {
                                        printf(".");
                                }
                        }

                        printf("\n" );
                }
        }
}


int main(int argc, char **argv)
{
        char *dev = NULL; // Interfaz que se va a usar
        pcap_if_t *interfaces;

        
        char *net; //Direccion de la red (dotacion con puntos)
        char *mask; //Mascara de la red (dotacion con puntos)

        int ret; //codigo de retorno
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 netp; //dir IP
        bpf_u_int32 maskp; //mascara de subred
        struct in_addr addr;
        struct pcap_pkthdr hdr;
        struct bpf_program fp; //contenedor con el programa compilado del filtro aplicado

        /* Se buscan interfaces validas */
        //dev = pcap_lookupdev(errbuf); --> deprecated method 
        if(pcap_findalldevs(&interfaces, errbuf)==-1)
        {
                printf("%s\n", errbuf);
                exit(1);
        }

        /* Se sabe de antemano que tendra dos interfaces: enp0s3 y enp0s8, en ese orden. 
        Se coge la segunda, que es la conectada al mundo "IP" puro */
        dev = (interfaces->next)->name;

        // Se comprueba si hubo un error
        if(dev == NULL)
        {
                printf("%s\n",errbuf);
                exit(1);
        }

        // Se muestra la interfaz escogida
        printf("DEV: %s\n",dev);

        // Se coge la direccion y mascara de la red
        ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

        //Se comprueba si hubo error
        if(ret == -1)
        {
                printf("%s\n",errbuf);
                exit(1);
        }


        // Se transforma la direccion y mascara de red a una formato legible
        addr.s_addr = netp;
        net = inet_ntoa(addr);
        if(net == NULL)
        {
                perror("inet_ntoa");
                exit(1);
        }
        printf("NET: %s\n",net);

        addr.s_addr = maskp;
        mask = inet_ntoa(addr);
        if(mask == NULL)
        {
                perror("inet_ntoa");
                exit(1);
        }
        printf("MASK: %s\n",mask);

        //Se comienza la captura en modo promiscuo
        pcap_t* descr;
        descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);

        if(descr == NULL) {
                printf("pcap_open_live(): %s\n", errbuf);
                exit(1);
        }

        /*Se compila el programa para el filtro de paquetes (solo se van a tomar paquetes IP provenientes del
        host 1.2.3.6, al cual sabemos que esta conectado el gateway)*/

        char filtro[30] = "ip and src host 1.2.3.6";
        //char filtro[30] = "ip and src net 1.2.3.4/30";
        if(pcap_compile(descr, &fp, filtro, 0, netp) == -1) {
                fprintf(stderr, "Error compilando el filtro\n");
                exit(1);
        }

        //Se aplica el filtro a la interfaz de captura
        if(pcap_setfilter(descr, &fp) == -1) {
                fprintf(stderr, "Error aplicando el filtro\n");
                exit(1);
        }


        //Se inicializa tabla de encaminamiento (por ahora solo ponemos una entrada conocida)
        Entrada_encaminamiento prueba;
        prueba.dir_ip = "1.2.3.5";
        prueba.prefijo_ndn = "/mired/nodoA";

        //Aqui es donde se inicializaria con el contenido del fichero correspondiente
        for(int i = 0; i < 1; i++) {
                tabla_encaminamiento[i] = prueba;
        }


        //Se entra en bucle infinito para la captura
        pcap_loop(descr,-1,llegada_paquete,NULL);


        return 0;
}