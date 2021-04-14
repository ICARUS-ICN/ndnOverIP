#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string>
#include <sys/socket.h>
#include <vector>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <boost/asio/io_service.hpp>
#include <boost/thread.hpp>
#include <boost/thread/scoped_thread.hpp>

#include <fstream>
#include <iostream>

// ************************************************** DECLARACION ESTRUCTURAS/CLASES Y FUNCIONES **********************************************

//Estructura que modela una entrada en la "tabla de encaminamiento" IP en la red NDN
typedef struct
{
    //std::string dir_ip;
    struct in_addr prefijo_ip;
    std::string prefijo_ndn;

} Entrada_encaminamiento;

//Clase que modela un paquete IP esperando en la cola para ser enviado a través de la red NDN
class Paquete_cola
{
private:
    const u_char *packet; //datos del paquete
    int size;             //tamaño del paquete
    int seqno_paquete;    //num de secuencia para identificarlo en la cola

public:
    Paquete_cola(const u_char *p, int num, int sizeIp)
    {
        packet = p;
        seqno_paquete = num;
        size = sizeIp;
    }
    const u_char *getPacket()
    {
        return packet;
    }
    int getSeqno()
    {
        return seqno_paquete;
    }
    int getSize()
    {
        return size;
    }
};

//Clase que modela la cola de paquetes IP de un gateway, esperando a ser enviados a través de la red NDN
class Cola_paquetes
{
public:
    //Funcion para imprimir los datos que contiene un paquete
    void PrintData(const u_char *data, int Size)
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
    int addPaquete(const u_char *p, int size)
    {
        boost::lock_guard<boost::mutex> mi_lock(mtx_); // operacion protegida por mutex

        struct iphdr *iph = (struct iphdr *)p;
        unsigned short iphdrlen = iph->ihl * 4;
        struct icmphdr *icmph = (struct icmphdr *)(p + iphdrlen);
        int header_size = iphdrlen + (sizeof(icmph)); // asumiendo que serán paquete ICMP

        //Imprimir por consola para comprobaciones
        std::cout << "<< Content of PAYLOAD saved: " << std::endl;
        PrintData(p + header_size, (size - header_size));
        std::cout << "<< Content of FULL packet saved: " << std::endl;
        PrintData(p, size);
        std::cout << "<< Size of FULL packet saved: " << size << std::endl;

        Paquete_cola packet(p, seqno_nodo, size);
        paquetes.push_back(packet);
        seqno_nodo = seqno_nodo + 1;
        return seqno_nodo; //devuelve el seqno_nodo+1 (el paquete se guardo en la cola con seqno --> Necesario para poder usarse en el Interest enviado)
    }

    //Función para recuperar un paquete de la cola identificado por el num de seqno que recibe como parametro
    const u_char *getPaquete(int seqno)
    {
        boost::lock_guard<boost::mutex> mi_lock(mtx_); // operacion protegida por mutex

        for (std::size_t i = 0; i < paquetes.size(); i++)
        {
            Paquete_cola p = paquetes.at(i);
            if (p.getSeqno() == seqno)
            {
                return p.getPacket();
            }
        }

        //Ningun paquete guardado en la cola tiene el SEQNO pedido
        std::string strVar = "error";
        const u_char *error = reinterpret_cast<const unsigned char *>(strVar.c_str());
        return error;
    }

    //Función para recuperar el tamaño de un paquete de la cola identificado por el num de seqno que recibe como parametro
    int getPaqueteSize(int seqno)
    {
        boost::lock_guard<boost::mutex> mi_lock(mtx_); // operacion protegida por mutex

        for (std::size_t i = 0; i < paquetes.size(); i++)
        {
            Paquete_cola p = paquetes.at(i);
            if (p.getSeqno() == seqno)
            {
                return p.getSize();
            }
        }

        //Ningun paquete guardado en la cola tiene el SEQNO pedido
        return -1;
    }

    //Función para recuperar la cola completa de paquetes y hacer el procesado de recuperar uno concreto posteriormente
    std::vector<Paquete_cola> getCola()
    {
        boost::lock_guard<boost::mutex> mi_lock(mtx_);
        return paquetes;
    }

private:
    boost::mutex mtx_; //mutex para proteger tanto al seqno_nodo como a la cola en si
    std::vector<Paquete_cola> paquetes;
    int seqno_nodo = 1; //inicializado a 1: se ira incrementando en una unidad con cada paquete añadido a la cola
};

//Funcion invocada para inicializar la tabla de encaminamiento del gateway a partir del fichero con esta información
std::vector<Entrada_encaminamiento> inicializacion_tabla();

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap();

//Funcion para procesar strings y separarlas de acuerdo al caracter especificado
std::vector<std::string> split(const std::string &, char);

//Funciones para procesar y acceder a las cabeceras del paquete IP capturado
struct sockaddr_in print_icmp_packet(const u_char *, int);
struct sockaddr_in print_tcp_packet(const u_char *, int);
struct sockaddr_in print_udp_packet(const u_char *, int);
void print_ip_header(const u_char *, int);

//Funcion para imprimir el payload de un paquete por consola
void PrintData(const u_char *, int);

// ************************************************** VARIABLES/DATOS DEL NODO **********************************************

//Representa la cola de paquetes IP del nodo que estan esperando a ser enviados por la red NDN
Cola_paquetes cola_paquetes_nodo;

//Representa la "tabla de encaminamiento" IP en la red NDN del gateway
std::vector<Entrada_encaminamiento> tabla_encaminamiento;

//Interfaz configurada para la captura de libpcap
pcap_t *interfaz_captura;

//Nombre del nodo gateway recibido como parametro por línea de comandos
std::string thisNodo;

//Estructuras para procesar las cabeceras del paquete entrante
struct sockaddr_in source, dest;

// ************************************************** DEFINICION DE FUNCIONES **********************************************

//Funcion invocada para inicializar la tabla de encaminamiento del gateway a partir del fichero presente en el Escritorio con esta información
//Formato de cada linea del fichero que contiene la info de encaminamiento: <prefijo_ip> <nombreGateway>
std::vector<Entrada_encaminamiento> inicializacion_tabla()
{
    std::string linea;

    std::ifstream fichero("/home/mariel/Escritorio/tablaEncaminamiento.txt");
    if (fichero.fail())
    {
        std::cout << "FILE does NOT exist!" << std::endl;
        exit(1);
    }

    std::vector<Entrada_encaminamiento> tabla;
    while (!fichero.eof())
    {
        std::getline(fichero, linea);
        if (!fichero.eof())
        {
            Entrada_encaminamiento entrada;
            std::vector<std::string> tokens = split(linea, ' ');
            entrada.prefijo_ip.s_addr = inet_addr(tokens.at(0).c_str());
            entrada.prefijo_ndn = tokens.at(1);
            tabla.push_back(entrada);
            std::cout << "New entry added: " << tokens.at(0) << "--" << tokens.at(1) << std::endl;
        }
    }
    fichero.close();
    return tabla;
}

//Funcion que configura la interfaz de captura de paquetes IP para su procesado
pcap_t *configuracion_captura_libpcap()
{

    char *dev = NULL; // Interfaz que se va a usar
    pcap_if_t *interfaces;
    pcap_if_t *device;
    char devs[100][100];

    char *net;  //Direccion de la red (notacion con puntos)
    char *mask; //Mascara de la red (notacion con puntos)

    int ret; //codigo de retorno
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;  //dir IP
    bpf_u_int32 maskp; //mascara de subred
    struct in_addr addr;
    struct bpf_program fp; //contenedor con el programa compilado del filtro aplicado

    /* Se buscan interfaces validas */
    if (pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    //Se muestran por consola los dispositivos disponibles para iniciar una captura
    int count = 1, n;
    int net_interface = 0;
    printf("Devices available: \n");
    for (device = interfaces; device != NULL; device = device->next)
    {
        net_interface = 0;
        pcap_addr_t *a;
        for (a = device->addresses; a != NULL; a = a->next)
        {
            if (a->addr->sa_family == AF_INET)
            {
                char *dir = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
                printf("%d. %s - %s\n", count, device->name, dir);
                net_interface = 1;
            }
        }
        if (net_interface == 0)
        {
            printf("%d. %s - %s\n", count, device->name, device->description);
        }

        if (device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }
        count++;
    }

    //Se pide que se introduzca en qué interfaz se desea capturar
    printf("Enter the number  of the device that you want to capture: ");
    while (scanf("%d", &n) != 1)
    {
        printf("Failed to read the number. Enter it again: \n");
    }
    dev = devs[n];

    // Se comprueba si hubo un error
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // Se muestra la interfaz escogida
    printf("DEV: %s\n", dev);

    // Se coge la direccion y mascara de la red
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    //Se comprueba si hubo error
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    // Se transforma la direccion y mascara de red a una formato legible
    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (net == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
    printf("NET: %s\n", net);
    std::string network(net);

    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    if (mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }
    printf("MASK: %s\n", mask);

    //Se comienza la captura en modo promiscuo
    pcap_t *descr;
    descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);

    if (descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    //char filtro[30] = "ip and src host 1.2.3.6";
    char filtro[100] = "ip and src net ";
    char filtro2[100] = " mask ";
    strcat(filtro, network.c_str()); //ip and src net <net_dir>
    strcat(filtro, filtro2);         //ip and src net <net_dir> mask
    strcat(filtro, mask);            //ip and src net <net_dir> mask <mask>
    if (pcap_compile(descr, &fp, filtro, 0, netp) == -1)
    {
        fprintf(stderr, "Error compiling the filter\n");
        exit(1);
    }

    //Se aplica el filtro a la interfaz de captura
    if (pcap_setfilter(descr, &fp) == -1)
    {
        fprintf(stderr, "Error setting the filter\n");
        exit(1);
    }

    return descr;
}

//Funcion para procesar los prefijos de los paquetes ndn, separandolo por '/'
std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim))
    {
        result.push_back(item);
    }

    return result;
}

struct sockaddr_in print_icmp_packet(const u_char *Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    printf("\n\n***********************ICMP Packet*************************\n");

    //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
    print_ip_header(Buffer, Size);

    printf("Data Payload: \n");

    //Se imprimen los datos del paquete
    PrintData(Buffer + header_size, (Size - header_size));

    printf("\n###########################################################");

    return dest;
}

struct sockaddr_in print_tcp_packet(const u_char *Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + (tcph->doff) * 4;

    printf("\n\n***********************TCP Packet*************************\n");

    //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
    print_ip_header(Buffer, Size);

    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);

    //Se imprimen los datos del paquete
    printf("Data Payload: \n");
    PrintData(Buffer + header_size, Size - header_size);

    printf("\n###########################################################");

    return dest;
}

struct sockaddr_in print_udp_packet(const u_char *Buffer, int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    printf("\n\n***********************UDP Packet*************************\n");

    //Se procesa la cabecera IP y desde ahi se realiza la llamada a la pasarela NDN
    print_ip_header(Buffer, Size);

    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n", ntohs(udph->source));
    printf("   |-Destination Port : %d\n", ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));

    //Se imprimen los datos del paquete
    printf("Data Payload\n");
    PrintData(Buffer + header_size, Size - header_size);

    printf("\n###########################################################");

    return dest;
}

//Funcion que accede y procesa los datos de la cabecera IP
void print_ip_header(const u_char *Buffer, int Size)
{
    //unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    //iphdrlen = iph->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("IP Header\n");
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
    printf("   |-TTL      : %d\n", (unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n", (unsigned int)iph->protocol);
    printf("   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));

    return;
}

//Funcion para imprimir los datos que contiene el paquete
void PrintData(const u_char *data, int Size)
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

namespace processLibpcap
{

    //Comprueba si la direccion destino de un paquete IP recibido coincide con una entrada de su tabla
    //Devuelve el índice de la coincidencia o -1 si no hay ninguna
    int check_tabla_encaminamiento(struct in_addr dest_addr)
    {
        //Se pasa a recorrer la tabla de encaminamiento buscando coincidencias...
        std::cout << "Checking destination IP in the table: " << inet_ntoa(dest_addr) << std::endl;
        for (std::size_t i = 0; i < tabla_encaminamiento.size(); i++)
        {
            if (tabla_encaminamiento[i].prefijo_ip.s_addr == dest_addr.s_addr)
            {
                std::cout << "Destination IP is reachable through NDN network!" << std::endl;
                return (static_cast<int>(i));
            }
        }
        //Si se llega a este punto es que no hubo coincidencias en la tabla de encaminamiento
        std::cout << "Destination IP is NOT reachable through NDN network!" << std::endl;
        return -1;
    }
    // Usada para el procesado del paquete IP entrante
    void pcap_callback(const u_char *packet, struct pcap_pkthdr *pkthdr, ndn::Face *face)
    {
        std::cerr << "Ready to process an IP packet!" << std::endl;

        //Se apunta el puntero a la cabecera Ethernet al comienzo del paquete
        struct ether_header *eptr;
        eptr = (struct ether_header *)packet;

        //Comprobar que es un paquete IP
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        {
            std::cout << "It is an IP packet!" << std::endl;
        }
        else
        {
            std::cout << "It is NOT an IP packet!" << std::endl;
            return;
        }

        int size = pkthdr->len;
        int sizeIp = size - sizeof(struct ethhdr);

        //Se accede a la cabecera IP, saltandose la cabecera Ethernet
        struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

        //La siguiente variable contendra el contenido del paquete excluyendo la cabecera Ethernet
        const u_char *packetIP = packet + sizeof(struct ethhdr);

        //Se comprueba el protocolo (los ping seran ICMP)
        switch (iph->protocol)
        {
        case 1:
            std::cout << "It is ICMP!" << std::endl;
            dest = print_icmp_packet(packet, size);
            break;
        case 6:
            std::cout << "It is TCP!" << std::endl;
            dest = print_tcp_packet(packet, size);
            break;
        case 17:
            std::cout << "It is UDP!" << std::endl;
            dest = print_udp_packet(packet, size);
            break;
        default:
            std::cout << "Unknown protocol!" << std::endl;
            return;
        }

        //Se pasa a aplicar la logica de la pasarela NDN
        std::cout << "Checking destination IP in the table..." << std::endl;

        //Devuelve el indice de la entrada en la tabla que se corresponde con el prefijo destino
        int entrada_tabla = check_tabla_encaminamiento(dest.sin_addr);

        if (entrada_tabla >= 0)
        {
            std::string gateway_envio = tabla_encaminamiento[entrada_tabla].prefijo_ndn;
            std::cout << ">> NDN prefix found: " << gateway_envio << std::endl;

            //Se guarda el paquete en la cola, devolviendo el num de secuencia asignado
            int seqno_paquete = cola_paquetes_nodo.addPaquete(packetIP, sizeIp) - 1;
            std::cout << "Packet saved in the queue of the gateway with sqno = " << seqno_paquete << std::endl;

            //Mandar INTEREST "/mired/<gateway_envio>/ip/request/<miNodo>/<seqno_paquete>"
            std::string interestName_saliente = "/mired/" + gateway_envio + "/ip/request/" + thisNodo + "/" + (std::to_string(seqno_paquete));
            ndn::Name interestName(interestName_saliente);
            interestName.appendVersion();

            ndn::Interest interes_peticion(interestName);
            interes_peticion.setCanBePrefix(false);
            interes_peticion.setMustBeFresh(true);

            std::cout << "Sending Interest " << interes_peticion << std::endl;
            //En realidad esta Interest no espera ninguna respuesta
            face->expressInterest(interes_peticion,
                                  NULL,
                                  NULL,
                                  NULL);

            std::cout << "Request Interest sent to the gateway!" << std::endl;
        }
        else
        {
            std::cout << "IP prefix is no reachable through the NDN network!! " << std::endl;
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

            std::cerr << "A packet from the IPv4 world has arrived!" << std::endl;

            // Desde el hilo ejecutamos variable_contexto.dispatch(callback...) cada vez que nos llega un paquete.
            io_context->dispatch(bind(pcap_callback, paquete, &pkthdr, face));
        }
    }
} //namespace processLibpcap

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
                boost::scoped_thread<> t{boost::thread(bind(&processLibpcap::pcap_reader, &m_ioContext, &m_face))};

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

        private:
            //Declarar variable de método de tipo boost::asio::io_context
            boost::asio::io_context m_ioContext;

            //El gateway podrá recibir peticiones internas de la red NDN para direcciones IP que él conozca
            //Llegará Interest solicitando el envío de un Interest para poder enviarle un paquete IP en un futuro Data --> Responde con otra Interest
            void
            onInterest_request(const Interest &interest_request)
            {
                //Prefijo Interest = /mired/<mi_nodo>/ip/request/<gateway_origen>/<seqno_nodoOrigen>
                std::cout << ">> Interest arrived: " << interest_request << std::endl;
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

                std::cout << "Sending Interest Datagram to respond de request of an IP packet from other gateway: " << interest << std::endl;
                m_face.expressInterest(interest,
                                       bind(&Producer::onData, this, _2),
                                       bind(&Producer::onNack, this, _2),
                                       bind(&Producer::onTimeout, this, _1));
            }

            void
            onRegisterFailed_request(const Name &prefix, const std::string &reason)
            {
                std::cerr << "ERROR: Failed to register prefix '" << prefix
                          << "' with the local forwarder (" << reason << ")" << std::endl;
                m_face.shutdown();
            }

            //Interest de respuesta de un gateway al que previamente se le solicito el envio de un paquete IP (/mired/<this_gateway>/ip/datagram/<this_seqno>)
            //Responde con Data conteniendo el paquete IP previamente guardado en cola de paquetes y prefijo /mired/<this_gateway>/ip/datagram/<this_seqno>
            void
            onInterest_datagram(const Interest &interest_datagram)
            {
                std::cout << ">> Interest arrived: " << interest_datagram << std::endl;

                //Se recupera el paquete IP de la cola de paquetes utilizando el seqno en la Interest
                std::string interestName_entrante = (interest_datagram.getName()).toUri();
                std::vector<std::string> tokens = split(interestName_entrante, '/');
                std::string seqno = tokens.at(5);

                const u_char *paquete = cola_paquetes_nodo.getPaquete(std::stoi(seqno));
                int sizePaqueteCola = cola_paquetes_nodo.getPaqueteSize(std::stoi(seqno));

                //Verificar que no hubo error extrayendo el paquete de la cola
                std::string paquete_string(reinterpret_cast<const char *>(paquete));
                std::string error("error");
                if (paquete_string.compare(error) == 0)
                {
                    std::cout << ">> Error retrieving packet from the queue! " << std::endl;
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
                    std::cout << "<< Content of FULL IP packet sent in Data packet: " << std::endl;
                    PrintData(paquete, sizePaqueteCola);
                    std::cout << "<< Size of FULL IP packet sent in Data packet: " << sizePaqueteCola << std::endl;
                    m_face.put(*data);
                }
            }

            void
            onRegisterFailed_datagram(const Name &prefix, const std::string &reason)
            {
                std::cerr << "ERROR: Failed to register prefix '" << prefix
                          << "' with the local forwarder (" << reason << ")" << std::endl;
                m_face.shutdown();
            }

            //Llegada de un paquete IP confirmado previamente --> Paquete IP = Contenido del Data --> Enviar a la direccion IP correspondiente
            void
            onData(const Data &data) const
            {
                std::cout << "IP packet received in DATA !!!" << std::endl;
                // //Extraer paquete del DATA
                const u_char *packet = (const u_char *)data.getContent().value();
                std::size_t size = data.getContent().value_size();
                std::cout << "Size of the received IP packet: " << size << std::endl;
                std::cout << "Content of the received Data: " << std::endl;
                PrintData(packet, size);

                // Se apunta el puntero a la cabecera IP al comienzo del paquete
                struct iphdr *iph = (struct iphdr *)(packet);
                struct sockaddr_in destIpData;
                memset(&destIpData, 0, sizeof(destIpData));
                destIpData.sin_addr.s_addr = iph->daddr;
                std::cout << "Destination IP address on the received packet: " << inet_ntoa(destIpData.sin_addr) << std::endl;

                int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                if (raw_socket < 0)
                {
                    std::cout << "<<    Error creating socket to send IP packet!! " << std::endl;
                    exit(-1);
                }
                std::cout << "Socket created successfully! " << std::endl;

                // struct sockaddr_in {
                //     short            sin_family;   // e.g. AF_INET
                //     unsigned short   sin_port;     // e.g. htons(3490)
                //     struct in_addr   sin_addr;     // see struct in_addr, below
                //     char             sin_zero[8];  // zero this if you want to
                // };

                struct sockaddr_in *addrDest = NULL;
                addrDest = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
                if (addrDest == NULL)
                {
                    std::cout << "Unable to allocate memory for the struct sockaddr_in! " << std::endl;
                    close(raw_socket);
                }
                addrDest->sin_family = AF_INET;
                addrDest->sin_port = htons(3490); //No se usara (protocolo IP)
                (addrDest->sin_addr).s_addr = destIpData.sin_addr.s_addr;

                // int sendto(
                //     __in SOCKET s,
                //     __in const char *buf,
                //     __in int len,
                //     __in int flags,
                //     __in const struct sockaddr *to,
                //     __in int tolen
                // );
                socklen_t num_of_bytes = sendto(raw_socket, packet, size, 0,
                                                (struct sockaddr *)addrDest, sizeof(struct sockaddr_in));

                if (num_of_bytes == -1)
                {
                    std::cout << "Error sending RAW SOCKET!!! " << std::endl;
                    free(addrDest);
                    close(raw_socket);
                }
                else
                {
                    std::cout << "Raw socket sent successfully!" << std::endl;
                    free(addrDest);
                    close(raw_socket);
                }
            }

            void
            onNack(const lp::Nack &nack) const
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
            KeyChain m_keyChain;
        };

    } // namespace gateway
} // namespace ndn

// ************************************************** MAIN **********************************************
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
