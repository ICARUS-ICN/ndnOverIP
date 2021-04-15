#ifndef PRODUCER_HPP
#define PRODUCER_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <boost/asio/io_service.hpp>
#include <boost/thread.hpp>
#include <boost/thread/scoped_thread.hpp>

#include "gateway.hpp"

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
            run();

        private:
            //Declarar variable de método de tipo boost::asio::io_context
            boost::asio::io_context m_ioContext;

            //El gateway podrá recibir peticiones internas de la red NDN para direcciones IP que él conozca
            //Llegará Interest solicitando el envío de un Interest para poder enviarle un paquete IP en un futuro Data --> Responde con otra Interest
            void
            onInterest_request(const Interest &interest_request);

            void
            onRegisterFailed_request(const Name &prefix, const std::string &reason);

            //Interest de respuesta de un gateway al que previamente se le solicito el envio de un paquete IP (/mired/<this_gateway>/ip/datagram/<this_seqno>)
            //Responde con Data conteniendo el paquete IP previamente guardado en cola de paquetes y prefijo /mired/<this_gateway>/ip/datagram/<this_seqno>
            void
            onInterest_datagram(const Interest &interest_datagram);

            void
            onRegisterFailed_datagram(const Name &prefix, const std::string &reason);
            //Llegada de un paquete IP confirmado previamente --> Paquete IP = Contenido del Data --> Enviar a la direccion IP correspondiente
            void
            onData(const Data &data) const;

            void
            onNack(const lp::Nack &nack) const;

            void
            onTimeout(const Interest &interest) const;

        private:
            Face m_face;
            KeyChain m_keyChain;
        };

    } // namespace gateway
} // namespace ndn

#endif