#ifndef _SPOOF_ARP_SOCKET_HPP
#define _SPOOF_ARP_SOCKET_HPP

#include <linux/if_packet.h>

namespace spoof {

    //! @class ip4_addr
    /*! ip v4 address */
    struct ip4_addr {
        char ip4[32];
        char mac[32];
    };

    ip4_addr locate_ip4_addr(const char* interface, const char* const ip4);
    ip4_addr locate_my_ip4_addr(const char* interface);

    //! @class arp_socket
    class arp_socket {
    public:

        static arp_socket* create_broadcast(const char* interface);
        static arp_socket* create_spoofed_gateway(const char* interface, const ip4_addr& tgtAddr, const char* gatewayAddr);
        static arp_socket* create_spoofed_machine(const char* interface, const ip4_addr& tgtAddr, const char* machineAddr);

        arp_socket(const char* const interface, const ip4_addr& srcAddr);
        arp_socket(const char* const interface, const ip4_addr& srcAddr, const ip4_addr& tgtAddr);

        void close();
        bool send_reply() const;
        bool send_request() const;

    private:

        static const ::size_t ETHLEN = 14; // > Ethernet header length
        static const ::size_t ARPLEN = 28; // > ARP header length

        // Total Header length
        static const ::size_t PACKETLEN = ETHLEN + ARPLEN;

        sockaddr_ll device_;

        int sfd_;
        char header_[PACKETLEN];

        inline bool send_impl(const int opcode) const;
    };
}

#endif
