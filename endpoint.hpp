/* endpoint.hpp -- v1.0 -- contains socket read, write and fcntl functions
   Author: Sam Y. 2021 */

#ifndef _SPOOF_ENDPOINT_HPP
#define _SPOOF_ENDPOINT_HPP

#include <fcntl.h>

#include <arpa/inet.h>

namespace spoof {

    inline int endpoint_tcp()
    {
        return ::socket(AF_INET, SOCK_STREAM, 0);
    }

    inline int endpoint_tcp_server(const int port, const int queuelen)
    {
        struct sockaddr_in addr = {};

        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = ::htonl(INADDR_ANY);

        int sfd;
        if ((sfd = endpoint_tcp()) == -1) {
            return -1;
        }

        int flags = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(int)) == -1) {
            return -1;
        }

        // Bind to local socket
        if (bind(sfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_in)) == -1) {
            return ::close(sfd), -1;
        }

        // Start listening on socket
        if (listen(sfd, queuelen) == -1) {
            return ::close(sfd), -1;
        }

        return sfd;
    }

    inline int endpoint_udp()
    {
        return ::socket(AF_INET, SOCK_DGRAM, 0);
    }

    inline int endpoint_udp_server(const int port)
    {
        struct sockaddr_in addr = {};

        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = ::htonl(INADDR_ANY);

        int sfd;
        if ((sfd = endpoint_udp()) == -1) {
            return -1;
        }

        int flags = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(int)) == -1) {
            return -1;
        }

        // bind to local socket
        if (bind(sfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_in)) == -1) {
            return ::close(sfd), -1;
        }

        return sfd;
    }

    inline int endpoint_read(const int sfd,
                             void* const buff,
                             const int bufflen)
    {
        return ::recv(sfd, buff, bufflen, 0);
    }

    inline int endpoint_read_oob(const int sfd,
                                 void* const buff)
    {
        return ::recv(sfd, buff, 1, MSG_OOB);
    }

    inline int endpoint_write(const int sfd,
                              const void* buff,
                              const int bufflen)
    {
        return ::send(sfd, buff, bufflen, 0);
    }

    inline int endpoint_write(const int sfd,
                              const int ipaddr,
                              const int port,
                              const void* buff,
                              const unsigned bufflen)
    {
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = ipaddr;

        return ::sendto(sfd,
                        buff,
                        bufflen,
                        0,
                        reinterpret_cast<struct sockaddr*>(&addr),
                        sizeof(sockaddr_in));
    }

    inline int endpoint_write(const int sfd,
                              const char* ipaddr,
                              const int port,
                              const void* buff,
                              const unsigned bufflen)
    {
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = ::inet_addr(ipaddr);

        return ::sendto(sfd,
                        buff,
                        bufflen,
                        0,
                        reinterpret_cast<struct sockaddr*>(&addr),
                        sizeof(sockaddr_in));
    }

    inline int endpoint_connect(const int sfd,
                                const char* ipaddr,
                                const int port)
    {
        struct sockaddr_in addr = {};

        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = ::inet_addr(ipaddr);
        addr.sin_family = AF_INET;

        return ::connect(sfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_in));
    }

    inline int endpoint_unblock(const int sfd)
    {
        int flags = ::fcntl(sfd, F_GETFL, 0);
        return ::fcntl(sfd, F_SETFL, flags | O_NONBLOCK);
    }

    inline int endpoint_close(const int sfd)
    {
        return ::close(sfd);
    }

    inline int endpoint_accept(const int sfd)
    {
        struct sockaddr_in addr = {};
        socklen_t size = sizeof(struct sockaddr_in);

        return ::accept(sfd, reinterpret_cast<struct sockaddr*>(&addr), &size);
    }
}

#endif
