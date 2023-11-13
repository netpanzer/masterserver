/*

npms.c

aka netpanzer 'masterserver'

listens to port 28900 for 'heartbeat' messages from

netpanzer gameservers, provides a list of live games

system firewall must allow connections to port 28900

both udp and tcp (udp is used for a quick challenge

echo request)



Copyright (C) 2018 by Fulvio Testi <effetix@gmail.com>

This program is free software; you can redistribute it and/or

modify it under the terms of the GNU General Public License

as published by the Free Software Foundation; either version 2

of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,

but WITHOUT ANY WARRANTY; without even the implied warranty of

MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the

GNU General Public License for more details.

You should have received a copy of the GNU General Public License

along with this program; if not, write to the Free Software

Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

See README file for more information.

*/

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

////////// customizable data is here ////////////

// max number of gameservers array

#define GS_MAX_NUM 64

// program name to appear in logs

static const char *progname = "npms";

// shutdown command

static const char shutdown_com[] = "shutdown!";  // max 12 chars

// admin address (for shutdown command)

static const char admin_addr[] = "127.0.0.1";

////////// better not touch below here //////////

#define SEND_BUFFER 1024

#define UDP_BUFFER 13

#define MAX_HOST 1025

#define MAX_PORT 32

static const char ECHO_QUERY[] = "\\echo\\";

// static const char MS_LIST_QUERY[] = "\\list\\gamename\\netpanzer\\final\\";

static const char MS_LIST_QUERY_ANSWER[] = "\\final\\";

static int ufd;  // udp fd

static const char heartbeat_t[] = "heartbeat";

static const char list_t[] = "list";

static const char gamename_t[] = "gamename";

static const char netpanzer_t[] = "netpanzer";

static const char port_t[] = "port";

static const char protocol_t[] = "protocol";

static const char final_t[] = "final";

typedef struct {
    int status;

    char addr[16];

    int port;

    int protocol;

    time_t timestamp;

    char echokey[13];

} gs_list;

static gs_list gs_arr[GS_MAX_NUM];

static int running_mode = 0;

struct event *uev;

/////////////////////////////////////////////////

///

static int

tcp_close(int fd) {
    return close(fd);
}

///

///

static int

udp_socket_send_to(evutil_socket_t fd, char *msg, long int truelen,
                   struct sockaddr *dest, int fromlen) {
    int n = sendto(fd, msg, truelen, 0,

                   (struct sockaddr *) dest, fromlen);

    return n;
}

///

/////

static void

writecb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *output = bufferevent_get_output(bev);

    if (evbuffer_get_length(output) == 0) {
        // printf("flushed answer\n\n");

        int tfd = bufferevent_getfd(bev);

        if (tfd != -1) {
            tcp_close(tfd);
        }

        bufferevent_free(bev);
    }
}

/////

/////

static void

readcb(struct bufferevent *bev, void *ctx) {
    struct evbuffer *input;

    input = bufferevent_get_input(bev);

    // struct event_base *base = ctx;

    int bufflen = evbuffer_get_length(input);

    if (bufflen > 0) {
        if (bufflen > 256) {
            bufflen = 256;
        }

        char cmsg[bufflen + 1];

        evbuffer_copyout(input, cmsg, bufflen);

        cmsg[bufflen] = '\0';

        // printf("input(%d): %s\n", bufflen-1, cmsg);

        char cl_ip[16];

        struct sockaddr_in cl_addr;

        bzero(&cl_addr, sizeof(cl_addr));

        socklen_t cl_addr_len = sizeof(cl_addr);

        if (getpeername(bufferevent_getfd(bev), (struct sockaddr *) &cl_addr,
                        &cl_addr_len) == 0) {
            inet_ntop(AF_INET, &cl_addr.sin_addr, cl_ip, sizeof(cl_ip));

            // unsigned int cl_port = ntohs(cl_addr.sin_port);

            // printf("ip address:port %s:%d\n", cl_ip, cl_port);
        }

        // processing input

        char *token = strtok(cmsg, "\\");

        unsigned int port_v = 0;

        unsigned int protocol_v = 0;

        int tokenc = 0;

        int hcl = 0;

        int result = 0;

        if (token == NULL) {
            // printf("Malformed string\n");

            goto out;
        }

        while (token) {
            tokenc++;

            if (tokenc == 1) {
                if ((strcmp(token, heartbeat_t)) == 0) {  // heartbeat

                    hcl++;
                }

                if ((strcmp(token, list_t)) == 0) {  // list

                    int intokenc = 1;

                    int validity = 1;

                    while (token) {
                        if (intokenc == 2 && (strcmp(token, gamename_t)) == 0) {
                            validity++;
                        }

                        if (intokenc == 3 && (strcmp(token, netpanzer_t)) == 0) {
                            validity++;
                        }

                        if (intokenc == 4 && (strcmp(token, final_t)) == 0) {
                            validity++;
                        }

                        token = strtok(NULL, "\\");

                        intokenc++;

                    }  // while

                    if (validity == 4) {
                        result = 2;

                        break;

                    } else {
                        result = 0;

                        break;
                    }
                }
            }

            if (tokenc == 2) {
                if ((strcmp(token, gamename_t)) == 0) {
                    hcl++;
                }
            }

            if (tokenc == 3) {
                if ((strcmp(token, netpanzer_t)) == 0) {
                    hcl++;
                }
            }

            if (tokenc == 4) {
                if ((strcmp(token, port_t)) == 0) {
                    hcl++;
                }
            }

            if (tokenc == 5 && hcl == 4) {
                port_v = atoi(token);

                if (port_v > 0) {
                    if (port_v > 1024 && port_v < 65535) {
                        hcl++;
                    }
                }
            }

            if (tokenc == 6) {
                if ((strcmp(token, protocol_t)) == 0) {
                    hcl++;
                }
            }

            if (tokenc == 7 && hcl == 6) {
                protocol_v = atoi(token);

                if (protocol_v > 0) {
                    hcl++;
                }
            }

            if (tokenc == 8) {
                if ((strcmp(token, final_t)) == 0) {
                    hcl++;

                    if (hcl == 8) {
                        // heartbeat string is ok

                        result = 1;

                        break;
                    }
                }
            }

            token = strtok(NULL, "\\");

        }  // while

        if (result == 0) {
            goto out;

        } else if

                (result == 1) {
            // send "\final\" back and add gs to list (optionally may do more checks)

            int first_entry = 0;

            bool free_entries = false;

            bool isinit = false;

            int i;

            for (i = 0; i < GS_MAX_NUM; i++) {
                if (gs_arr[i].status == 0 && free_entries == false) {
                    first_entry = i;

                    free_entries = true;
                }

                if (gs_arr[i].status > 0) {
                    if ((strcmp(cl_ip, gs_arr[i].addr)) == 0 &&
                        port_v == gs_arr[i].port) {
                        isinit = true;

                        gs_arr[i].timestamp = time(NULL);

                    } else {
                        time_t now = time(NULL);

                        if (now - gs_arr[i].timestamp > 60 * 5) {
                            gs_arr[i].status =
                                    0;  // deleting gameserver if more than 5 mins old
                        }
                    }

                    // printf("[status] %d  [ip] %s  [port] %d  [time] %ld\n\n",

                    // gs_arr[i].status, gs_arr[i].addr, gs_arr[i].port,
                    // gs_arr[i].timestamp);

                }  // status > 0
            }

            if (isinit == false && free_entries == true) {
                // echo udp challenge test

                struct sockaddr_in si_me;

                int slen = sizeof(si_me);

                memset((char *) &si_me, 0, sizeof(si_me));

                si_me.sin_family = AF_INET;

                si_me.sin_port = htons(port_v);

                si_me.sin_addr.s_addr = inet_addr(cl_ip);

                char echo_query[13] = {0};

                strcat(echo_query, ECHO_QUERY);

                unsigned int echo_key = (rand() % 8999) + 1000;

                char echo_str[5] = {0};

                sprintf(echo_str, "%d", echo_key);

                strcat(echo_query, echo_str);

                int n = udp_socket_send_to(ufd, echo_query, strlen(echo_query),
                                           (struct sockaddr *) &si_me, slen);

                if (n == -1) {
                    syslog(LOG_ERR, "sendto failed: %s", strerror(errno));

                    return;
                }

                gs_arr[first_entry].status = 1;

                strcpy(gs_arr[first_entry].addr, cl_ip);

                gs_arr[first_entry].port = port_v;

                gs_arr[first_entry].protocol = protocol_v;

                gs_arr[first_entry].timestamp = time(NULL);

                strcpy(gs_arr[first_entry].echokey, echo_str);
            }

            bufferevent_write(bev, MS_LIST_QUERY_ANSWER,
                              strlen(MS_LIST_QUERY_ANSWER));

            bufferevent_enable(bev, EV_WRITE);

            return;

        } else {
            // send gs list to client

            char sendbuff[SEND_BUFFER] = {0};

            int buffind = 0;

            const char ip_token[] = "\\ip\\";

            const char port_token[] = "\\port\\";

            const char final_token[] = "\\final\\";

            int i;

            for (i = 0; i < GS_MAX_NUM; i++) {
                // deletion here too

                if (gs_arr[i].status > 0) {
                    time_t now = time(NULL);

                    if (now - gs_arr[i].timestamp > 60 * 5) {
                        gs_arr[i].status =
                                0;  // deleting gameserver if more than 5 mins old
                    }
                }

                //

                if (gs_arr[i].status >
                    1) {  // only those who passed udp echo challenge test

                    strcat(sendbuff, ip_token);

                    buffind = buffind + 6;

                    int addrlen = strlen(gs_arr[i].addr);

                    strcat(sendbuff, gs_arr[i].addr);

                    buffind = buffind + addrlen;

                    strcat(sendbuff, port_token);

                    buffind = buffind + 8;

                    char port_str[6] = {0};

                    sprintf(port_str, "%d", gs_arr[i].port);

                    int portlen = strlen(port_str);

                    strcat(sendbuff, port_str);

                    buffind = buffind + portlen;

                    // printf("status: %d  ip: %s  port: %d  time: %ld\n\n",

                    //       gs_arr[i].status, gs_arr[i].addr, gs_arr[i].port,
                    //       gs_arr[i].timestamp);
                }

            }  // for

            strcat(sendbuff, final_token);

            buffind = buffind + 9;

            char send_str[buffind + 1];

            send_str[buffind] = '\0';

            strcpy(send_str, sendbuff);

            bufferevent_write(bev, send_str, strlen(send_str));

            bufferevent_enable(bev, EV_WRITE);

            return;

        }  // else

    }  // bufflen > 0

    out:

    bufferevent_free(bev);
}

/////

/////

static void

errorcb(struct bufferevent *bev, short error, void *ctx) {
    if (error & BEV_EVENT_CONNECTED) {
        // go on

    } else if (error & BEV_EVENT_ERROR) {
        // we decide to just clean up on error

        bufferevent_free(bev);

    } else if (error & BEV_EVENT_TIMEOUT) {
        bufferevent_free(bev);

    } else if (error & BEV_EVENT_READING) {
        bufferevent_free(bev);

    } else if (error & BEV_EVENT_WRITING) {
        bufferevent_free(bev);

    } else if (error & BEV_EVENT_EOF) {
        bufferevent_free(bev);
    }
}

/////

/////

static void

do_accept(evutil_socket_t listener, short event, void *arg) {
    struct event_base *base = arg;

    struct sockaddr_storage ss;

    socklen_t slen = sizeof(ss);

    int fd = accept(listener, (struct sockaddr *) &ss, &slen);

    if (fd < 0) {
        perror("accept");

    } else if (fd > FD_SETSIZE) {
        close(fd);

    } else {
        struct bufferevent *bev;

        evutil_make_socket_nonblocking(fd);

        char cl_ip[16] = {0};

        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *) &ss;

            // int cl_port = ntohs(s->sin_port);

            inet_ntop(AF_INET, &s->sin_addr, cl_ip, sizeof cl_ip);
        }

        bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

        bufferevent_setcb(bev, readcb, writecb, errorcb, base);

        bufferevent_enable(bev, EV_READ | EV_WRITE);

        bufferevent_disable(bev, EV_WRITE);
    }
}

/////

///

static int

udp_socket_open() {
    struct addrinfo hints, *ai_list, *ai;

    int n, fd = 0, on = 1;

    char *port = "28900";

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_PASSIVE;

    hints.ai_family = AF_UNSPEC;

    hints.ai_socktype = SOCK_DGRAM;

    n = getaddrinfo(NULL, port, &hints, &ai_list);

    if (n) {
        fprintf(stderr, "%s: getaddrinfo failed: %s\n",

                progname, gai_strerror(n));

        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (fd < 0) {
            continue;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }

        close(fd);
    }

    freeaddrinfo(ai_list);

    if (ai == NULL) {
        fprintf(stderr, "%s: bind failed for port %s\n", progname, port);

        return -1;
    }

    return fd;
}

///

///

static int

udp_socket_close(int fd) {
    return close(fd);
}

///

/////

static void

udp_socket_main(evutil_socket_t evfd, short evwhat, void *evarg) {
    char message[UDP_BUFFER] = {0};

    struct sockaddr_storage from;

    socklen_t fromlen = sizeof(from);

    int n;

    /*
        unsigned long truelen = recv(evfd, message, sizeof(message), MSG_PEEK |
       MSG_TRUNC); //solution with PEEK/TRUNC

        if (truelen > UDP_BUFFER - 1) {

            truelen = UDP_BUFFER - 1;

            return; // we decide to just drop too big packets

        }
    */

    n = recvfrom(evfd, message, sizeof(message) - 1, 0,

                 (struct sockaddr *) &from, &fromlen);

    if (n == -1) {
        syslog(LOG_ERR, "recvfrom failed: %s", strerror(errno));

        goto endf;
    }

    char hoststr[MAX_HOST];

    char portstr[MAX_PORT];

    n = getnameinfo((struct sockaddr *) &from, fromlen,

                    hoststr, sizeof(hoststr), portstr, sizeof(portstr),

                    NI_NUMERICHOST | NI_DGRAM);

    if (n) {
        syslog(LOG_ERR, "getnameinfo failed: %s", gai_strerror(n));

    } else {
        // check for shutdown command (from 127.0.0.1)

        if ((strcmp(message, shutdown_com)) == 0 &&
            (strcmp(hoststr, admin_addr)) == 0) {
            event_base_loopbreak(evarg);
        }

        int i;
        for (i = 0; i < GS_MAX_NUM; i++) {
            if (gs_arr[i].status == 1) {
                unsigned int port_num = atoi(portstr);
                time_t justnow = time(NULL);

                if ((justnow - gs_arr[i].timestamp) > 2) {
                    gs_arr[i].status = 0;  // delete!
                }

                if ((strcmp(hoststr, gs_arr[i].addr)) == 0 &&
                    port_num == gs_arr[i].port) {
                    if ((strcmp(message, gs_arr[i].echokey)) == 0) {
                        gs_arr[i].status = 2;  // echo challenge test success!
                    } else {
                        gs_arr[i].status = 0;  // echo challenge test fail!
                    }
                }
            }
        }

    }  // else end

    // return - reactivating the event here

    endf:
    // struct event *uev;
    // uev = event_new(evarg, evfd, EV_READ, udp_socket_main, evarg);
    event_add(uev, NULL);
}

/////

/////

static void quick_shutdown(evutil_socket_t fd, short what, void *arg) {
    struct event_base *sev = arg;

    event_base_loopbreak(sev);
}

/////

/////

int

main(int argc, char *argv[]) {
    if (argc > 2) {
        fprintf(stderr, " usage: %s [--options] (try 'npsb --help')\n", progname);

        exit(EXIT_FAILURE);
    }

    if (argc == 2) {
        const char debug_arg[] = "--debug";

        const char silent_arg[] = "--silent";

        const char version_arg[] = "--version";

        const char help_arg[] = "--help";

        if ((strcmp(argv[1], debug_arg)) == 0) {
            running_mode = 0;  // debug mode

            printf(" program started\n");

        } else if ((strcmp(argv[1], silent_arg)) == 0) {
            running_mode = 1;  // silent mode

            printf(" program started\n");

        } else if ((strcmp(argv[1], version_arg)) == 0) {
            printf(" npms version 1.0\n");

            exit(EXIT_SUCCESS);

        } else if ((strcmp(argv[1], help_arg)) == 0) {
            printf(
                    " Listens to port 28900 for 'heartbeat' messages\n"

                    " from NetPanzer gameservers.\n"

                    " Provides a list of live games at the same port.\n"

                    " Works with NetPanzer version 0.8.7 and higher.\n\n"

                    " Usage:\n"

                    " [--debug]\n"

                    "    Lots of messages and logs.\n"

                    " [--silent]\n"

                    "    Just start and shutdown messages.\n"

                    " [--version]\n"

                    "    Prints version number and exits.\n"

                    " [--help]\n"

                    "    This! Check README for more information.\n\n"

                    " (if no arguments starts in [--debug] mode)\n\n"

            );

            exit(EXIT_SUCCESS);

        } else {
            fprintf(stderr, " usage: %s [--options] (try 'npsb --help')\n", progname);

            exit(EXIT_FAILURE);
        }

    }  // argc = 2

    if (argc == 1) {
        running_mode = 0;  // debug mode

        printf(" program started\n");
    }

    openlog(progname, LOG_PID, LOG_USER);

    syslog(LOG_NOTICE, "program started");

    evutil_socket_t listener;

    struct sockaddr_in sin;

    struct event_base *base;

    struct event *listener_event, *term, *term2, *term3, *term4;

    // init gs_arr

    int i;

    for (i = 0; i < GS_MAX_NUM; i++) {
        gs_arr[i].status = 0;
    }

    if (running_mode == 0) {
        syslog(LOG_NOTICE, "program started");

    } else if (running_mode == 1) {
        syslog(LOG_NOTICE, "program started as daemon");
    }

    base = event_base_new();

    if (!base) {
        return EXIT_FAILURE;
    }

    // signals mgmt

    term = evsignal_new(base, SIGTERM, quick_shutdown, base);

    evsignal_add(term, NULL);

    term2 = evsignal_new(base, SIGINT, quick_shutdown, base);

    evsignal_add(term2, NULL);

    term3 = evsignal_new(base, SIGHUP, quick_shutdown, base);

    evsignal_add(term3, NULL);

    term4 = evsignal_new(base, SIGQUIT, quick_shutdown, base);

    evsignal_add(term4, NULL);

    sin.sin_family = AF_INET;

    sin.sin_addr.s_addr = 0;

    sin.sin_port = htons(28900);

    listener = socket(AF_INET, SOCK_STREAM, 0);

    evutil_make_socket_nonblocking(listener);

    if (bind(listener, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("bind");

        return EXIT_FAILURE;
    }

    if (listen(listener, 16) < 0) {
        perror("listen");

        return EXIT_FAILURE;
    }

    listener_event =
            event_new(base, listener, EV_READ | EV_PERSIST, do_accept, (void *) base);

    event_add(listener_event, NULL);

    /// udp event / gets status array from gameservers

    ufd = udp_socket_open();

    if (ufd > -1) {
        uev = event_new(base, ufd, EV_READ, udp_socket_main, base);

        event_add(uev, NULL);

    } else {
        return EXIT_FAILURE;
    }

    // loop init and exiting stuff

    if (event_base_loop(base, 0) == -1) {
        goto end;
    }

    end:

    syslog(LOG_NOTICE, "shutting down");

    printf(" shutting down...\n");

    udp_socket_close(ufd);

    event_free(uev);

    event_free(listener_event);

    event_free(term);

    event_free(term2);

    event_free(term3);

    event_free(term4);

    event_base_free(base);

    closelog();

    libevent_global_shutdown();

    return EXIT_SUCCESS;
}
