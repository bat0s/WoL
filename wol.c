#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <arpa/inet.h>

#define error(...) \
do { (fprintf (stderr, "\x1B[31m[ERROR] (%s: %d: %s) ", __FILE__, __LINE__, __func__), fprintf (stderr, __VA_ARGS__), fputs ("\x1b[0m\n", stderr)); exit (EXIT_FAILURE); } while (0)

#define dprintf(...) (printf ("\x1B[34m[DEBUG] (%s: %d: %s) ", __FILE__, __LINE__, __func__), printf (__VA_ARGS__), puts ("\x1b[0m"));

#ifdef __APPLE__
    #include <sys/sysctl.h>
    #include <net/route.h>
    #include <netinet/if_ether.h>
    #include <net/if_dl.h>

    static inline char* __attribute__ ((malloc)) malloc_s (size_t size)
    {
        if (size <= 0)  error("size must be > 0");
    
        char* ptr = (char *) malloc (sizeof (char) * size);
    
        if (ptr == NULL)    error ("Failed to allocate memory.");
    
        return ptr;
    }

    #define	ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof (uint32_t) - 1))) : \
        sizeof (uint32_t))
#endif

static unsigned char* mac_from_ipv6 (struct in6_addr* addr)
{
#ifdef __APPLE__
    int mib[6];
    size_t needed;
    char* buf, *next;
    struct rt_msghdr* rtm;
    struct sockaddr_in6* sin;
    struct sockaddr_dl* sdl;
    
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET6;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;
    
    if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0)    error ("route-sysctl-estimate");
    
    buf = malloc_s (needed);
    
    if (sysctl (mib, 6, buf, &needed, NULL, 0) < 0)
    {
        free (buf);
        error ("actual retrieval of routing table.");
    }

    for (next = buf; next && next < buf + needed; next += rtm -> rtm_msglen)
    {
        rtm = (struct rt_msghdr *)(void *) next;
        sin = (struct sockaddr_in6 *)(rtm + 1);
        sdl = (struct sockaddr_dl *)(void *) ((char *) sin + ROUNDUP (sin -> sin6_len));
        
        if (sdl -> sdl_family != AF_LINK)
            continue;
        
        if (addr && !IN6_ARE_ADDR_EQUAL (addr, &sin -> sin6_addr))
            continue;
        
        return (unsigned char *) LLADDR (sdl);
    }
    
    free (buf);
    error ("Not found.");
#endif
    
#ifdef __linux__
    error ("Not implemented. (/proc/net/arp) like neighbor table not exists.");
#endif
}

static unsigned char* mac_from_ipv4 (struct in_addr* addr)
{
#ifdef __APPLE__
    int mib[6];
    size_t needed;
    char* buf, *next;
    struct rt_msghdr* rtm;
    struct sockaddr_inarp* sin;
    struct sockaddr_dl* sdl;
    
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;
    
    if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0)    error ("route-sysctl-estimate");
    
    buf = malloc_s (needed);
    
    if (sysctl (mib, 6, buf, &needed, NULL, 0) < 0)
    {
        free (buf);
        error ("actual retrieval of routing table.");
    }

    for (next = buf; next && next < buf + needed; next += rtm -> rtm_msglen)
    {
        rtm = (struct rt_msghdr *)(void *) next;
        sin = (struct sockaddr_inarp *) (rtm + 1);
        sdl = (struct sockaddr_dl *)(void *) ((char *) sin + ROUNDUP (sin -> sin_len));
        
        if (addr && addr -> s_addr != sin -> sin_addr.s_addr)
            continue;
        
        return (unsigned char *) LLADDR (sdl);
    }
    
    free (buf);
    error ("Not found.");
#endif
    
#ifdef __linux__
    FILE* arp = fopen ("/proc/net/arp", "r");
    
    if (arp == NULL)    error ("Failed to open file (/proc/net/arp)");
    
    unsigned int* macstr = (unsigned int *) malloc (6 * sizeof (unsigned int));
    
    if (macstr == NULL)    error ("Failed to allocate memory.");
    
    char line [256], str [INET_ADDRSTRLEN];

    if (inet_ntop (AF_INET, &(addr -> s_addr), str, INET_ADDRSTRLEN) == NULL)  error ("inet_ntop");
    
    while (fgets (line, sizeof (line), arp) != NULL)
    {
        if (strstr (line, str) != NULL && sscanf (line, "%*s 0x%*d 0x%*d %02X:%02X:%02X:%02X:%02X:%02X", &macstr[0], &macstr[1], &macstr[2], &macstr[3], &macstr[4], &macstr[5]) == 6)
        {
            (void) fclose (arp);
            return (unsigned char *) macstr;
        }
    }
    
    (void) fclose (arp);
    free (macstr);
    error ("Not found.");
#endif
}

static void send_wol (const char* bcast, unsigned long port, bool ipv6)
{
    int sock, i;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    unsigned char packet[102];
    
    if ((sock = socket (ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        error ("Cannot open socket.");
    
    if (ipv6)
    {
        memset (&addr6, '\0', sizeof (struct sockaddr_in6));
        addr6.sin6_family = AF_INET6;
        if (inet_pton (AF_INET6, bcast, &(addr6.sin6_addr)) != 1)   error ("Invalid IPv6 address.");
        addr6.sin6_port = htons (port);
    }
    
    else
    {
        memset (&addr, '\0', sizeof (struct sockaddr_in));
        addr.sin_family = AF_INET;
        if (inet_pton (AF_INET, bcast, &(addr.sin_addr)) != 1)   error ("Invalid IPv4 address.");
        addr.sin_port = htons (port);
    }
    
    memset(packet, 0xFF, 6);
    
    unsigned char* mac_addr = ipv6 ? mac_from_ipv6 (&addr6.sin6_addr) : mac_from_ipv4 (&addr.sin_addr);
    
    for (i = 1; i < 17; ++i)
    {
        packet[i * 6] = mac_addr[0];
        packet[i * 6 + 1] = mac_addr[1];
        packet[i * 6 + 2] = mac_addr[2];
        packet[i * 6 + 3] = mac_addr[3];
        packet[i * 6 + 4] = mac_addr[4];
        packet[i * 6 + 5] = mac_addr[5];
    }
    
    #ifdef __linux__
        free (mac_addr);
    #endif
    
    if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (int []) { 1 }, sizeof (int)) < 0)
    {
        (void) close (sock);
        error ("Cannot set socket options.");
    }
    
    if (sendto (sock, packet, sizeof (packet), 0, ipv6 ? (struct sockaddr *) &addr6 : (struct sockaddr *) &addr, ipv6 ? sizeof (addr6) : sizeof (addr)) < 0)
    {
        (void) close (sock);
        error ("Cannot send data.");
    }
    
    (void) close (sock);
    dprintf ("Sent WOL (Wake on LAN) magic packet to (%s:%lu)", bcast, port);
}

static void __attribute__ ((noreturn)) usage (const char* name)
{
    dprintf ("Usage: %s [-4 <IPv4 broadcast>] [-6 <IPv6 broadcast>] [-p <port>]", name);
    exit (EXIT_FAILURE);
}

int main (int argc, char* argv[])
{
    unsigned long port = 9;
    int c;
    bool ipv6 = false;
    const char* bcast = "255.255.255.255";
    
    if (argc < 3)   usage (argv[0]);
    
    while ((c = getopt (argc, argv, "h4:6:p:")) != EOF)
    {
        switch (c)
        {
            case 'h':
                usage (argv[0]);
            case '4':   bcast = optarg;
                break;
            case '6':   bcast = optarg;
                ipv6 = true;
                break;
            case 'p':   port = strtoul (optarg, NULL, 0);
                if (port == 0)  error ("port == 0");
                break;
            case '?':
                usage (argv[0]);
            default:
                usage (argv[0]);
        }
    }
    
    send_wol (bcast, port, ipv6);
}
