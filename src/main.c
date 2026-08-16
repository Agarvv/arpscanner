#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <net/if.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>

int main(int argc, char** argv) {

    if(argc != 2) {
        printf("Error: Expected interface argument.\n");
        return -1;
    }

    // socket file descriptor
    int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(sfd == -1) {
        perror("Error in Socket Creation");
    }

    

    struct sockaddr_ll addr;
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex(argv[1]);
    addr.sll_halen    = ETH_ALEN;
    memset(addr.sll_addr, 0xff, 6);

    struct ifreq ireq;
    memcpy(ireq.ifr_name, argv[1], strlen(argv[1]));
      unsigned char frame[42] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination mac (broadcast)
    }; 

    ioctl(sfd, SIOCGIFNETMASK, &ireq);
  
        printf("%d.%d.%d.%d\n",
           (unsigned char)ireq.ifr_netmask.sa_data[2],
           (unsigned char)ireq.ifr_netmask.sa_data[3],
           (unsigned char)ireq.ifr_netmask.sa_data[4],
           (unsigned char)ireq.ifr_netmask.sa_data[5]);  
	unsigned int inet_mask;
    
   unsigned int *range = (unsigned int*)(&(ireq.ifr_netmask.sa_data[2]));
   inet_mask = *range;

    unsigned int n = (0xffffffff - ntohl(*range) - 1); // avoid ARP to Broadcast address
    ioctl(sfd, SIOCGIFHWADDR, &ireq);
        // source mac
    memcpy(&(frame[6]), ireq.ifr_hwaddr.sa_data, 6);

    // Sender hardware address
    memcpy(&(frame[22]), ireq.ifr_hwaddr.sa_data, 6);

    printf(
    "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned char)ireq.ifr_hwaddr.sa_data[0],
    (unsigned char)ireq.ifr_hwaddr.sa_data[1],
    (unsigned char)ireq.ifr_hwaddr.sa_data[2],
    (unsigned char)ireq.ifr_hwaddr.sa_data[3],
    (unsigned char)ireq.ifr_hwaddr.sa_data[4],
    (unsigned char)ireq.ifr_hwaddr.sa_data[5]
);


    ioctl(sfd, SIOCGIFADDR, &ireq);

    struct sockaddr_in *ip =
    (struct sockaddr_in *)&ireq.ifr_addr;

printf(
    "IP: %s\n",
    inet_ntoa(ip->sin_addr)
);

    // 14 Bytes of Ethernet frame.

    // 12 bytes for destination MAC and source MAC
    // 2 Bytes for Ether Type.

    // ARP packet starts at index 14.

    // then the ARP packet is 28 Bytes.

    // 2 bytes for hardware type, in this case, 1. which means ethernet.

    // 2 bytes for protocol type. in this case, 0x0800. which means IPv4.

    // 1 byte for HLEN, which means Hardware length in bytes. in this case, 6. since we are working with MAC Adresses.

    // 1 byte for PLEN which means protocol address to be resolved length. in our case, 4. since we are working with IPv4.

    // 2 Bytes for OPER. which identifies the ARP operation

    // 6 bytes for SHA (sender hardware address)

    // 4 bytes for SPA (sender protocol address)

    // 6 bytes for THA  (target hardware address)

    // 4 bytes for TPA (target protocol address)

    // 18 Bytes of Padding like that we avoid this frame to be a runt.



    /*
    frame[6] = 0xff; //ireq.ifr_hwaddr.sa_data[0];
    frame[7] = ireq.ifr_hwaddr.sa_data[1];
    frame[8] = ireq.ifr_hwaddr.sa_data[2];
    frame[9] = ireq.ifr_hwaddr.sa_data[3];
    frame[10] = ireq.ifr_hwaddr.sa_data[4];
    frame[11] = ireq.ifr_hwaddr.sa_data[5];
    */

    /*
    frame[7] = 0x3b;
    frame[8] = 0x70;

    frame[9] = 0x3e;
    frame[10] = 0x8a;
    frame[11] = 0x31;
    */


    // ethertype
    frame[12] = 0x08;
    frame[13] = 0x06;

    // hardware type
    frame[14] = 0x00;
    frame[15] = 0x01;

    // protocol type (ipv4)
    frame[16] = 0x08;
    frame[17] = 0x00;

    // HLEN
    frame[18] = 0x06;

    // protocol len
    frame[19] = 0x04;

    // ARP operation (request)
    frame[20] = 0x00;
    frame[21] = 0x01;

    /*

    frame[6] = ireq.ifr_hwaddr.sa_data[0];
    frame[7] = ireq.ifr_hwaddr.sa_data[1];
    frame[8] = ireq.ifr_hwaddr.sa_data[2];
    frame[9] = ireq.ifr_hwaddr.sa_data[3];
    frame[10] = ireq.ifr_hwaddr.sa_data[4];
    frame[11] = ireq.ifr_hwaddr.sa_data[5];

    */


    // sender protocol address
    memcpy(&(frame[28]), &(ireq.ifr_addr.sa_data[2]), 4);
    


    // target hardware address (not known)
    memset(&(frame[32]), 0x00, 6);

    // target protocol address
    /*
    unsigned char target[4] = {
        192, 168, 1, 254
    };
    */


    unsigned int* iface_addr = (unsigned int*)(&(ireq.ifr_addr.sa_data[2]));
    

    unsigned int net_addr = ((ntohl(*iface_addr) & ntohl(inet_mask)) + 1); // avoid arp to network address 
    printf("net addrrrr: %u\n", (net_addr & 0xff000000) >> 24);



     for (int i = 0; i < 4; i++) {
        unsigned char byte =
            (unsigned char)ireq.ifr_addr.sa_data[2 + i];

        printf("byte[%d] = %u\n", i, byte);
    }


    while(n != 0) {
    
    
   
    // memcpy(&(frame[38]), target, 4);
    frame[38] = (unsigned char)((net_addr & 0xff000000) >> 24);
    frame[39] = (unsigned char)((net_addr & 0x00ff0000) >> 16); 
    frame[40] = (unsigned char)((net_addr & 0x0000ff00) >> 8); 
    frame[41] = (unsigned char)net_addr & 0x000000ff;

    net_addr  = net_addr + 1;

    printf("net addr; %u \n", net_addr);




    // padding
    //memset(&(frame[42]), 0x00, 18);


    sendto(sfd, frame, sizeof(frame), 0, (struct sockaddr *)&addr, sizeof(addr)); 


     n = n - 1;
    }

}
