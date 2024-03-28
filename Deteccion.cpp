#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Función para bloquear la dirección IP de origen del ataque
void blockIP(const in_addr* sourceIP) {
    // Ejecuta un comando de iptables para agregar una regla de bloqueo
    char command[256];
    snprintf(command, sizeof(command), "sudo iptables -A INPUT -s %s -j DROP", inet_ntoa(*sourceIP));
    system(command);
}

void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packetData) {
    struct ip* ipHeader;
    struct tcphdr* tcpHeader;

    ipHeader = (struct ip*)(packetData + sizeof(struct ether_header));
    tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ether_header) + sizeof(struct ip));

    // Filtra por puertos comúnmente utilizados por Nmap
    if (ntohs(tcpHeader->th_dport) == 80 || ntohs(tcpHeader->th_dport) == 443) {
        // Filtra por flags SYN para detectar escaneos Nmap
        if (tcpHeader->th_flags == (TH_SYN)) {
            std::cout << "Possible Nmap Scan Detected!" << std::endl;
            std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
            std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
            std::cout << "Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
            std::cout << std::endl;
            // Bloquea la dirección IP de origen del ataque
            blockIP(&ipHeader->ip_src);
            std::cout << "Ataque defendido con iptables." << std::endl;
            exit(0); // Termina el programa después de defender el ataque
        }
    }

    // Filtra por puertos o patrones específicos para hping3
    if (ntohs(tcpHeader->th_dport) == 8080) {
        std::cout << "Possible hping3 Activity Detected!" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
        std::cout << std::endl;
        // Bloquea la dirección IP de origen del ataque
        blockIP(&ipHeader->ip_src);
        std::cout << "Ataque defendido con iptables." << std::endl;
        exit(0); // Termina el programa después de defender el ataque
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle;

    // Abre la interfaz de red para capturar tráfico
    pcapHandle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // Cambia "enp0s3" a tu interfaz de red

    if (pcapHandle == NULL) {
        std::cerr << "Error al abrir la interfaz de red: " << errbuf << std::endl;
        return 1;
    }

    // Realiza la captura de paquetes
    pcap_loop(pcapHandle, -1, packetHandler, NULL);

    // Cierra el manejador de captura cuando hayas terminado
    pcap_close(pcapHandle);

    return 0;
}





hping3 -c 5 -p 80 -S 10.0.2.15
sudo nmap -PU -PA 10.0.2.5


DETECTA TODO

#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packetData) {
	struct ip* ipHeader;
	struct tcphdr* tcpHeader;

	ipHeader = (struct ip*)(packetData + sizeof(struct ether_header));
	tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ether_header) + sizeof(struct ip));

	// Imprime información sobre el paquete capturado
	std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
	std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
	std::cout << "Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
	std::cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
	std::cout << "Sequence Number: " << ntohl(tcpHeader->th_seq) << std::endl;
	std::cout << "Acknowledge Number: " << ntohl(tcpHeader->th_ack) << std::endl;
	std::cout << "Flags: " << std::hex << (int)tcpHeader->th_flags << std::endl;
	std::cout << "Data Length: " << pkthdr->len - sizeof(struct ether_header) - sizeof(struct ip) - (tcpHeader->th_off * 4) << std::endl;
	std::cout << std::endl;
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcapHandle;

	// Abre la interfaz de red para capturar tráfico
	pcapHandle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // Cambia "enp0s3" a tu interfaz de red

	if (pcapHandle == NULL) {
    	std::cerr << "Error al abrir la interfaz de red: " << errbuf << std::endl;
    	return 1;
	}

	// Realiza la captura de paquetes
	pcap_loop(pcapHandle, -1, packetHandler, NULL);

	// Cierra el manejador de captura cuando hayas terminado
	pcap_close(pcapHandle);

	return 0;
}

