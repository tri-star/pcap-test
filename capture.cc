#include <iostream>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include <pcap.h>

void my_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char* argv[]) {
  
  char error_buffer[PCAP_ERRBUF_SIZE];
  char *dev = NULL;
  pcap_t *handle;
  
  if(argv[1] == NULL) {
    dev = "any";
  } else {
    dev = argv[1];
  }
  
  // pcap_open_liveの引数は以下の通り
  // - デバイス名
  // - キャプチャする最大長
  // - プロミスキャスモードにするかどうか
  // - 読み込みのタイムアウト(ミリ秒)
  // - エラーメッセージを格納するバッファ
  handle = pcap_open_live(dev, BUFSIZ, 0, -1, error_buffer);
  if(handle == NULL) {
    std::cout << "ERROR: " << error_buffer << std::endl;
    return 1;
  }
  
  struct bpf_program compiled_filter;
  char *filter = "port 3306 ";
  bpf_u_int32 mask;
  bpf_u_int32 address;
  
  pcap_lookupnet(dev, &address, &mask, error_buffer);
  
  if(pcap_compile(handle, &compiled_filter, filter, 0, address) == -1) {
    std::cout << "ERROR: pcap_compile error." << std::endl;
    return 1;
  }
  
  if(pcap_setfilter(handle, &compiled_filter) == -1) {
    std::cout << "ERROR: pcap_setfilter error." << std::endl;
    return 1;
  }
  
  pcap_loop(handle, 100, my_callback, (u_char*)handle);
  
  return 0;
}


void my_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  std::cout << "--- CAPTURED ----------------------------------------" << std::endl;
  pcap_t* handle = (pcap_t*)args;
  
  int packet_type = 0;
  packet_type = pcap_datalink(handle);
  struct ether_header *eth_header;
  struct iphdr *ip_header;
  struct in_addr bsd_address;
  struct tcphdr *tcp_header;
  u_char *payload;
  unsigned int payload_len = 0;
  
  const char *packet_type_name = NULL;
  switch(packet_type) {
    case DLT_EN10MB:
      std::cout << "Packet type: Normal" << std::endl;
      eth_header = (struct ether_header*)packet;
      
      if(ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        std::cout << "Protocol: " << ntohs(eth_header->ether_type) << ", Not IPv4. Skipped." << std::endl;
        break;
      }
      
      //IP Part
      ip_header = (struct iphdr*)(packet + sizeof(ether_header));
      if(ip_header->version != IPVERSION) {
        std::cout << "IP version: Not IPv4. Skipped." << std::endl;
        break;
      }
      
      bsd_address.s_addr = ip_header->saddr;
      std::cout << "SRC IP: " << inet_ntoa(bsd_address) << std::endl;
      bsd_address.s_addr = ip_header->daddr;
      std::cout << "DST IP: " << inet_ntoa(bsd_address) << std::endl;
      
      //TCP Part
      tcp_header = (struct tcphdr*)(packet + sizeof(ether_header) + (ip_header->ihl * 4));
      std::cout << "SRC PORT: " << ntohs(tcp_header->source) << std::endl;
      std::cout << "DST PORT: " << ntohs(tcp_header->dest) << std::endl;
      std::cout << "ACK SEQ: " << ntohl(tcp_header->ack_seq) << std::endl;
      std::cout << "FLAG: ";
      if(tcp_header->ack) {
        std::cout << "ACK,";
      }
      if(tcp_header->rst) {
        std::cout << "RST,";
      }
      if(tcp_header->syn) {
        std::cout << "SYN,";
      }
      if(tcp_header->fin) {
        std::cout << "fin,";
      }
      std::cout << std::endl;
      
      //DATA
      payload = (u_char*)(packet +  sizeof(ether_header) + (ip_header->ihl * 4) + (tcp_header->doff * 4));
      payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_header->doff * 4);
      
      std::cout << "DATA PART:" << std::endl;
      for(int i = 0; i < payload_len; i++) {
        if(payload[i] >= 0x20 && payload[i] <=0x7E) {
          std::cout << payload[i];
        } else {
          std::cout << "*";
        }
      }
      
      std::cout << payload << std::endl;
      break;
    
    case DLT_LINUX_SLL:
      std::cout << "Packet type: LINUX_SLL" << std::endl;
      break;
      
    default:
      packet_type_name = pcap_datalink_val_to_name(packet_type);
      if(packet_type_name == NULL) {
        std::cout << "Packet type: unknown" << std::endl;
      } else {
        std::cout << "Packet type: " << packet_type_name << std::endl;
      }
  }
  
}
