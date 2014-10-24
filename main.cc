#include <iostream>

//inet_ntoa()
#include <arpa/inet.h>

#include <pcap.h>


void print_addresses(pcap_addr_t *address) {
  struct sockaddr_in *sock_address;
  while(address != NULL) {
    sock_address = (struct sockaddr_in*)address->addr;
    if(sock_address->sin_family != AF_INET) {
      address = address->next;
      continue;
    }
    std::cout << " - Address: " << inet_ntoa(sock_address->sin_addr) << std::endl;
    address = address->next;
  }
}

int main(int argc, char* argv[]) {
  
  char error_buffer[PCAP_ERRBUF_SIZE];
  int result = 0;
  pcap_if_t *device_list = NULL;
  
  result = pcap_findalldevs(&device_list, error_buffer);
  if(result != 0) {
    std::cout << error_buffer << std::endl;
    return 1;
  }
  
  pcap_if_t *device = device_list;
  while(device != NULL) {
    std::cout << "-----------" << std::endl;
    std::cout << "Device: " << device->name << std::endl;
    if(device->description != NULL) {
      std::cout << " - Description: " << device->description << std::endl;
    }
    if(device->addresses != NULL) {
      print_addresses(device->addresses);
    }
    std::cout << std::endl;
    device = device->next;
  }
  
  pcap_freealldevs(device_list);
  
  return 0;
}
