#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cstdio>
#include <pcap.h>
#include <cstdlib>
#include "device.h"

/*
  gcc -lpcap sniffer.cpp -o sniffer 
  
  Project not completed ! 
  - the filter is hardcoded for now but will allow user input for it, for now it is hardcoded to sniff on port 23 (usually telnet).
  - the sniffing part has been coded in a single block of code, we will try and split this in multiple functions.
  - lack verbosity in the sniffing area, plus could potentially rework error messages.
  - not using pcap_loop() and pcap_dispatch() instead we're using pcap_next() (sniffers should avoid using this function) so for now 
       we're only capturing a single packet.
  - haven't implement anything related to the packet after it being captured (program captures a packet then hangs).
*/

static char* deviceNameInUse = nullptr;
pcap_if_t* deviceInUse = nullptr;

void ShowNetworkDevices(std::vector<pcap_if_t*> deviceList){
  if(deviceList.empty()){
    fprintf(stderr, "No devices are currently available, make sure you use 'getdevice' before using 'showdevices' or check your permissions.\n");
  };

  int deviceCount = 0;
  std::for_each(deviceList.begin(), deviceList.end(), [&](const pcap_if_t* t){
    printf("%d) %s %s", deviceCount+1, t->name, t->description != nullptr ? "- " : "\n");
    if(t->description != nullptr) printf("%s\n", t->description);
    deviceCount += 1;
  });
  return;
}

std::vector<char*> tokenizeInput(std::string const& input){
  std::vector<char*> output;
  char* token = strtok(const_cast<char*>(input.c_str()), " ");
  while(token != nullptr){
    output.push_back(token);
    token = strtok(NULL, " ");
  }
  return output;
}

bool checkDigits(char* &token){
  for(int i = 0; i < strlen(token); i++){
    if(!isdigit(token[i])) return false;
  }
  return true;
}

std::vector<pcap_if_t*> GetAllNetworkDevices(){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t* alldevs = nullptr;
  std::vector<pcap_if_t*> allDevicesVector;

  printf("Looking for devices...\n");
  
  pcap_findalldevs(&alldevs, errbuf);
  if(alldevs == NULL){
    fprintf(stderr, "Couldn't find any usable device.", errbuf);
    exit(-1);
  }

  for(int i = 0; alldevs != nullptr; alldevs = alldevs->next){
    allDevicesVector.push_back(alldevs);
  }

  printf("Found %d devices.\n", allDevicesVector.size());
  return allDevicesVector;
}

void clear(){
  system("clear");
}

void GetAllDeviceAddresses(std::vector<pcap_if_t*> device){
  std::for_each(device.begin(), device.end(), [&](pcap_if_t* dev){
    if(dev != nullptr){
      for(int i = 0; dev->addresses != nullptr; dev->addresses = dev->addresses->next, i++){
        struct sockaddr_in* sockstruct = (struct sockaddr_in*)dev->addresses->addr;
        char* ipaddr = inet_ntoa(sockstruct->sin_addr);
        printf("%s - %s\n", dev->name, ipaddr);
     }
    }
  });
}

void GetDeviceAddresses(pcap_if_t* device){
  for(int i = 0; device->addresses != nullptr; device->addresses = device->addresses->next, i++){
    struct sockaddr_in* sockstruct = (struct sockaddr_in*)device->addresses->addr;
    char* addr = inet_ntoa(sockstruct->sin_addr);
    printf("%s - %s\n", device->name, addr);
  }
}

char* GetDeviceAddress(pcap_if_t* device){
  struct sockaddr_in* sockstruct = (struct sockaddr_in*)device->addresses->addr;
  return inet_ntoa(sockstruct->sin_addr);
} 

pcap_t* startSniffing(pcap_if_t* device){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* dev_handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
  
  if(dev_handle == NULL){
    fprintf(stderr, "Couldn't open device %s\n", errbuf);
    return nullptr;
  }

  printf("Successfully opened device %s.\n", device->name);
  if(pcap_datalink(dev_handle) != DLT_EN10MB){
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\nFailed to open device for sniffing.\n", device);
    return nullptr;
  }

  return dev_handle;
}

bool useDevice(std::string& line, std::vector<pcap_if_t*> devicesList){
  std::vector<char*> tokenizedInput = tokenizeInput(line);
  if(checkDigits(tokenizedInput[1])){
    int deviceToken = std::stoi(tokenizedInput[1]);
    if(deviceToken <= devicesList.size() && deviceToken > 0){
      deviceInUse = devicesList[deviceToken - 1];
      deviceNameInUse = devicesList[deviceToken - 1]->name;
      printf("Currently using device %s.\n", deviceNameInUse);
      return true;
    } else {
      fprintf(stderr, "Couldn't find device %s, please check your syntax or if the device is present on the system.\n", tokenizedInput[1]);
      return false;
    }
  } else {
    fprintf(stderr, "Couldn't find device %s, please check your syntax or if the device is present on the system.\n", tokenizedInput[1]);
    return false;
  }
  return false;
}

int main(int argc, char** argv){
  std::string line;
  char* errbuf = nullptr;
  std::vector<pcap_if_t*> devicesList;
  pcap_t* deviceSessionHandle;

  clear();
  printf("Welcome in the Commandline Helper for Sniffer 1.0 ! Type 'help' for further informations.\n");

  while(true){
    printf("> ");
    std::getline(std::cin, line);
    if(line == "getdev") {
      devicesList = GetAllNetworkDevices();
    
    } else if(line == "showdev"){
        ShowNetworkDevices(devicesList);
    
    } else if(line == "getinfo"){
      GetDeviceAddresses(devicesList[0]);
    
    } else if(line == "getinfos"){
      GetAllDeviceAddresses(devicesList);
    
    } else if(line.rfind("use", 0) == 0){
      if(!useDevice(line, devicesList)) 
        fprintf(stderr, "Something went wrong while trying to change device, please try again.\n");
      
      } 
      else if(line == "startsniffing"){
        deviceSessionHandle = startSniffing((deviceInUse != nullptr ? deviceInUse : devicesList[0]));
        if(deviceSessionHandle != nullptr){
          struct bpf_program fp;
          char filter_exp[] = "port 23";
          bpf_u_int32 mask;
          bpf_u_int32 net;
          struct pcap_pkthdr header;
          const u_char *packet;
          if(pcap_lookupnet(deviceNameInUse, &net, &mask, errbuf) == -1){
            fprintf(stderr, "Couldn't open device %s: %s\n", deviceNameInUse, errbuf);
            return(2);
          }
          if(pcap_compile(deviceSessionHandle, &fp, filter_exp, 0, net) == -1){
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(deviceSessionHandle));
            return(2);
          }
          if(pcap_setfilter(deviceSessionHandle, &fp) == -1){
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(deviceSessionHandle));
            return(2);
          }

          packet = pcap_next(deviceSessionHandle, &header);
          printf("Jacked a packet with length of [%d]\n", header.len);
          pcap_close(deviceSessionHandle);
          return 0;
          
        // ready for sniffing
      } else{
        fprintf(stderr, "Invalid Command, Please try again.\n", errbuf);
      }
    line.clear();
    }
  }
  return 0;
}
