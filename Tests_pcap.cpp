/*
The MIT License (MIT)

Copyright (c) 2015 Manu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define HAVE_REMOTE
#include <pcap.h>


// Structure to represent an ip address in the ip header of the netpacket
struct ip_address
{
  union 
  {
    struct { unsigned char byte1, byte2, byte3, byte4; }bytes;
    unsigned int data;
  };
  ip_address():data(0){}
};

// ///////////////////////////////////////////////////////////////////////
/* IPv4 header */
#pragma pack(push)
#pragma pack(1)
struct ip_header{
  u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
  u_char  tos;            // Type of service 
  u_short tlen;           // Total length 
  u_short identification; // Identification
  u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;            // Time to live
  u_char  proto;          // Protocol
  u_short crc;            // Header checksum
  ip_address  saddr;      // Source address
  ip_address  daddr;      // Destination address
  u_int   op_pad;         // Option + Padding

  int ip_len(){ return (ver_ihl & 0xf) * 4; }
  bool is_udp(){ return proto == 17; }
};

/* UDP header*/
struct udp_header{
  u_short sport;          // Source port
  u_short dport;          // Destination port
  u_short len;            // Datagram length
  u_short crc;            // Checksum
};
#pragma pack(pop)

int isBigEndian(void)
{
  union {
    unsigned int i;
    char c[4];
  } bint = {0x01020304};

  return bint.c[0] == 1; 
}

u_short getChecksum(const u_char* netPacketData)
{
  ip_header* ih = (ip_header *) ( netPacketData );
  return ih->crc;
}

int offsetToCigiData( const u_char* netPacketData )
{
  // ip header(variable ~20) and udp header (8)
  ip_header* ih = (ip_header *) ( netPacketData );
  if ( !ih->is_udp() )
    return -1;
  return ih->ip_len() + sizeof(udp_header);
}

bool extractIPAdresses( const u_char* netPacketData, ip_address& src, ip_address& dst )
{
  ip_header* ih = (ip_header*)(netPacketData);
  src = ih->saddr;
  dst = ih->daddr;
  // first 3 bits in flags_fo indicates fragmentation type, if 1 then it's fragmented.
  int flags = isBigEndian() ? (ih->flags_fo & 0xe000)>>16 : (ih->flags_fo & 0x700)>>8;
  return flags==1;
}

int timeval_subtract(timeval* result, timeval* x, timeval* y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) 
  {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) 
  {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait. tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

int main(int argc, char **argv)
{
  pcap_t *fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  char source[PCAP_BUF_SIZE];
  struct pcap_pkthdr *header;
  const u_char *pkt_data;
  u_int i=0;
  int res;
  
  /* Create the source string according to the new WinPcap syntax */
  if ( pcap_createsrcstr( source,         // variable that will keep the source string
    PCAP_SRC_FILE,      // we want to open a file
    NULL,               // remote host
    NULL,               // port on the remote host
    "ipdumpfile.pcap",  // name of the file we want to open
    errbuf              // error buffer
    ) != 0)
  {
    fprintf(stderr,"\nError creating a source string\n");
    return -1;
  }

  /* Open the capture file */
  if ( (fp= pcap_open(source,         // name of the device
    65536,          // portion of the packet to capture
    // 65536 guarantees that the whole packet will be captured on all the link layers
    PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
    1000,              // read timeout
    NULL,              // authentication on the remote machine
    errbuf         // error buffer
    ) ) == NULL)
  {
    fprintf(stderr,"\nUnable to open the file %s.\n", source);
    return -1;
  }

  /*
  bpf_program fcode;
  if ( pcap_compile(fp, &fcode, "udp and ip.checksum!=0", 1, 0xffffff) >= 0 )
  {
    if ( pcap_setfilter(fp, &fcode) < 0 )
    {
      fprintf(stderr,"\nError creating filter for cigi\n" );
      return -1;
    }
  }*/
  
  /* Retrieve the packets from the file */
  long firstTime=0;
  timeval lastTime={0};
  unsigned long frameNo=0;
  bool ignoreNullChecksum=true;
  while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
  {
    if ( ignoreNullChecksum && getChecksum(pkt_data)==0 )
      continue;
    /* print pkt timestamp and pkt len */
    int offsetToCigi = offsetToCigiData(pkt_data);
    if ( offsetToCigi != -1 )
    {
      if ( firstTime == 0 )
      {
        firstTime = header->ts.tv_sec;
        lastTime = header->ts;
      }
      int cigiSize = header->caplen - offsetToCigi;
      timeval delta; timeval_subtract(&delta, &header->ts, &lastTime);
      int alignR=5;
      printf("[%ld] [%*ld] %ld:%*ld\tdt(%ld:%*ld)\tCigi(%*ld)\n", 
        frameNo, alignR, header->caplen, 
        header->ts.tv_sec-firstTime, alignR, header->ts.tv_usec, 
        delta.tv_sec, alignR, delta.tv_usec, 
        alignR, cigiSize );
      lastTime = header->ts;
    }
    ++frameNo;
    if ( frameNo > 50 ) break;
  }


  if (res == -1)
  {
    printf("Error reading the packets: %s\n", pcap_geterr(fp));
  }

  return 0;
}
