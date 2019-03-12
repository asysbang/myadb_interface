//============================================================================
// Name        : aaaa.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================


#include "stdafx.h"
using namespace std;

const GUID kAdbInterfaceId = ANDROID_USB_CLASS_ID;

// Number of interfaces detected in TestEnumInterfaces.
int interface_count = 0;

// Constants used to initialize a "handshake" message
#define MAX_PAYLOAD 4096
#define A_SYNC 0x434e5953
#define A_CNXN 0x4e584e43
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257
#define A_AUTH 0x48545541
#define A_VERSION 0x01000000

// AUTH packets first argument
#define ADB_AUTH_TOKEN         1
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3

// Interface descriptor constants for ADB interface
#define ADB_CLASS              0xff
#define ADB_SUBCLASS           0x42
#define ADB_PROTOCOL           0x1

// Formats message sent to USB device
struct message {
    unsigned int command;       /* command identifier constant      */
    unsigned int arg0;          /* first argument                   */
    unsigned int arg1;          /* second argument                  */
    unsigned int data_length;   /* length of payload (0 is allowed) */
    unsigned int data_crc32;    /* crc32 of data payload            */
    unsigned int magic;         /* command ^ 0xffffffff             */
};

bool TestInterfaceName(ADBAPIHANDLE interface_handle) {
  bool ret = true;
  unsigned long intr_name_size = 0;
  char* buf = NULL;

  if (AdbGetInterfaceName(interface_handle, NULL, &intr_name_size, true)) {
    printf("\n--- AdbGetInterfaceName unexpectedly succeeded %u",
           GetLastError());
    ret = false;
  }
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    printf("\n--- AdbGetInterfaceName failure %u", GetLastError());
    ret = false;

  }
  if (intr_name_size == 0) {
    printf("\n--- AdbGetInterfaceName returned name size of zero");
    ret = false;

  }

  const size_t buf_size = intr_name_size + 16; // extra in case of overwrite
  buf = reinterpret_cast<char*>(malloc(buf_size));
  if (buf == NULL) {
    printf("\n--- could not malloc %d bytes, errno %u", buf_size, errno);
    ret = false;
  }
  const char buf_fill = (unsigned char)0xFF;
  memset(buf, buf_fill, buf_size);

  if (!AdbGetInterfaceName(interface_handle, buf, &intr_name_size, true)) {
    printf("\n--- AdbGetInterfaceName failure %u", GetLastError());
    ret = false;

  }
  if (buf[intr_name_size - 1] != '\0') {
    printf("\n--- AdbGetInterfaceName returned non-NULL terminated string");
    ret = false;

  }
  for (size_t i = intr_name_size; i < buf_size; ++i) {
    if (buf[i] != buf_fill) {
      printf("\n--- AdbGetInterfaceName overwrote past the end of the buffer at"
             " index %u with 0x%02X", i, (unsigned char)buf[i]);
      ret = false;

    }
  }

  printf("\n+++ Interface name %s", buf);

  return ret;
}

void DumpEndpointInformation(const AdbEndpointInformation* pipe_info) {
  printf("\n          max_packet_size   = %u", pipe_info->max_packet_size);
  printf("\n          max_transfer_size = %u", pipe_info->max_transfer_size);
  printf("\n          endpoint_type     = %u", pipe_info->endpoint_type);
  const char* endpoint_type_desc = NULL;
  switch (pipe_info->endpoint_type) {
#define CASE_TYPE(type) case type: endpoint_type_desc = #type; break
    CASE_TYPE(AdbEndpointTypeInvalid);
    CASE_TYPE(AdbEndpointTypeControl);
    CASE_TYPE(AdbEndpointTypeIsochronous);
    CASE_TYPE(AdbEndpointTypeBulk);
    CASE_TYPE(AdbEndpointTypeInterrupt);
#undef CASE_TYPE
  }
  if (endpoint_type_desc != NULL) {
    printf(" (%s)", endpoint_type_desc);
  }
  printf("\n          endpoint_address  = %02X", pipe_info->endpoint_address);
  printf("\n          polling_interval  = %u", pipe_info->polling_interval);
  printf("\n          setting_index     = %u", pipe_info->setting_index);
}

void HexDump(const void* data, const size_t read_bytes) {
  const unsigned char* buf = reinterpret_cast<const unsigned char*>(data);
  const size_t line_length = 16;
  for (size_t n = 0; n < read_bytes; n += line_length) {
    const unsigned char* line = &buf[n];
    const size_t max_line = min(line_length, read_bytes - n);

    printf("\n          ");
    for (size_t i = 0; i < line_length; ++i) {
      if (i >= max_line) {
        printf("   ");
      } else {
        printf("%02X ", line[i]);
      }
    }
    printf(" ");
    for (size_t i = 0; i < max_line; ++i) {
      if (isprint(line[i])) {
        printf("%c", line[i]);
      } else {
        printf(".");
      }
    }
  }
}

void DumpMessageArg0(unsigned int command, unsigned int arg0) {
  if (command == A_AUTH) {
    const char* desc = NULL;
    switch (arg0) {
#define CASE_ARG0(arg) case arg: desc = # arg; break
      CASE_ARG0(ADB_AUTH_TOKEN);
      CASE_ARG0(ADB_AUTH_SIGNATURE);
      CASE_ARG0(ADB_AUTH_RSAPUBLICKEY);
#undef CASE_ARG0
    }
    if (desc != NULL) {
      printf(" (%s)", desc);
    }
  }
}

bool DeviceHandShake(ADBAPIHANDLE adb_interface) {
  // Get interface name
  char interf_name[512];
  unsigned long name_size = sizeof(interf_name);
  if (!AdbGetInterfaceName(adb_interface, interf_name, &name_size, true)) {
    printf("\nDeviceHandShake: AdbGetInterfaceName returned error %u",
           GetLastError());
    return false;
  }

  printf("\n\nDeviceHandShake on %s", interf_name);

  char* ser_num = NULL;
  name_size = 0;
  if (!AdbGetSerialNumber(adb_interface, ser_num, &name_size, true)) {
    ser_num = reinterpret_cast<char*>(malloc(name_size));
    if (NULL != ser_num) {
      if (!AdbGetSerialNumber(adb_interface, ser_num, &name_size, true)) {
        printf("\n      AdbGetSerialNumber returned error %u", GetLastError());
        AdbCloseHandle(adb_interface);
        return false;
      }
      printf("\nInterface serial number is %s", ser_num);
      free(ser_num);
    }
  }

  // Get default read endpoint
  ADBAPIHANDLE adb_read = AdbOpenDefaultBulkReadEndpoint(adb_interface,
                                                         AdbOpenAccessTypeReadWrite,
                                                         AdbOpenSharingModeReadWrite);
  if (NULL == adb_read) {
    printf("\n      AdbOpenDefaultBulkReadEndpoint returned error %u", GetLastError());
    return false;
  }

  // Get default write endpoint
  ADBAPIHANDLE adb_write = AdbOpenDefaultBulkWriteEndpoint(adb_interface,
                                                           AdbOpenAccessTypeReadWrite,
                                                           AdbOpenSharingModeReadWrite);
  if (NULL == adb_write) {
    printf("\n      AdbOpenDefaultBulkWriteEndpoint returned error %u", GetLastError());
    AdbCloseHandle(adb_read);
    return false;
  }

  // Send connect message
  message msg_send;
  msg_send.command = A_CNXN;
  msg_send.arg0 = A_VERSION;
  msg_send.arg1 = MAX_PAYLOAD;
  msg_send.data_length = 0;
  msg_send.data_crc32 = 0;
  msg_send.magic = msg_send.command ^ 0xffffffff;

  ULONG written_bytes = 0;
  bool write_res = AdbWriteEndpointSync(adb_write, &msg_send, sizeof(msg_send), &written_bytes, 500);
  if (!write_res) {
    printf("\n       AdbWriteEndpointSync returned error %u", GetLastError());
    AdbCloseHandle(adb_write);
    AdbCloseHandle(adb_read);
    return false;
  }

  // Receive handshake
  message msg_rcv;
  ULONG read_bytes = 0;
  bool read_res = AdbReadEndpointSync(adb_read, &msg_rcv, sizeof(msg_rcv), &read_bytes, 512);
  if (!read_res) {
    printf("\n       AdbReadEndpointSync returned error %u", GetLastError());
    AdbCloseHandle(adb_write);
    AdbCloseHandle(adb_read);
    return false;
  }

  printf("\n      Read handshake: %u bytes received", read_bytes);
  char* cmd_ansi = reinterpret_cast<char*>(&msg_rcv.command);
  printf("\n         command     = %08X (%c%c%c%c)", msg_rcv.command,
         cmd_ansi[0], cmd_ansi[1], cmd_ansi[2], cmd_ansi[3]);
  printf("\n         arg0        = %08X", msg_rcv.arg0);
  DumpMessageArg0(msg_rcv.command, msg_rcv.arg0);
  printf("\n         arg1        = %08X", msg_rcv.arg1);
  printf("\n         data_length = %u", msg_rcv.data_length);
  printf("\n         data_crc32  = %08X", msg_rcv.data_crc32);
  printf("\n         magic       = %08X", msg_rcv.magic);
  printf(" (%s)", (msg_rcv.magic == (msg_rcv.command ^ 0xffffffff)) ?
           "valid" : "invalid");

  if (0 != msg_rcv.data_length) {
    char* buf = reinterpret_cast<char*>(malloc(msg_rcv.data_length));
    read_res = AdbReadEndpointSync(adb_read, buf, msg_rcv.data_length, &read_bytes, 512);
    if (!read_res) {
      printf("\n       AdbReadEndpointSync (data) returned error %u", GetLastError());
      free(buf);
      AdbCloseHandle(adb_write);
      AdbCloseHandle(adb_read);
      return false;
    }

    HexDump(buf, read_bytes);

    free(buf);
  }

  if (!AdbCloseHandle(adb_write)) {
    printf("\n--- AdbCloseHandle failure %u", GetLastError());
  }
  if (!AdbCloseHandle(adb_read)) {
    printf("\n--- AdbCloseHandle failure %u", GetLastError());
  }

  return true;
}


bool TestInterfaceHandle(ADBAPIHANDLE interface_handle) {
  // Get interface name.
  if (!TestInterfaceName(interface_handle)) {
    return false;
  }

  // Get device descriptor for the interface
  USB_DEVICE_DESCRIPTOR dev_desc;
  if (AdbGetUsbDeviceDescriptor(interface_handle, &dev_desc)) {
    printf("\n+++ Device descriptor:");
    printf("\n        bLength            = %u", dev_desc.bLength);
    printf("\n        bDescriptorType    = %u", dev_desc.bDescriptorType);
    printf("\n        bcdUSB             = %u", dev_desc.bcdUSB);
    printf("\n        bDeviceClass       = %u", dev_desc.bDeviceClass);
    printf("\n        bDeviceSubClass    = %u", dev_desc.bDeviceSubClass);
    printf("\n        bDeviceProtocol    = %u", dev_desc.bDeviceProtocol);
    printf("\n        bMaxPacketSize0    = %u", dev_desc.bMaxPacketSize0);
    printf("\n        idVendor           = %X", dev_desc.idVendor);
    printf("\n        idProduct          = %X", dev_desc.idProduct);
    printf("\n        bcdDevice          = %u", dev_desc.bcdDevice);
    printf("\n        iManufacturer      = %u", dev_desc.iManufacturer);
    printf("\n        iProduct           = %u", dev_desc.iProduct);
    printf("\n        iSerialNumber      = %u", dev_desc.iSerialNumber);
    printf("\n        bNumConfigurations = %u", dev_desc.bNumConfigurations);
  } else {
    printf("\n--- AdbGetUsbDeviceDescriptor failure %u", GetLastError());
    return false;
  }

  // Get configuration descriptor for the interface
  USB_CONFIGURATION_DESCRIPTOR config_desc;
  if (AdbGetUsbConfigurationDescriptor(interface_handle, &config_desc)) {
    printf("\n+++ Configuration descriptor:");
    printf("\n        bLength             = %u", config_desc.bLength);
    printf("\n        bDescriptorType     = %u", config_desc.bDescriptorType);
    printf("\n        wTotalLength        = %u", config_desc.wTotalLength);
    printf("\n        bNumInterfaces      = %u", config_desc.bNumInterfaces);
    printf("\n        bConfigurationValue = %u", config_desc.bConfigurationValue);
    printf("\n        iConfiguration      = %u", config_desc.iConfiguration);
    printf("\n        bmAttributes        = %u", config_desc.bmAttributes);
    printf("\n        MaxPower            = %u", config_desc.MaxPower);
  } else {
    printf("\n--- AdbGetUsbConfigurationDescriptor failure %u", GetLastError());
    return false;
  }

  // Get device serial number
  char ser_num[1024];
  unsigned long ser_num_size = sizeof(ser_num);
  if (AdbGetSerialNumber(interface_handle, ser_num, &ser_num_size, true)) {
    printf("\n+++ Serial number: %s", ser_num);
  } else {
    printf("\n--- AdbGetSerialNumber failure %u", GetLastError());
    return false;
  }

  // Get interface descriptor
  USB_INTERFACE_DESCRIPTOR intr_desc;
  if (AdbGetUsbInterfaceDescriptor(interface_handle, &intr_desc)) {
    printf("\n+++ Interface descriptor:");
    printf("\n        bDescriptorType    = %u", intr_desc.bDescriptorType);
    printf("\n        bInterfaceNumber   = %u", intr_desc.bInterfaceNumber);
    printf("\n        bAlternateSetting  = %u", intr_desc.bAlternateSetting);
    printf("\n        bNumEndpoints      = %u", intr_desc.bNumEndpoints);
    printf("\n        bInterfaceClass    = %u", intr_desc.bInterfaceClass);
    if (intr_desc.bInterfaceClass == ADB_CLASS) {
      printf(" (ADB_CLASS)");
    }
    printf("\n        bInterfaceSubClass = %u", intr_desc.bInterfaceSubClass);
    if (intr_desc.bInterfaceSubClass == ADB_SUBCLASS) {
      printf(" (ADB_SUBCLASS)");
    }
    printf("\n        bInterfaceProtocol = %u", intr_desc.bInterfaceProtocol);
    if (intr_desc.bInterfaceProtocol == ADB_PROTOCOL) {
      printf(" (ADB_PROTOCOL)");
    }
    printf("\n        iInterface         = %u", intr_desc.iInterface);
  } else {
    printf("\n--- AdbGetUsbInterfaceDescriptor failure %u", GetLastError());
    return false;
  }

  // Enumerate interface's endpoints
  AdbEndpointInformation pipe_info;
  for (UCHAR pipe = 0; pipe < intr_desc.bNumEndpoints; pipe++) {
    if (AdbGetEndpointInformation(interface_handle, pipe, &pipe_info)) {
      printf("\n      PIPE %u info:", pipe);
      DumpEndpointInformation(&pipe_info);
    } else {
      printf("\n--- AdbGetEndpointInformation(%u) failure %u", pipe,
             GetLastError());
      return false;
    }
  }

  // Get default bulk read endpoint info
  if (AdbGetDefaultBulkReadEndpointInformation(interface_handle, &pipe_info)) {
    printf("\n      Default Bulk Read Pipe info:");
    DumpEndpointInformation(&pipe_info);
  } else {
    printf("\n--- AdbGetDefaultBulkReadEndpointInformation failure %u",
           GetLastError());
    return false;
  }

  // Get default bulk write endpoint info
  if (AdbGetDefaultBulkWriteEndpointInformation(interface_handle, &pipe_info)) {
    printf("\n      Default Bulk Write Pipe info:");
    DumpEndpointInformation(&pipe_info);
  } else {
    printf("\n--- AdbGetDefaultBulkWriteEndpointInformation failure %u",
           GetLastError());
    return false;
  }

  // Test a handshake on that interface
  DeviceHandShake(interface_handle);

  return true;
}

bool TestInterface(const wchar_t* device_name) {
	printf("\n*** Test interface( %ws )", device_name);
	// Get ADB handle to the interface by its name
	ADBAPIHANDLE interface_handle = AdbCreateInterfaceByName(device_name);
	if (NULL == interface_handle) {
		printf("\n FAILED:\nUnable to create interface by name: %u", GetLastError());
		return false;
	}

	// Test it
  TestInterfaceHandle(interface_handle);
	if (!AdbCloseHandle(interface_handle)) {
		printf("\n--- AdbCloseHandle failure %u", GetLastError());
		return false;
	}

	return true;
}




int main() {
	ADBAPIHANDLE enum_handle = AdbEnumInterfaces(kAdbInterfaceId, true, true, true);
	if (NULL == enum_handle) {
		printf("\nTest interfaces failure:");
		printf("\nUnable to enumerate ADB interfaces: %u", GetLastError());
		return 0;
	}

    union {
      AdbInterfaceInfo interface_info;
      char buf[4096];
    };
    unsigned long buf_size = sizeof(buf);

    // Test each found interface
    while (AdbNextInterface(enum_handle, &interface_info, &buf_size)) {
    	printf("\n======>>>>flags>> %d  ===",interface_info.device_name);
      TestInterface(interface_info.device_name);
      buf_size = sizeof(buf);
    }


//	char entry_buffer[2048];
//	AdbInterfaceInfo* next_interface = (AdbInterfaceInfo*)(&entry_buffer[0]);
//	 unsigned long entry_buffer_size = sizeof(entry_buffer);
//
//	 while (AdbNextInterface(enum_handle, next_interface, &entry_buffer_size)) {
//
//		 printf("\n======>>>>flags>> %d  ===",next_interface->flags);
//		 char ser_num[1024];
//		 unsigned long ser_num_size = sizeof(ser_num);
//		 AdbGetSerialNumber(enum_handle,ser_num,&ser_num_size,true);
//		 printf("\n======>>>>ser_num>> %s  ===",ser_num);
//	 }
	return 0;
}

