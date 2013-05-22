#ifndef _SCSICORE_H_
#define _SCSICORE_H_

//#include "version.h"
//#include "mem.h"
//#include "cdrom.h"  // nvn - no need
//#include "disk.h"   // nvn - no need, too detail
#include "osutils.h"
//#include "heuristics.h"
//#include "sysfs.h"
#include <glob.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>
#ifndef MKDEV
#include <linux/kdev_t.h>
#endif
#ifndef MINOR
#include <linux/kdev_t.h>
#endif

#include <string>
#include <map>

struct tDevice
{
  std::string id, vendor, product, version, date, serial, slot, handle, description,
    businfo, physid, dev;
  bool enabled;
  bool claimed;
  unsigned long long start;
  unsigned long long size;
  unsigned long long capacity;
  unsigned long long clock;
  unsigned int width;
  std::vector < std::string > attracted;
  std::vector < std::string > features;
  std::vector < std::string > logicalnames;
  std::map < std::string, std::string > features_descriptions;
  std::map < std::string, std::string > config;
  int busType;
};

//bool scan_scsi(hwNode & n);
bool scan_scsi();
void scan_devices();
bool scan_sg(std::string sg);
bool scan_sg(int sg, std::string &sSerNum);
extern std::map < std::string, std::string > sg_map;
extern tDevice myDev;

#endif
