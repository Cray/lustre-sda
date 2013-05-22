
#include "scsiCore.h"

#define SG_X "/dev/sg%d"
#define SG_MAJOR 21

#ifndef SCSI_IOCTL_GET_PCI
#define SCSI_IOCTL_GET_PCI 0x5387
#endif

#define OPEN_FLAG O_RDWR

#define SENSE_BUFF_LEN 32
//#define INQ_REPLY_LEN 96 // nvn20111013
#define INQ_CMD_CODE 0x12
#define INQ_CMD_LEN 6
//#define INQ_PAGE_SERIAL 0x80 // nvn20111013

//#define SENSE_REPLY_LEN 96 // nvn20111013
//#define SENSE_CMD_CODE 0x1a // nvn20111013
//#define SENSE_CMD_LEN 6 // nvn20111013
//#define SENSE_PAGE_SERIAL 0x80 // nvn20111013

#define MX_ALLOC_LEN 255
//#define EBUFF_SZ 256 // nvn20111013

/* Some of the following error/status codes are exchanged between the
   various layers of the SCSI sub-system in Linux and should never
   reach the user. They are placed here for completeness. What appears
   here is copied from drivers/scsi/scsi.h which is not visible in
   the user space. */

#ifndef SCSI_CHECK_CONDITION
/* Following are the "true" SCSI status codes. Linux has traditionally
   used a 1 bit right and masked version of these. So now CHECK_CONDITION
   and friends (in <scsi/scsi.h>) are deprecated. */
#define SCSI_CHECK_CONDITION 0x2
/* // nvn20111013
#define SCSI_CONDITION_MET 0x4
#define SCSI_BUSY 0x8
#define SCSI_IMMEDIATE 0x10
#define SCSI_IMMEDIATE_CONDITION_MET 0x14
#define SCSI_RESERVATION_CONFLICT 0x18
*/
#define SCSI_COMMAND_TERMINATED 0x22
/* // nvn20111013
#define SCSI_TASK_SET_FULL 0x28
#define SCSI_ACA_ACTIVE 0x30
#define SCSI_TASK_ABORTED 0x40
*/
#endif

/* The following are 'host_status' codes */
#ifndef DID_OK
#define DID_OK 0x00
#endif
#ifndef DID_NO_CONNECT
#define DID_NO_CONNECT 0x01                       /* Unable to connect before timeout */
#define DID_BUS_BUSY 0x02                         /* Bus remain busy until timeout */
#define DID_TIME_OUT 0x03                         /* Timed out for some other reason */
#define DID_BAD_TARGET 0x04                       /* Bad target (id?) */
#define DID_ABORT 0x05                            /* Told to abort for some other reason */
#define DID_PARITY 0x06                           /* Parity error (on SCSI bus) */
#define DID_ERROR 0x07                            /* Internal error */
#define DID_RESET 0x08                            /* Reset by somebody */
#define DID_BAD_INTR 0x09                         /* Received an unexpected interrupt */
#define DID_PASSTHROUGH 0x0a                      /* Force command past mid-level */
#define DID_SOFT_ERROR 0x0b                       /* The low-level driver wants a retry */
#endif

/* These defines are to isolate applictaions from kernel define changes */
#define SG_ERR_DID_OK           DID_OK
#define SG_ERR_DID_NO_CONNECT   DID_NO_CONNECT
#define SG_ERR_DID_BUS_BUSY     DID_BUS_BUSY
#define SG_ERR_DID_TIME_OUT     DID_TIME_OUT
#define SG_ERR_DID_BAD_TARGET   DID_BAD_TARGET
#define SG_ERR_DID_ABORT        DID_ABORT
#define SG_ERR_DID_PARITY       DID_PARITY
#define SG_ERR_DID_ERROR        DID_ERROR
#define SG_ERR_DID_RESET        DID_RESET
#define SG_ERR_DID_BAD_INTR     DID_BAD_INTR
#define SG_ERR_DID_PASSTHROUGH  DID_PASSTHROUGH
#define SG_ERR_DID_SOFT_ERROR   DID_SOFT_ERROR

/* The following are 'driver_status' codes */
#ifndef DRIVER_OK
#define DRIVER_OK 0x00
#endif
#ifndef DRIVER_BUSY
#define DRIVER_BUSY 0x01
#define DRIVER_SOFT 0x02
#define DRIVER_MEDIA 0x03
#define DRIVER_ERROR 0x04
#define DRIVER_INVALID 0x05
#define DRIVER_TIMEOUT 0x06
#define DRIVER_HARD 0x07
#define DRIVER_SENSE 0x08                         /* Sense_buffer has been set */

/* Following "suggests" are "or-ed" with one of previous 8 entries */
#define SUGGEST_RETRY 0x10
#define SUGGEST_ABORT 0x20
#define SUGGEST_REMAP 0x30
#define SUGGEST_DIE 0x40
#define SUGGEST_SENSE 0x80
#define SUGGEST_IS_OK 0xff
#endif
#ifndef DRIVER_MASK
#define DRIVER_MASK 0x0f
#endif
#ifndef SUGGEST_MASK
#define SUGGEST_MASK 0xf0
#endif

/* These defines are to isolate applictaions from kernel define changes */
#define SG_ERR_DRIVER_OK        DRIVER_OK
#define SG_ERR_DRIVER_BUSY      DRIVER_BUSY
#define SG_ERR_DRIVER_SOFT      DRIVER_SOFT
#define SG_ERR_DRIVER_MEDIA     DRIVER_MEDIA
#define SG_ERR_DRIVER_ERROR     DRIVER_ERROR
#define SG_ERR_DRIVER_INVALID   DRIVER_INVALID
#define SG_ERR_DRIVER_TIMEOUT   DRIVER_TIMEOUT
#define SG_ERR_DRIVER_HARD      DRIVER_HARD
#define SG_ERR_DRIVER_SENSE     DRIVER_SENSE
#define SG_ERR_SUGGEST_RETRY    SUGGEST_RETRY
#define SG_ERR_SUGGEST_ABORT    SUGGEST_ABORT
#define SG_ERR_SUGGEST_REMAP    SUGGEST_REMAP
#define SG_ERR_SUGGEST_DIE      SUGGEST_DIE
#define SG_ERR_SUGGEST_SENSE    SUGGEST_SENSE
#define SG_ERR_SUGGEST_IS_OK    SUGGEST_IS_OK
#define SG_ERR_DRIVER_MASK      DRIVER_MASK
#define SG_ERR_SUGGEST_MASK     SUGGEST_MASK

/* The following "category" function returns one of the following */
#define SG_ERR_CAT_CLEAN 0                        /* No errors or other information */
#define SG_ERR_CAT_MEDIA_CHANGED 1                /* interpreted from sense buffer */
#define SG_ERR_CAT_RESET 2                        /* interpreted from sense buffer */
#define SG_ERR_CAT_TIMEOUT 3
#define SG_ERR_CAT_RECOVERED 4                    /* Successful command after recovered err */
#define SG_ERR_CAT_SENSE 98                       /* Something else is in the sense buffer */
#define SG_ERR_CAT_OTHER 99                       /* Some other error/warning has occurred */

typedef struct my_sg_scsi_id
{
  int host_no;                                    /* as in "scsi<n>" where 'n' is one of 0, 1, 2 etc */
  int channel;
  int scsi_id;                                    /* scsi id of target device */
  int lun;
  int scsi_type;                                  /* TYPE_... defined in scsi/scsi.h */
  short h_cmd_per_lun;                            /* host (adapter) maximum commands per lun */
  short d_queue_depth;                            /* device (or adapter) maximum queue length */
  int unused1;                                    /* probably find a good use, set 0 for now */
  int unused2;                                    /* ditto */
}


My_sg_scsi_id;

typedef struct my_scsi_idlun
{
  int mux4;
  int host_unique_id;
}


My_scsi_idlun;

static const char *devices[] =
{
    "/dev/sg**[0-99]", 
//  "/dev/sde",
//  "/dev/sdf",
  //"/dev/sd*[!0-9]",	/* don't look at partitions */
  //"/dev/scd*", // nvn20110817 - only look at sd*
  //"/dev/sr*",
  //"/dev/cd*",
  //"/dev/dvd*",
  //"/dev/st*",
  //"/dev/nst*",
  //"/dev/nosst*",
  //"/dev/tape*",
  NULL
};

using namespace std;

//static map < string, string > sg_map;
map < string, string > sg_map;



tDevice myDev;

string strip(const string & s)
{
  string result = s;

  size_t i = result.find('\0');

  if(i != string::npos)
    result = result.substr(0, i);

  while ((result.length() > 0) && ((uint8_t)result[0] <= ' '))
    result.erase(0, 1);
  while ((result.length() > 0) && ((uint8_t)result[result.length() - 1] <= ' '))
    result.erase(result.length() - 1);

  for (i = 0; i < result.length(); i++)
    if ((uint8_t)result[i] < ' ')
    {
      result.erase(i, 1);
      i--;
    }

  //result = utf8_sanitize(result);

  return result;
}

static string scsi_handle(unsigned int host,
int channel = -1,
int id = -1,
int lun = -1)
{
  char buffer[10];
  string result = "SCSI:";

  snprintf(buffer, sizeof(buffer), "%02d", host);
  result += string(buffer);

  if (channel < 0)
    return result;

  snprintf(buffer, sizeof(buffer), "%02d", channel);
  result += string(":") + string(buffer);
  
  if (id < 0)
    return result;

  snprintf(buffer, sizeof(buffer), "%02d", id);
  result += string(":") + string(buffer);

  if (lun < 0)
    return result;

  snprintf(buffer, sizeof(buffer), "%02d", lun);
  result += string(":") + string(buffer);

  return result;
}

static const char *scsi_type(int type)
{
  switch (type)
  {
    case 0:
      return "Disk";
    case 1:
      return "Tape";
    case 3:
      return "Processor";
    case 4:
      return "Write-Once Read-Only Memory";
    case 5:
      return "CD-ROM";
    case 6:
      return "Scanner";
    case 7:
      return "Magneto-optical Disk";
    case 8:
      return "Medium Changer";
    case 0xd:
      return "Enclosure";
    default:
      return "";
  }
}


static int sg_err_category(int scsi_status,
int host_status,
int driver_status,
const unsigned char *sense_buffer,
int sb_len)
{
  scsi_status &= 0x7e;
  if ((0 == scsi_status) && (0 == host_status) && (0 == driver_status))
    return SG_ERR_CAT_CLEAN;
  if ((SCSI_CHECK_CONDITION == scsi_status) ||
    (SCSI_COMMAND_TERMINATED == scsi_status) ||
    (SG_ERR_DRIVER_SENSE == (0xf & driver_status)))
  {
    if (sense_buffer && (sb_len > 2))
    {
      int sense_key;
      unsigned char asc;

      if (sense_buffer[0] & 0x2)
      {
        sense_key = sense_buffer[1] & 0xf;
        asc = sense_buffer[2];
      }
      else
      {
        sense_key = sense_buffer[2] & 0xf;
        asc = (sb_len > 12) ? sense_buffer[12] : 0;
      }

      if (RECOVERED_ERROR == sense_key)
        return SG_ERR_CAT_RECOVERED;
      else if (UNIT_ATTENTION == sense_key)
      {
        if (0x28 == asc)
          return SG_ERR_CAT_MEDIA_CHANGED;
        if (0x29 == asc)
          return SG_ERR_CAT_RESET;
      }
    }
    return SG_ERR_CAT_SENSE;
  }
  if (0 != host_status)
  {
    if ((SG_ERR_DID_NO_CONNECT == host_status) ||
      (SG_ERR_DID_BUS_BUSY == host_status) ||
      (SG_ERR_DID_TIME_OUT == host_status))
      return SG_ERR_CAT_TIMEOUT;
  }
  if (0 != driver_status)
  {
    if (SG_ERR_DRIVER_TIMEOUT == driver_status)
      return SG_ERR_CAT_TIMEOUT;
  }
  return SG_ERR_CAT_OTHER;
}

#if 0
static bool do_modesense(int sg_fd,
int page,
int page_code,
void *resp,
int mx_resp_len)
{
  int res;
  unsigned char senseCmdBlk[SENSE_CMD_LEN] =
    { SENSE_CMD_CODE, 0, 0, 0, 0, 0 };
  unsigned char sense_b[SENSE_BUFF_LEN];
  sg_io_hdr_t io_hdr;

  page &= 0x3f;
  page_code &= 3;

  senseCmdBlk[2] = (unsigned char) ((page_code << 6) | page);
  senseCmdBlk[4] = (unsigned char) 0xff;
  memset(&io_hdr, 0, sizeof(io_hdr));
  memset(sense_b, 0, sizeof(sense_b));
  io_hdr.interface_id = 'S';
  io_hdr.cmd_len = sizeof(senseCmdBlk);
  io_hdr.mx_sb_len = sizeof(sense_b);
  io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
  io_hdr.dxfer_len = mx_resp_len;
  io_hdr.dxferp = resp;
  io_hdr.cmdp = senseCmdBlk;
  io_hdr.sbp = sense_b;
  io_hdr.timeout = 20000;                         /* 20 seconds */

  if (ioctl(sg_fd, SG_IO, &io_hdr) < 0)
    return false;

  res =
    sg_err_category(io_hdr.status, io_hdr.host_status, io_hdr.driver_status,
    (unsigned char*)io_hdr.sbp, io_hdr.sb_len_wr);
  switch (res)
  {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
      return true;
    default:
      return false;
  }

  return true;
}
#endif


static bool do_inq(int sg_fd,
int cmddt,
int evpd,
unsigned int pg_op,
void *resp,
int mx_resp_len,
int noisy)
{
  int res;
  unsigned char inqCmdBlk[INQ_CMD_LEN] = { INQ_CMD_CODE, 0, 0, 0, 0, 0 };
  unsigned char sense_b[SENSE_BUFF_LEN];
  sg_io_hdr_t io_hdr;

  if (cmddt)
    inqCmdBlk[1] |= 2;
  if (evpd)
    inqCmdBlk[1] |= 1;
  inqCmdBlk[2] = (unsigned char) pg_op;
  inqCmdBlk[4] = (unsigned char) mx_resp_len;
  memset(&io_hdr, 0, sizeof(io_hdr));
  memset(sense_b, 0, sizeof(sense_b));
  io_hdr.interface_id = 'S';
  io_hdr.cmd_len = sizeof(inqCmdBlk);
  io_hdr.mx_sb_len = sizeof(sense_b);
  io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
  io_hdr.dxfer_len = mx_resp_len;
  io_hdr.dxferp = resp;
  io_hdr.cmdp = inqCmdBlk;
  io_hdr.sbp = sense_b;
  io_hdr.timeout = 20000;                         /* 20 seconds */

  if (ioctl(sg_fd, SG_IO, &io_hdr) < 0)
    return false;

  res =
    sg_err_category(io_hdr.status, io_hdr.host_status, io_hdr.driver_status,
    (unsigned char*)io_hdr.sbp, io_hdr.sb_len_wr);
  switch (res)
  {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
      return true;
    default:
      return false;
  }

  return true;
}


#if 0
static unsigned long decode_3_bytes(void *ptr)
{
  unsigned char *p = (unsigned char *) ptr;

  return (p[0] << 16) + (p[1] << 8) + p[2];
}


static u_int16_t decode_word(void *ptr)
{
  unsigned char *p = (unsigned char *) ptr;

  return (p[0] << 8) + p[1];
}
#endif

static bool do_inquiry(int sg_fd)//, hwNode & node)
{
  unsigned char rsp_buff[MX_ALLOC_LEN + 1];
  int k;
  unsigned int len;

  if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000))
    return false;

  memset(rsp_buff, 0, sizeof(rsp_buff));
  if (!do_inq(sg_fd, 0, 0, 0, rsp_buff, 96, 1))
    return false;

  len = (unsigned int) rsp_buff[4] + 5;

  if ((len > 36) && (len < 256))
  {
    memset(rsp_buff, 0, sizeof(rsp_buff));
    if (!do_inq(sg_fd, 0, 0, 0, rsp_buff, len, 1))
      return false;
  }
  else
    return false;

  if (len != ((unsigned int) rsp_buff[4] + 5))
    return false;                                 // twin INQUIRYs yield different lengths

  //unsigned ansiversion = rsp_buff[2] & 0x7;

  //if (rsp_buff[1] & 0x80)
  //  node.addCapability("removable", "support is removable");

  //node.setVendor(string(rsp_buff + 8, 8));
  myDev.vendor = strip(string((char *) rsp_buff + 8, 8));
  if (len > 16)
  {
    //node.setProduct(string(rsp_buff + 16, 16));
     myDev.product = strip(string((char *)rsp_buff + 16, 16));
  }
  if (len > 32)
  {
    //node.setVersion(string(rsp_buff + 32, 4));
     myDev.version = strip(string((char *)rsp_buff + 32, 4));
  }

  //if (ansiversion)
  //  node.setConfig("ansiversion", tostring(ansiversion));

  memset(rsp_buff, 0, sizeof(rsp_buff));
  if (do_inq(sg_fd, 0, 1, 0x80, rsp_buff, MX_ALLOC_LEN, 0))
  {
    len = rsp_buff[3];
    if (len > 0)
    {
      //node.setSerial(hw::strip(string(rsp_buff + 4, len)));
       myDev.serial = strip(string((char *)rsp_buff + 4, len));
    }
  }
#if 0 // nvn20110705 - hwnode
  memset(rsp_buff, 0, sizeof(rsp_buff));
  if (do_modesense(sg_fd, 0x3F, 0, rsp_buff, sizeof(rsp_buff)))
  {
    unsigned long long sectsize = 0;
    unsigned long long heads = 0;
    unsigned long long cyl = 0;
    unsigned long long sectors = 0;
    unsigned long rpm = 0;
    u_int8_t *end = (u_int8_t *) rsp_buff + (u_int8_t) rsp_buff[0];
    u_int8_t *p = NULL;

    if (rsp_buff[3] == 8)
      sectsize = decode_3_bytes(rsp_buff + 9);

    p = (u_int8_t *) & rsp_buff[4];
    p += (u_int8_t) rsp_buff[3];
    while (p < end)
    {
      u_int8_t page = *p & 0x3F;

      if (page == 3)
      {
        sectors = decode_word(p + 10);
        sectsize = decode_word(p + 12);
      }
      if (page == 4)
      {
        cyl = decode_3_bytes(p + 2);
        rpm = decode_word(p + 20);
        heads = p[5];
      }

      p += p[1] + 2;
    }

    node.setCapacity(heads * cyl * sectors * sectsize);

    if (rpm / 15000 == 1)
      node.addCapability("15000rpm", "15000 rotations per minute");
    else
    {
      if (rpm / 10000 == 1)
        node.addCapability("10000rpm", "10000 rotations per minute");
      else
      {
        if (rpm / 7200 == 1)
          node.addCapability("7200rpm", "7200 rotations per minute");
        else
        {
          if (rpm / 5400 == 1)
            node.addCapability("5400rpm", "5400 rotations per minute");
        }
      }
    }
  }
#endif
  return true;
}

//static void scan_devices()
void scan_devices()
{
  int fd = -1;
  int i = 0;
  size_t j = 0;
  My_scsi_idlun m_idlun;

  for (i = 0; devices[i] != NULL; i++)
  {
    glob_t entries;

    if(glob(devices[i], 0, NULL, &entries) == 0)
    {
      for(j=0; j < entries.gl_pathc; j++)
      {
        fd = open(entries.gl_pathv[j], O_RDONLY | O_NONBLOCK);
        if (fd >= 0)
        {
          int bus = -1;
          union
          {
            char host[50];
            int length;
          } tmp;
          tmp.length = sizeof(tmp.host);
          memset(tmp.host, 0, sizeof(tmp.host));

          if(ioctl(fd, SCSI_IOCTL_PROBE_HOST, &tmp.length) >= 0)
          {
            if (ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bus) >= 0)
            {
              memset(&m_idlun, 0, sizeof(m_idlun));
              if (ioctl(fd, SCSI_IOCTL_GET_IDLUN, &m_idlun) >= 0)
              {
                sg_map[string(entries.gl_pathv[j])] = scsi_handle(bus, (m_idlun.mux4 >> 16) & 0xff,
                  m_idlun.mux4 & 0xff,
                  (m_idlun.mux4 >> 8) & 0xff);
              }
            }
          }

          close(fd);
        }
      }
      globfree(&entries);
    }
  }
}

#if 0
static void find_logicalname()//hwNode & n)
{
  map < string, string >::iterator i = sg_map.begin();

  for (i = sg_map.begin(); i != sg_map.end(); i++)
  {
    /*if (i->second == n.getHandle())
    {
      n.setLogicalName(i->first);
      n.claim();
    }*/
  }
}
#endif

static string scsi_businfo(int host,
int channel = -1,
int target = -1,
int lun = -1)
{
  string result;

  result = "scsi@" + tostring(host);

  if (channel >= 0)
  {
    result += ":" + tostring(channel);

    if (target >= 0)
    {
      result += "." + tostring(target);

      if (lun >= 0)
        result += "." + tostring(lun);
    }
  }

  return result;
}

static string host_logicalname(int i)
{
  return "scsi"+tostring(i);
}

// nvn20110705 - remove sysfs
//static string host_kname(int i)                   // for sysfs
//{
//  return "host"+tostring(i);
//}


//static bool atapi(const hwNode & n)
//{
//  return n.isCapable("atapi") && (n.countChildren() == 0);
//}


//static bool scan_sg(int sg)//, hwNode & n)
bool scan_sg(string sg)
{
  char buffer[20];
  int fd = -1;
  My_sg_scsi_id m_id;
  char slot_name[64];                             // should be 16 but some 2.6 kernels require 32 bytes
  string host = "";
  string businfo = "";
  //hwNode *parent = NULL;
  int emulated = 0;
  bool ghostdeventry = false;

//  snprintf(buffer, sizeof(buffer), SG_X, sg);
//  strncpy(buffer, sg, strlen(sg));
  ghostdeventry = !exists(buffer);

//  if(ghostdeventry) mknod(buffer, (S_IFCHR | S_IREAD), MKDEV(SG_MAJOR, sg));
  fd = open(sg.c_str(), OPEN_FLAG | O_NONBLOCK);
//  if(ghostdeventry) unlink(buffer);
  if (fd < 0)
    return false;

  memset(&m_id, 0, sizeof(m_id));
  if (ioctl(fd, SG_GET_SCSI_ID, &m_id) < 0)
  {
    close(fd);
    return true;                                  // we failed to get info but still hope we can continue
  }

  // nvn20111012
  if ( 0 == m_id.scsi_type || 14 == m_id.scsi_type )
  {
  }
  else
  {
     close(fd);
     return false;
  }

  emulated = 0;
  ioctl(fd, SG_EMULATED_HOST, &emulated);

  host = host_logicalname(m_id.host_no);
  businfo = scsi_businfo(m_id.host_no);


  myDev.businfo = businfo;
   switch (m_id.scsi_type)
   {
   case 0:
   case 14:
     myDev.dev = "disk";
     break;
   case 1:
     myDev.dev = "tape";
     break;
   case 3:
     myDev.dev = "processor";
     break;
   case 4:
   case 5:
     myDev.dev = "cdrom";
     break;
   case 6:
     myDev.dev = "scanner";
     break;
   case 7:
     myDev.dev = "magnetooptical";
     break;
   case 8:
     myDev.dev = "changer";
     break;
   case 0xd:
     myDev.dev = "enclosure";
     break;
   }
  myDev.description = scsi_type(m_id.scsi_type);
  myDev.handle = scsi_handle(m_id.host_no,
      m_id.channel, m_id.scsi_id, m_id.lun);
  do_inquiry(fd);
   if(myDev.vendor == "ATA")
   {
      myDev.description = "\\\\ATA_" + myDev.description + "_" +
                                       myDev.serial + "_" +
                                       myDev.version;
      myDev.busType = 0;
      //device.setVendor("");
   }
   else
   {
      myDev.description = "\\\\SCSI_" + myDev.description + "_" +
                                       myDev.serial + "_" +
                                       myDev.version;
      //device.addHint("bus.icon", string("scsi"));
      myDev.busType = 1;
   }
#if 0
  device.setDescription(string(scsi_type(m_id.scsi_type)));
  device.setHandle(scsi_handle(m_id.host_no,
    m_id.channel, m_id.scsi_id, m_id.lun));
  device.setBusInfo(scsi_businfo(m_id.host_no,
    m_id.channel, m_id.scsi_id, m_id.lun));
  device.setPhysId(m_id.channel, m_id.scsi_id, m_id.lun);
  find_logicalname(device);
  do_inquiry(fd, device);
  if(device.getVendor() == "ATA")
  {
    device.setDescription("ATA " + device.getDescription());
    device.setVendor("");
  }
  else
  {
    device.setDescription("SCSI " + device.getDescription());
    device.addHint("bus.icon", string("scsi"));
  }
  // nvn20110705 - no need to scan cdrom
  //if ((m_id.scsi_type == 4) || (m_id.scsi_type == 5))
  //  scan_cdrom(device);
  //if ((m_id.scsi_type == 0) || (m_id.scsi_type == 7) || (m_id.scsi_type == 14))
  //  scan_disk(device);
#endif
  memset(slot_name, 0, sizeof(slot_name));
  ioctl(fd, SCSI_IOCTL_GET_PCI, slot_name);
#if 0
  /*if (ioctl(fd, SCSI_IOCTL_GET_PCI, slot_name) >= 0)
  {
    parent = n.findChildByBusInfo(guessBusInfo(hw::strip(slot_name)));
  }

  if (!parent)
    parent = n.findChildByLogicalName(host);*/

                                                  // IDE-SCSI pseudo host controller
  if (emulated && device.getConfig("driver")=="ide-scsi")
  {
    hwNode *ideatapi = n.findChild(atapi);

    if (ideatapi)
      parent = ideatapi->addChild(hwNode("scsi", hw::storage));
  }

  if (!parent)
  {
    hwNode *core = n.getChild("core");

    if (core)
      parent = core->addChild(hwNode("scsi", hw::storage));
  }

  if (!parent)
    parent = n.addChild(hwNode("scsi", hw::storage));

  if (!parent)
  {
    close(fd);
    return true;
  }

  // nvn20110705
  //if(parent->getBusInfo() == "")
  //  parent->setBusInfo(guessBusInfo(hw::strip(slot_name)));
  parent->setLogicalName(host);
  parent->claim();

  if (emulated)
  {
    parent->addCapability("emulated", "Emulated device");
  }
  parent->addChild(device);
#endif
  close(fd);

  return true;
}

#if 0
static bool scan_hosts(hwNode & node)
{
  struct dirent **namelist = NULL;
  int n;
  vector < string > host_strs;

  if (!pushd("/proc/scsi"))
    return false;
  n = scandir(".", &namelist, selectdir, alphasort);
  popd();
  if ((n < 0) || !namelist)
    return false;

  pushd("/proc/scsi");
  for (int i = 0; i < n; i++)
  {
    struct dirent **filelist = NULL;
    int m = 0;

    pushd(namelist[i]->d_name);
    m = scandir(".", &filelist, NULL, alphasort);
    popd();

    if (m >= 0)
    {
      for (int j = 0; j < m; j++)
      {
        char *end = NULL;
        int number = -1;

        number = strtol(filelist[j]->d_name, &end, 0);

        if ((number >= 0) && (end != filelist[j]->d_name))
        {
          hwNode *controller =
            node.findChildByLogicalName(host_logicalname(number));

          if (!controller)
          { // nvn20110705 - remove sysfs
            //string parentbusinfo = sysfs_getbusinfo(sysfs::entry::byClass("scsi_host", host_kname(number)));

            //controller = node.findChildByBusInfo(parentbusinfo);
          }

          if (!controller)
          {
            controller = node.addChild(hwNode("scsi", hw::storage));
            if (controller)
            {
              controller->setLogicalName(host_logicalname(number));
              // nvn20110705
              //controller->setBusInfo(scsi_businfo(number));
            }
          }

          if (controller)
          {
            controller->setLogicalName(host_logicalname(number));
            // nvn20110705
            //controller->setConfig(string("driver"),
            //  string(namelist[i]->d_name));
            controller->setHandle(scsi_handle(number));
            controller->addCapability("scsi-host", "SCSI host adapter");
            controller->claim();
          }
        }
        free(filelist[j]);
      }
      free(filelist);
    }
    free(namelist[i]);
  }
  free(namelist);
  popd();

  if (!loadfile("/proc/scsi/sg/host_strs", host_strs))
    return false;

  for (unsigned int i = 0; i < host_strs.size(); i++)
  {
    hwNode *host = node.findChildByLogicalName(host_logicalname(i));

    if (host)
    {
      if ((host->getProduct() == "") && (host->getDescription() == ""))
        host->setDescription("SCSI storage controller");
    }
  }

  return true;
}
#endif

bool scan_scsi()//(hwNode & n)
{
  scan_devices();

#if 0
  int i = 0;

//  while (scan_sg(i)) //while (scan_sg(i, n))
    i++;
#endif

#if 0
  scan_hosts(n);
#endif
  return false;
}

//scan_sg with integer input - abhay

bool scan_sg(int sg, std::string &sSerNum)
{
  char buffer[20];
  int fd = -1;
  My_sg_scsi_id m_id;
  char slot_name[64];                             /* should be 16 but some 2.6 kernels require 32 bytes*/
  string host = "";
  string businfo = "";
  /*hwNode *parent = NULL;*/
  int emulated = 0;
  bool ghostdeventry = false;

  snprintf(buffer, sizeof(buffer), SG_X, sg);
/*strncpy(buffer, sg, strlen(sg));*/
  ghostdeventry = !exists(buffer);

/*  if(ghostdeventry) mknod(buffer, (S_IFCHR | S_IREAD), MKDEV(SG_MAJOR, sg));
  fd = open(sg.c_str(), OPEN_FLAG | O_NONBLOCK);*/
  fd = open(buffer, OPEN_FLAG | O_NONBLOCK);
/*  if(ghostdeventry) unlink(buffer);*/
  if (fd < 0)
    return false;

  memset(&m_id, 0, sizeof(m_id));
  if (ioctl(fd, SG_GET_SCSI_ID, &m_id) < 0)
  {
    close(fd);
    return true;                                  // we failed to get info but still hope we can continue
  }

  // nvn20111012
  if ( 0 == m_id.scsi_type || 14 == m_id.scsi_type )
  {
  }
  else
  {
     close(fd);
     return false;
  }

  emulated = 0;
ioctl(fd, SG_EMULATED_HOST, &emulated);

  host = host_logicalname(m_id.host_no);
  businfo = scsi_businfo(m_id.host_no);


  myDev.businfo = businfo;
   switch (m_id.scsi_type)
   {
   case 0:
   case 14:
     myDev.dev = "disk";
     break;
   case 1:
     myDev.dev = "tape";
     break;
   case 3:
     myDev.dev = "processor";
     break;
   case 4:
   case 5:
     myDev.dev = "cdrom";
     break;
   case 6:
     myDev.dev = "scanner";
     break;
   case 7:
     myDev.dev = "magnetooptical";
     break;
   case 8:
     myDev.dev = "changer";
     break;
   case 0xd:
     myDev.dev = "enclosure";
     break;
   }
  myDev.description = scsi_type(m_id.scsi_type);
  myDev.handle = scsi_handle(m_id.host_no,
      m_id.channel, m_id.scsi_id, m_id.lun);
  do_inquiry(fd);
   if(myDev.vendor == "ATA")
 {
      myDev.description = "\\\\ATA_" + myDev.description + "_" +
                                       myDev.serial + "_" +
                                       myDev.version;
      myDev.busType = 0;
      //device.setVendor("");
   }
   else
   {
      myDev.description = "\\\\SCSI_" + myDev.description + "_" +
                                       myDev.serial + "_" +
                                       myDev.version;
      //device.addHint("bus.icon", string("scsi"));
      myDev.busType = 1;
        sSerNum = myDev.serial;
      //std::copy(sSerNum, myDev.serial.size(),0);
       //printf("serial no: %s",myDev.serial);
       
   }

memset(slot_name, 0, sizeof(slot_name));
  ioctl(fd, SCSI_IOCTL_GET_PCI, slot_name);

 close(fd);

  return true;
}

