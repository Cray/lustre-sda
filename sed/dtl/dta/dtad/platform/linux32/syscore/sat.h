#ifndef __SAT_H__
#define __SAT_H__

#include <sys/ioctl.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>


#define LSCSI_DRIVER_MASK					0xF 
#define LSCSI_DRIVER_SENSE					0x8 
#define LSCSI_DRIVER_TIMEOUT				0x6
#define LSCSI_DID_TIME_OUT					0x3
#define LSCSI_DID_BUS_BUSY					0x2
#define LSCSI_DID_NO_CONNECT				0x1

#define SCSI_STATUS_CHECK_CONDITION			0x2


#define SECTOR_SIZE							512
#define MAX_SENSE_BUFFER_LENGTH				22
#define DEF_TIMEOUT							60




//SCSI To ATA Passthrough Types
#define SCSI_TO_ATA_TRANSLATION_16			0x85
#define SCSI_TO_ATA_TRANSLATION_12			0xA1

#define SAT_48_BIT_COMMAND_SIZE			16
#define SAT_28_BIT_COMMAND_SIZE			12


//Flags for SCSI to ATA Passthrough
#define SCSI_FLAG_EXTENDED_COMMAND				1
#define SCSI_FLAG_CHECK_CONDITION				32
#define SCSI_FLAG_TRANSFER_FROM_DEVICE			8
#define SCSI_FLAG_BLOCK							4
#define SCSI_FLAG_TLENGTH_IN_SECTOR_REGISTER	2

//TODO: // nvn20110628 - scsi win-ddk porting - need to remove
#define SCSI_IOCTL_DATA_OUT           0
#define SCSI_IOCTL_DATA_IN            1
#define SCSI_IOCTL_DATA_UNSPECIFIED   2

//TODO: // nvn20110628 - scsi pass through
typedef struct _SCSI_PASS_THROUGH_DIRECT
{
	unsigned char PathId;
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

#endif
