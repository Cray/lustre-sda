#ifndef __ATA_H__
#define __ATA_H__

#include "common.h"

#define SECTOR_SIZE					512

#define MAX_48BIT_LBA				0xFFFFFFFFFFFF
#define MAX_28BIT_LBA				0xFFFFFFF

#define ATA_SMART_LBA_MID			0x4F
#define ATA_SMART_LBA_HI			0xC2
#define FEAT_SMART_ENABLE			0xD8
#define FEAT_SMART_DISABLE			0xD9
#define FEAT_SMART_AUTOSAVE			0xD2
#define FEAT_SMART_EXEC_OFFLINE		0xD4
#define FEAT_SMART_READ_DATA		0xD0
#define FEAT_SMART_READ_LOG			0xD5
#define FEAT_SMART_RETURN_STATUS	0xDA
#define FEAT_SMART_WRITE_LOG		0xD6

#define ATA_DEV_CONFIG				0xB1
#define ATA_DNLD_CODE				0x92
#define ATA_ACK_MEDIA_CHANGE		0xDB
#define ATA_POST_BOOT				0xDC
#define ATA_PRE_BOOT				0xDD
#define ATA_IDENTIFY				0xEC
#define ATA_IDENTIFY_DMA			0xEE
#define ATA_CHECK_POWER_MODE		0xE5
#define ATA_DOOR_LOCK				0xDE
#define ATA_DOOR_UNLOCK				0xDF
#define ATA_EXEC_DRV_DIAG			0x90
#define ATA_FORMAT_TRACK			0x50
#define ATA_FLUSH_CACHE				0xE7
#define ATA_FLUSH_CACHE_EXT			0xEA
#define ATA_GET_MEDIA_STATUS		0xDA
#define ATA_IDLE_IMMEDIATE			0xE1
#define ATA_IDLE					0xE3
#define ATA_INIT_DRV_PARAM			0x91
#define ATA_NOP						0x00
#define ATA_READ_BUF				0xE4
#define ATA_READ_DMA_QUEUED			0xC7
#define ATA_READ_DMA_RETRY			0xC8
#define ATA_READ_DMA_NORETRY		0xC9
#define ATA_READ_DMA_EXT			0x25
#define ATA_READ_DMA_QUE_EXT		0x26
#define ATA_READ_FPDMA_QUEUED		0x60
#define ATA_READ_LOG_EXT			0x2F
#define ATA_READ_LONG_RETRY			0x22
#define ATA_READ_LONG_NORETRY		0x23
#define ATA_READ_MULTIPLE			0xC4
#define ATA_READ_MULTIPLE_EXT		0x29
#define ATA_READ_MAX_ADDRESS		0xF8
#define ATA_READ_MAX_ADDRESS_EXT	0x27
#define ATA_READ_SECT				0x20
#define ATA_READ_SECT_EXT			0x24
#define ATA_READ_SECT_NORETRY		0x21
#define ATA_READ_VERIFY_RETRY		0x40
#define ATA_READ_VERIFY_NORETRY		0x41
#define ATA_READ_VERIFY_EXT			0x42
#define ATA_RECALIBRATE				0x10
#define ATA_SEEK					0x70
#define ATA_SET_FEATURES			0xEF
#define ATA_SET_MULTIPLE			0xC6
#define ATA_SET_MAX					0xF9
#define ATA_SET_MAX_EXT				0x37
#define ATA_SLEEP					0xE6
#define ATA_STANDBY					0xE2
#define ATA_STANDBY_IMMD			0xE0
#define ATA_WRITE_BUF				0xE8
#define ATA_WRITE_DMA_RETRY			0xCA
#define ATA_WRITE_DMA_NORETRY		0xCB
#define ATA_WRITE_DMA_EXT			0x35
#define ATA_WRITE_DMA_QUEUED		0xCC
#define ATA_WRITE_DMA_QUE_EXT		0x36
#define ATA_WRITE_FPDMA_QUEUED		0x61
#define ATA_WRITE_LOG_EXT			0x3F
#define ATA_WRITE_LONG_RETRY		0x32
#define ATA_WRITE_LONG_NORETRY		0x33
#define ATA_WRITE_MULTIPLE			0xC5
#define ATA_WRITE_MULTIPLE_EXT		0x39
#define ATA_WRITE_SECT				0x30
#define ATA_WRITE_SECT_EXT			0x34
#define ATA_WRITE_SECT_NORETRY		0x31
#define ATA_WRITE_SECTV_RETRY		0x3C
#define ATA_PIO_TRUSTED_RECEIVE		0x5C
#define ATA_DMA_TRUSTED_RECEIVE		0x5D
#define ATA_PIO_TRUSTED_SEND		0x5E
#define ATA_DMA_TRUSTED_SEND		0x5F
#define ATA_SMART					0xB0
#define ATA_SECURITY_DISABLE_PASS	0xF6
#define ATA_SECURITY_ERASE_PREP		0xF3
#define ATA_SECURITY_ERASE_UNIT		0xF4
#define ATA_SECURITY_FREEZE_LOCK	0xF5
#define ATA_SECURITY_SET_PASS		0xF1
#define ATA_SECURITY_UNLOCK			0xF2
#define ATA_LEGACY_TRUSTED_RECEIVE	0xF7
#define ATA_LEGACY_TRUSTED_SEND		0xFB
#define ATAPI_COMMAND				0xA0
#define ATAPI_IDENTIFY				0xA1
#define ATAPI_RESET					0x08
#define ATASET						0x04
#define ATA_DEV_RESET				0x08

typedef enum _eDataTransferDirection 
{
	XFER_UNKNOWN,
	XFER_NO_DATA,
	XFER_DATA_IN,			// Transfer from target to host
	XFER_DATA_OUT,			// Transfer from host to target
	XFER_DATA_OUT_IN,		// Transfer from host to target, followed by target to host
	XFER_DATA_IN_OUT,		// Transfer from target to host, followed by host to target
} eDataTransferDirection;

typedef enum _eAtaCmdType 
{
	ATA_CMD_TYPE_UNKNOWN,
	ATA_CMD_TYPE_TASKFILE,
	ATA_CMD_TYPE_EXTENDED_TASKFILE,
	ATA_CMD_TYPE_NON_TASKFILE,
	ATA_CMD_TYPE_SOFT_RESET,
	ATA_CMD_TYPE_HARD_RESET
} eAtaCmdType;

typedef enum _eAtaProtocol 
{
	ATA_PROTOCOL_UNKNOWN,		// initial setting
	ATA_PROTOCOL_PIO,			// various, includes r/w
	ATA_PROTOCOL_DMA,			// various, includes r/w
	ATA_PROTOCOL_NO_DATA,		// various (e.g. NOP)
	ATA_PROTOCOL_DEV_RESET,		// DEVICE RESET
	ATA_PROTOCOL_DEV_DIAG,		// EXECUTE DEVICE DIAGNOSTIC
	ATA_PROTOCOL_DMA_QUE,		// various, includes r/w
	ATA_PROTOCOL_PACKET,		// PACKET
	ATA_PROTOCOL_PACKET_DMA,	// PACKET
	ATA_PROTOCOL_DMA_FPDMA,		// READ/WRITE FPDMA QUEUED
	ATA_PROTOCOL_MAX_VALUE,		// Error check terminator
} eAtaProtocol;

typedef enum _eSatProtocol
{
	SAT_PROTOCOL_HARDWARE_RESET,
	SAT_PROTOCOL_SRST,
	SAT_PROTOCOL_RESERVED1,
	SAT_PROTOCOL_NON_DATA,
	SAT_PROTOCOL_PIO_DATA_IN,
	SAT_PROTOCOL_PIO_DATA_OUT,
	SAT_PROTOCOL_DMA,
	SAT_PROTOCOL_DMA_QUEUED,
	SAT_PROTOCOL_DEVICE_DIAGNOSTIC,
	SAT_PROTOCOL_DEVICE_RESET,
	SAT_PROTOCOL_UDMA_DATA_IN,
	SAT_PROTOCOL_UDMA_DATA_OUT,
	SAT_PROTOCOL_FPDMA,
	SAT_PROTOCOL_RESERVED2,
	SAT_PROTOCOL_RESERVED3,
	SAT_PROTOCOL_RETURN_RESPONSE_INFORMATION

}eSatProtocol;


typedef struct _tAtaIdentifyData
{
	tUINT16 Word000;
	tUINT16 Word001;
	tUINT16 Word002;
	tUINT16 Word003;
	tUINT16 Word004;
	tUINT16 Word005;
	tUINT16 Word006;
	tUINT16 Word007;
	tUINT16 Word008;
	tUINT16 Word009;

	tUINT8 SerNum[20];			// 10 ... 19

	tUINT16 Word020;
	tUINT16 Word021;
	tUINT16 Word022;
	tUINT8  FwRev[8];			// 23 24 25 26
	tUINT8  ModelNum[40];		// 27 ... 46
	tUINT8  BLK_SIZE[2];		// 47
	tUINT16 Word048;
	tUINT16 Capabilities1;		// 49

	tUINT16 Capabilities2;		// 50
	tUINT16 Word051;
	tUINT16 Word052;
	tUINT16 Word053;
	tUINT16 Word054;
	tUINT16 Word055;
	tUINT16 Word056;
	tUINT16 Word057;
	tUINT16 Word058;
	tUINT16 Word059;

	tUINT32 TotalUserLba;		// 60 61
	tUINT16 Word062;
	tUINT8  MultiDmaModesSupported; tUINT8 MultiDMAModeSelected;		// 63
	tUINT8 PioModesSupported; tUINT8 Reserved;							// 64
	tUINT16 MinDMACycleTime;											// 65
	tUINT16 RecDMACycleTime;											// 66
	tUINT16 MinPIOCycleTime;											// 67
	tUINT16 MinPIOCycleTimeIORDY;										// 68
	tUINT16 Word069;

	tUINT16 Word070;
	tUINT16 Word071;
	tUINT16 Word072;
	tUINT16 Word073;
	tUINT16 Word074;
	tUINT16 QueueDepth;													// 75, bits 0-4 only
	tUINT16 Word076;													// 76
	tUINT16 Word077;
	tUINT16 Word078;
	tUINT16 Word079;

	tUINT16 Word080;
	tUINT16 Word081;
	tUINT16 CommandSetsSupported1;										// 82
	tUINT16 CommandSetsSupported2;										// 83
	tUINT16 CommandSetsSupported3;										// 84
	tUINT16 CommandSetsEnabled1;										// 85
	tUINT16 CommandSetsEnabled2;										// 86
	tUINT16 CommandSetsEnabled3;										// 87
	tUINT8 UdmaModesSupported; tUINT8 UdmaModeSelected;					// 88
	tUINT16 Word089;

	tUINT16 Word090;
	tUINT16 Word091;
	tUINT16 Word092;
	tUINT16 Word093;
	tUINT16 Word094;
	tUINT16 Word095;
	tUINT16 Word096;
	tUINT16 Word097;
	tUINT16 Word098;
	tUINT16 Word099;

	//Both Changed from tUINT32 to 16
	//tUINT32 TotSectNumLBALo;
	//tUINT32 TotSectNumLBAHi;
	
	tUINT64 TotalUserLba48;						// 100 ... 103
	tUINT16 Word104;
	tUINT16 Word105;
	union {  // 106
	  tUINT16 AsWord;
	  struct  {
		 tUINT16 LogicalSectorCount:4;			// Bits 0-3
		 tUINT16 Reserved4_11:8;				// Bits 4-11
		 tUINT16 LargeSectors:1;				// Bit 12
		 tUINT16 LogicalSectors:1;				// Bit 13
		 tUINT16 FeatureSupport:2;				// Bits 14-15
	  } bitfields;
	} SectorSizeReport;
	tUINT16 Word107;
	tUINT16 Word108;
	tUINT16 Word109;

	tUINT16 Word110;
	tUINT16 Word111;
	tUINT16 Word112;
	tUINT16 Word113;
	tUINT16 Word114;
	tUINT16 Word115;
	tUINT16 Word116;
	tUINT16 SectorSize[2];						// 117-118
	tUINT16 Word119;

	tUINT16 Word120;
	tUINT16 Word121;
	tUINT16 Word122;
	tUINT16 Word123;
	tUINT16 Word124;
	tUINT16 Word125;
	tUINT16 Word126;
	tUINT16 Word127;
	tUINT16 Word128;
	tUINT16 Word129;

	tUINT16 Word130;
	tUINT16 Word131;
	tUINT16 Word132;
	tUINT16 Word133;
	tUINT16 Word134;
	tUINT16 Word135;
	tUINT16 Word136;
	tUINT16 Word137;
	tUINT16 Word138;
	tUINT16 Word139;

	tUINT16 Word140;
	tUINT16 Word141;
	tUINT16 Word142;
	tUINT16 Word143;
	tUINT16 Word144;
	tUINT16 Word145;
	tUINT16 Word146;
	tUINT16 Word147;
	tUINT16 Word148;
	tUINT16 Word149;

	tUINT16 VendorUniqueTDSupport;				// 150
	tUINT16 Word151;
	tUINT16 Word152;
	tUINT16 Word153;
	tUINT16 Word154;
	tUINT16 Word155;
	tUINT16 Word156;
	tUINT16 Word157;
	tUINT16 Word158;
	tUINT16 Word159;

	tUINT16 Word160;
	tUINT16 Word161;
	tUINT16 Word162;
	tUINT16 Word163;
	tUINT16 Word164;
	tUINT16 Word165;
	tUINT16 Word166;
	tUINT16 Word167;
	tUINT16 Word168;
	tUINT16 Word169;

	tUINT16 Word170;
	tUINT16 Word171;
	tUINT16 Word172;
	tUINT16 Word173;
	tUINT16 Word174;
	tUINT16 Word175;
	tUINT16 Word176;
	tUINT16 Word177;
	tUINT16 Word178;
	tUINT16 Word179;

	tUINT16 Word180;
	tUINT16 Word181;
	tUINT16 Word182;
	tUINT16 Word183;
	tUINT16 Word184;
	tUINT16 Word185;
	tUINT16 Word186;
	tUINT16 Word187;
	tUINT16 Word188;
	tUINT16 Word189;

	tUINT16 Word190;
	tUINT16 Word191;
	tUINT16 Word192;
	tUINT16 Word193;
	tUINT16 Word194;
	tUINT16 Word195;
	tUINT16 Word196;
	tUINT16 Word197;
	tUINT16 Word198;
	tUINT16 Word199;

	tUINT16 Word200;
	tUINT16 Word201;
	tUINT16 Word202;
	tUINT16 Word203;
	tUINT16 Word204;
	tUINT16 Word205;
	tUINT16 Word206;
	tUINT16 Word207;
	tUINT16 Word208;
	tUINT16 Word209;

	tUINT16 Word210;
	tUINT16 Word211;
	tUINT16 Word212;
	tUINT16 Word213;
	tUINT16 Word214;
	tUINT16 Word215;
	tUINT16 Word216;
	tUINT16 Word217;
	tUINT16 Word218;
	tUINT16 Word219;

	tUINT16 Word220;
	tUINT16 Word221;
	tUINT16 Word222;
	tUINT16 Word223;
	tUINT16 Word224;
	tUINT16 Word225;
	tUINT16 Word226;
	tUINT16 Word227;
	tUINT16 Word228;
	tUINT16 Word229;

	tUINT16 Word230;
	tUINT16 Word231;
	tUINT16 Word232;
	tUINT16 Word233;
	tUINT16 Word234;
	tUINT16 Word235;
	tUINT16 Word236;
	tUINT16 Word237;
	tUINT16 Word238;
	tUINT16 Word239;

	tUINT16 Word240;
	tUINT16 Word241;
	tUINT16 Word242;
	tUINT16 Word243;
	tUINT16 Word244;
	tUINT16 Word245;
	tUINT16 Word246;
	tUINT16 Word247;
	tUINT16 Word248;
	tUINT16 Word249;

	tUINT16 Word250;
	tUINT16 Word251;
	tUINT16 Word252;
	tUINT16 Word253;
	tUINT16 Word254;
	tUINT16 Word255;
} tAtaIdentifyData;

typedef struct _tDataPtr 
{
	void* pData;				// If pData is NULL, AllocLen must be zero also.
	size_t DataLen;				// Number of valid bytes.
	size_t AllocLen;			// If AllocLen is zero, pData must be NULL also.
} tDataPtr;

typedef struct _AtaTfrBlock 
{
	tUINT8 CommandStatus;
	tUINT8 ErrorFeature;

	tUINT8 LbaLow;
	tUINT8 LbaMid;
	tUINT8 LbaHi;
	tUINT8 DevHead;

	tUINT8 LbaLow48;
	tUINT8 LbaMid48;
	tUINT8 LbaHi48;
	tUINT8 Feature48;

	tUINT8 SectorCount;
	tUINT8 SectorCount48;
	tUINT8 Reserved0;
	tUINT8 DeviceControl;
	// Pad it out to 16 bytes
	tUINT8 Reserved1;
	tUINT8 Reserved2;
} tAtaTfrBlock;

// Parameters for all ATA non-block commands
typedef struct _tAtaStdParameters 
{
	tDataPtr Data;
	tAtaTfrBlock *startTFR;				// Starting TFR
	tAtaTfrBlock *endTFR;				// Ending TFR Data
	tUINT64 Timeout;					// Set timeout to non-zero value to override default.
										// If timeout is zero, the default timeout is used.
	size_t DataBytesTransferred;		// Contains the number of data bytes
										// transferred to/from the device.  In most
										// cases it  will equal Data.DataLen, but it
										// will not in the case that the transfer
										// was less than requested.
	tUINT64 elapsedMsecs;				// Time in ticks for the command completion.
	tBOOL autoWaitQueue;
} tAtaStdParameters;

typedef struct _tAtaCommandParameters 
{
	size_t						Size;
	eDataTransferDirection		DataDirection;
	tAtaStdParameters			stdParms;
	tAtaTfrBlock				Tfr;
	eAtaProtocol				Protocol;
	eAtaCmdType					CmdType;
	size_t						BlocksToTransfer;
} tAtaCommandParameters;

#endif

