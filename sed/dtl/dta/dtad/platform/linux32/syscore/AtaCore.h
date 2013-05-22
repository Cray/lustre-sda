#ifndef __ATA_CORE_H__
#define __ATA_CORE_H__

#include "LinuxIncludes.h"

//Used for file reading and writing.  Needed in linux for llseek()
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

using namespace std;


//////////////////////////////////////////////
// Defines
//////////////////////////////////////////////
#define DEFAULT_CMD_TIMEOUT			30
#define ATACORE_VERSION				"201"

#define INVALID_HANDLE_VALUE			-1





//////////////////////////////////////////////
// eAtaError
//////////////////////////////////////////////
// Enum for error types
//////////////////////////////////////////////
typedef enum _eAtaError 
{
	ATA_NO_ERROR = 0,
	ATA_ERROR_INVALID_HANDLE,							// Invalid OS handle
	ATA_ERROR_INVALID_PARAMETER,							// Invalid parameter passed to command
	ATA_ERROR_COMMAND_PARAMETER_BLOCK_INCORRECT_SIZE,	// Size of parameter block does not equal sanity check
	ATA_ERROR_DATA_LEN_EXCEEDS_BUFFER_ALLOCATION,
	ATA_ERROR_DATA_FLAG_AND_BUFFER_MISMATCH,
	ATA_ERROR_INCONSISTENT_DATA_LEN,
	ATA_ERROR_MEMORY_ALLOCATION_FAILURE,					// Runtime memory alloc failed
	ATA_ERROR_OPERATION_FAILURE,							// Failure where we don't have control over the error info
	ATA_ERROR_COMMAND_TIMEOUT,
	ATA_ERROR_HARDWARE_ACCESS_FAILURE,
	ATA_ERROR_INVALID_MODE_REQUEST,
	ATA_ERROR_INVALID_PROTOCOL,
	ATA_UNEXPECTED_HOT_PLUG,								// Unexpected hot plug event
	ATA_ERROR_NOT_ATA_DEVICE,
	ATA_ERROR_NOT_SUPPORTED,

	// ATA error codes
	ATA_STATUS_ERROR,									// Ata error bit set but no error in the error register
														// or user called SendCommand and we didn't check the error register
	ATA_MEDIA_ERROR,
	ATA_NO_MEDIA,
	ATA_ABORTED_COMMAND,
	ATA_MEDIA_CHANGE_REQUESTED,
	ATA_ID_NOT_FOUND,
	ATA_MEDIA_CHANGED,
	ATA_UNCORRECTABLE_DATA,
	ATA_INTERFACE_CRC_ERROR,
	ATA_ERROR_WRITE_PROTECTED,							// In the spec, but not in any commands we have implemented yet
	ATA_DRQ_PENDING,
	ATA_DEVICE_FAULT,
	ATA_DEVICE_NOT_READY,
	ATA_DEVICE_BUSY,
	ATA_ERROR_INVALID_NAME,
	ATA_ERROR_NOT_OPENED,
	ATA_ERROR_CANNOT_OPEN,
	ATA_ERROR_ALREADY_OPENED,
	ATA_ERROR_ALREADY_CLOSED,
	ATA_ERROR_BROKEN_INTERNAL_STATE,
	ATA_ERROR_VERSION_MISMATCH,
	ATA_DEVICE_NOT_PRESENT,
	ATA_FATAL_ERROR,
	ATA_CANNOT_WRITE_TO_DISK,
	ATA_MAX_ERROR
} eAtaError;


//////////////////////////////////////////////
// CAtaPassThrough
//////////////////////////////////////////////
// Class for ATA passthrough drive objects.
//////////////////////////////////////////////

class CAtaPassThrough
{
public:
	CAtaPassThrough(void);
	CAtaPassThrough(string sName);
	~CAtaPassThrough(void);
	void Open(string sName);
	void Close();
	eAtaError InitIdentifiers();

	/////////////////////////
	// ATA PIO
	/////////////////////////
	eAtaError AtaCmdReadSector(tUINT32 lba, tUINT8 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadSectorExt(tUINT64 lba, tUINT16 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdWriteSector(tUINT32 lba, tUINT8 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdWriteSectorExt(tUINT64 lba, tUINT16 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);

	/////////////////////////
	// ATA DMA
	/////////////////////////
	eAtaError AtaCmdReadDma(tUINT32 lba, tUINT8 sectorCount, tUINT8 * pBuf, 
							tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT, tUINT64 * pPerfCounter=NULL);
	eAtaError AtaCmdReadDmaExt(tUINT64 lba, tUINT16 sectorCount, tUINT8 * pBuf, 
								tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT, tUINT64 * pPerfCounter=NULL);
	eAtaError AtaCmdWriteDma(tUINT32 lba, tUINT8 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdWriteDmaExt(tUINT64 lba, tUINT16 sectorCount, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);

	/////////////////////////
	// ATA SMART
	/////////////////////////
	eAtaError AtaCmdSmartEnable(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartDisable(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartReadLog(tUINT8 numOfSectors, tUINT8 logAddress, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartWriteLog(tUINT8 numOfSectors, tUINT8 logAddress, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartReadData(tUINT8 * pBuf, tUINT32 bufLen, 
									tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartExecOffLine(tUINT8 subCommand, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartShortDstOffline(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartExtendedDstOffline(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartAbortDst(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSmartReturnStatus(tBOOL * bExceeded, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);

	/////////////////////////
	// Misc. ATA commands
	/////////////////////////
	eAtaError AtaCmdIdentify(tUINT8 * pIdentData);
	eAtaError AtaCmdNop(tUINT8 subCmd, tUINT8 sectorCount = 0, tUINT8 lbaLow = 0, 
									tUINT8 lbaMid = 0, tUINT8 lbaHi = 0, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadVerify(tUINT32 lba, tUINT8 sectorCount, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadVerifyExt(tUINT64 lba, tUINT16 sectorCount, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdStandby(tUINT8 timerPeriod, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdStandbyImmediate(tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdCheckPowerMode(tUINT8 * result, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSetFeatures(tUINT8 features, tUINT8 sectorCount=0, tUINT8 LbaLow=0, tUINT8 LbaMid=0,
									tUINT8 LbaHi=0, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadNativeMaxAddress(tUINT32 * lba, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadNativeMaxAddressExt(tUINT64 * lba, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSetMaxAddress(tUINT32 lba, tUINT8 sectCount, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSetMaxAddressExt(tUINT64 lba, tUINT8 sectCount, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdWriteLogExt(tUINT16 sectCount, tUINT8 logAddress, tUINT16 sectOffset, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReadLogExt(tUINT16 sectCount, tUINT8 logAddress, tUINT16 sectOffset, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdSendSdbp(tUINT16 sectCount, tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdReceiveSdbp(tUINT16 sectCount,  tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);

	/////////////////////////
	// ATA base functions
	/////////////////////////
	eAtaError AtaCmdPioIn28(tUINT8 command, tUINT8 features, tUINT8 sectorCount, 
									tUINT8 lbaLow, tUINT8 lbaMid, tUINT8 lbaHi, tUINT8 device,
									tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdPioOut28(tUINT8 command, tUINT8 features, tUINT8 sectorCount, 
									tUINT8 lbaLow, tUINT8 lbaMid, tUINT8 lbaHi, tUINT8 device,
									tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdDmaIn28(tUINT8 command, tUINT8 features, tUINT8 sectorCount, 
									tUINT8 lbaLow, tUINT8 lbaMid, tUINT8 lbaHi, tUINT8 device,
							tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT, tUINT64 * pPerfCounter=NULL);
	eAtaError AtaCmdDmaOut28(tUINT8 command, tUINT8 features, tUINT8 sectorCount, 
									tUINT8 lbaLow, tUINT8 lbaMid, tUINT8 lbaHi, tUINT8 device,
									tUINT8 * pBuf, tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdNonData28(tUINT8 command, tUINT8 features, tUINT8 sectorCount, 
									tUINT8 lbaLow, tUINT8 lbaMid, tUINT8 lbaHi, tUINT8 device,
									tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdPioIn48(tUINT8 command, tUINT8 features, tUINT8 features48,
									tUINT8 sectorCount, tUINT8 sectorCount48, tUINT8 lbaLow, 
									tUINT8 lbaLow48, tUINT8 lbaMid, tUINT8 lbaMid48,  
									tUINT8 lbaHi, tUINT8 lbaHi48, tUINT8 device, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdPioOut48(tUINT8 command, tUINT8 features, tUINT8 features48,
									tUINT8 sectorCount, tUINT8 sectorCount48, tUINT8 lbaLow, 
									tUINT8 lbaLow48, tUINT8 lbaMid, tUINT8 lbaMid48,  
									tUINT8 lbaHi, tUINT8 lbaHi48, tUINT8 device, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdDmaIn48(tUINT8 command, tUINT8 features, tUINT8 features48,
									tUINT8 sectorCount, tUINT8 sectorCount48, tUINT8 lbaLow, 
									tUINT8 lbaLow48, tUINT8 lbaMid, tUINT8 lbaMid48,  
									tUINT8 lbaHi, tUINT8 lbaHi48, tUINT8 device, tUINT8 * pBuf, 
							tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT, tUINT64 * pPerfCounter=NULL);
	eAtaError AtaCmdDmaOut48(tUINT8 command, tUINT8 features, tUINT8 features48,
									tUINT8 sectorCount, tUINT8 sectorCount48, tUINT8 lbaLow, 
									tUINT8 lbaLow48, tUINT8 lbaMid, tUINT8 lbaMid48,  
									tUINT8 lbaHi, tUINT8 lbaHi48, tUINT8 device, tUINT8 * pBuf, 
									tUINT32 bufLen, tUINT64 timeout = DEFAULT_CMD_TIMEOUT);
	eAtaError AtaCmdNonData48(tUINT8 command, tUINT8 features, tUINT8 features48,
									tUINT8 sectorCount, tUINT8 sectorCount48, tUINT8 lbaLow, 
									tUINT8 lbaLow48, tUINT8 lbaMid, tUINT8 lbaMid48,  
									tUINT8 lbaHi, tUINT8 lbaHi48, tUINT8 device, 
									tUINT64 timeout = DEFAULT_CMD_TIMEOUT);

	/////////////////////////
	// Get/Set Attributes
	/////////////////////////
	inline HANDLE GetHandle()					{ return m_hDrive; }
	inline eAtaError GetLastWinAtaError()		{ return m_eLastError; }
	inline tUINT32 GetLastSystemError()			{ return m_eLastSystemError; }
	inline string GetDeviceName()				{ return m_sDevName; }
	inline string GetModelNumber()				{ return m_sModelNum; }
	inline string GetFirmwareRevision()			{ return m_sFwRev; }
	inline string GetSerialNumber()				{ return m_sSerialNum; }
	inline string GetCoreVersion()				{ return m_sCoreVersion; }
	inline tUINT64 GetMaxLba()					{ return m_uMaxLba; }
	inline tBOOL IsAllowWrites()				{ return m_bAllowWrites; }
	inline tUINT64 GetLastCmdTimeInMsecs()		{ return m_uCmdTimeInMsecs; }
	inline tUINT64 GetDefaultTimeoutInSecs()	{ return m_uTimeoutInSecs; }
	inline tUINT8 GetMaxSupportedUdmaMode()		{ return m_uMaxSupportedUdmaMode; }
	inline tUINT8 GetCurrentUdmaMode()			{ return m_uCurrentUdmaMode; }

	inline tUINT8 GetLastRecSectCountReg()		{ return m_tfrLastRec.SectorCount; }
	inline tUINT8 GetLastRecSectCountExtReg()	{ return m_tfrLastRec.SectorCount48; }
	inline tUINT8 GetLastRecLbaLowReg()			{ return m_tfrLastRec.LbaLow; }
	inline tUINT8 GetLastRecLbaLowExtReg()		{ return m_tfrLastRec.LbaLow48; }
	inline tUINT8 GetLastRecLbaMidReg()			{ return m_tfrLastRec.LbaMid; }
	inline tUINT8 GetLastRecLbaMidExtReg()		{ return m_tfrLastRec.LbaMid48; }
	inline tUINT8 GetLastRecLbaHiReg()			{ return m_tfrLastRec.LbaHi; }
	inline tUINT8 GetLastRecLbaHiExtReg()		{ return m_tfrLastRec.LbaHi48; }
	inline tUINT8 GetLastRecErrorReg()			{ return m_tfrLastRec.ErrorFeature; }
	inline tUINT8 GetLastRecStatusReg()			{ return m_tfrLastRec.CommandStatus; }
	inline tUINT8 GetLastRecDevHeadReg()		{ return m_tfrLastRec.DevHead; }
	inline tUINT8 * GetIdentifyData()			{ return (tUINT8 *) m_IdentData; }

	inline tBOOL IsSafeToWrite()				{ return m_bSafeToWrite; }
	inline tBOOL IsAtaSupported()				{ return m_bAtaSupported; }
	inline tBOOL Is48BitSupported()				{ return m_b48BitSupported; }
	inline tBOOL IsSmartSupported()				{ return m_bSmartSupported; }
	inline tBOOL IsUdmaSupported()				{ return m_bUdmaSupported; }
	inline tBOOL IsUdmaSelected()				{ return m_bUdmaSelected; }
	inline tBOOL IsWriteCacheEnabled()			{ return m_bWriteCacheEnabled; }
	inline tBOOL IsPlatformDrive()				{ return m_bPlatformDrive; }

	inline void SetDefaultTimeoutInSecs(tUINT64 timeInSecs)		{ m_uTimeoutInSecs = timeInSecs; }
	inline void SetEnableWriteCacheOnExit(tBOOL enable)			{ m_bEnableWriteCacheOnExit = enable; }

	eAtaError SetAllowWrites(tBOOL allowWrites);
	eAtaError LockAndDismountDrive();
	eAtaError UnlockDrive();


/////////////////////////
// Private stuff
/////////////////////////
private:
	eAtaError GetHandle(string sName);

	eAtaError AtaSendCmd(tUINT8 command, tUINT8 features, tUINT8 featuresExt,
						tUINT8 sectorCount, tUINT8 sectorCountExt, tUINT8 lbaLow, 
						tUINT8 lbaLowExt, tUINT8 lbaMid, tUINT8 lbaMidExt,  
						tUINT8 lbaHi, tUINT8 lbaHiExt, tUINT8 device, tUINT8 * pBuf, 
						tUINT32 bufLen, eDataTransferDirection dataDirection,
						tUINT16 xferLen, eAtaProtocol protocol, eAtaCmdType cmdType, 
						tUINT64 timeout, tUINT64 * pPerfCounter=NULL);

	eAtaError SendCommand(tAtaCommandParameters& rAPT, tUINT64 * pPerfCounter=NULL);
	eAtaError SendDMACommand(tAtaCommandParameters& rAPT, tUINT64 * pPerfCounter=NULL);


	eAtaError SATSendCommand(tAtaCommandParameters& rAPT, tUINT64 * pPerfCounter=NULL);

	//////////////////////////////////////////////////////////////////////////////////////////
	const char * scsi_get_opcode_name(tUINT8 opcode);
	int sg_io_cmnd_io(struct scsi_cmnd_io * iop, int report, int unknown, tUINT64 * pPerfCounter=NULL);


	//////////////////////////////////////////////////////////////////////////////////////////

	// Attributes
	HANDLE				m_hDrive;
	string				m_sDevName;
	string				m_sModelNum;
	string				m_sFwRev;
	string				m_sSerialNum;
	string				m_sCoreVersion;
	tAtaTfrBlock		m_tfrLastSent;
	tAtaTfrBlock		m_tfrLastRec;
	eAtaError			m_eLastError;
	tUINT32				m_eLastSystemError;
	tUINT64				m_uCmdTimeInMsecs;
	tUINT64				m_uTimeoutInSecs;
	tUINT64				m_uMaxLba;
	tUINT8				m_IdentData[512];
	tBOOL				m_bSafeToWrite;
	tBOOL				m_bAllowWrites;
	tBOOL				m_bAtaSupported;
	tBOOL				m_b48BitSupported;
	tBOOL				m_bSmartSupported;
	tBOOL				m_bUdmaSupported;
	tBOOL				m_bUdmaSelected;
	tBOOL				m_bWriteCacheEnabled;
	tBOOL				m_bPlatformDrive;
	tBOOL				m_bEnableWriteCacheOnExit;
	tUINT8				m_uMaxSupportedUdmaMode;
	tUINT8				m_uCurrentUdmaMode;
};




#ifndef TEST_UNIT_READY
#define TEST_UNIT_READY 0x0
#endif
#ifndef LOG_SELECT
#define LOG_SELECT 0x4c
#endif
#ifndef LOG_SENSE
#define LOG_SENSE 0x4d
#endif
#ifndef MODE_SENSE
#define MODE_SENSE 0x1a
#endif
#ifndef MODE_SENSE_10
#define MODE_SENSE_10 0x5a
#endif
#ifndef MODE_SELECT
#define MODE_SELECT 0x15
#endif
#ifndef MODE_SELECT_10
#define MODE_SELECT_10 0x55
#endif
#ifndef INQUIRY
#define INQUIRY 0x12
#endif
#ifndef REQUEST_SENSE
#define REQUEST_SENSE  0x03
#endif
#ifndef RECEIVE_DIAGNOSTIC
#define RECEIVE_DIAGNOSTIC  0x1c
#endif
#ifndef SEND_DIAGNOSTIC
#define SEND_DIAGNOSTIC  0x1d
#endif
#ifndef READ_DEFECT_10
#define READ_DEFECT_10  0x37
#endif

#ifndef SAT_ATA_PASSTHROUGH_12
#define SAT_ATA_PASSTHROUGH_12 0xa1
#endif
#ifndef SAT_ATA_PASSTHROUGH_16
#define SAT_ATA_PASSTHROUGH_16 0x85
#endif

struct scsi_opcode_name {
	tUINT8 opcode;
	const char * name;
};
#define DXFER_NONE        0
#define DXFER_FROM_DEVICE 1
#define DXFER_TO_DEVICE   2

#define LSCSI_DID_ERROR 0x7

static struct scsi_opcode_name opcode_name_arr[] = {
	/* in ascending opcode order */
	{TEST_UNIT_READY, "test unit ready"},       /* 0x00 */
	{REQUEST_SENSE, "request sense"},           /* 0x03 */
	{INQUIRY, "inquiry"},                       /* 0x12 */
	{MODE_SELECT, "mode select(6)"},            /* 0x15 */
	{MODE_SENSE, "mode sense(6)"},              /* 0x1a */
	{RECEIVE_DIAGNOSTIC, "receive diagnostic"}, /* 0x1c */
	{SEND_DIAGNOSTIC, "send diagnostic"},       /* 0x1d */
	{READ_DEFECT_10, "read defect list(10)"},   /* 0x37 */
	{LOG_SELECT, "log select"},                 /* 0x4c */
	{LOG_SENSE, "log sense"},                   /* 0x4d */
	{MODE_SELECT_10, "mode select(10)"},        /* 0x55 */
	{MODE_SENSE_10, "mode sense(10)"},          /* 0x5a */
	{SAT_ATA_PASSTHROUGH_16, "ata pass-through(16)"}, /* 0x85 */
	{SAT_ATA_PASSTHROUGH_12, "ata pass-through(12)"}, /* 0xa1 */
};

struct scsi_cmnd_io
{
	tUINT8 * cmnd;       /* [in]: ptr to SCSI command block (cdb) */
	size_t  cmnd_len;   /* [in]: number of bytes in SCSI command */
	int dxfer_dir;      /* [in]: DXFER_NONE, DXFER_FROM_DEVICE, or 
						DXFER_TO_DEVICE */
	tUINT8 * dxferp;     /* [in]: ptr to outgoing or incoming data buffer */
	size_t dxfer_len;   /* [in]: bytes to be transferred to/from dxferp */
	tUINT8 * sensep;     /* [in]: ptr to sense buffer, filled when 
						 CHECK CONDITION status occurs */
	size_t max_sense_len; /* [in]: max number of bytes to write to sensep */
	unsigned timeout;   /* [in]: seconds, 0-> default timeout (60 seconds?) */
	size_t resp_sense_len;  /* [out]: sense buffer length written */
	tUINT8 scsi_status;  /* [out]: 0->ok, 2->CHECK CONDITION, etc ... */
	int resid;          /* [out]: Number of bytes requested to be transferred
						less actual number transferred (0 if not
						supported) */
};

//TODO: // nvn20110628 - ata pass through
typedef struct _ATA_PASS_THROUGH_DIRECT
{
	unsigned char PathId;
} ATA_PASS_THROUGH_DIRECT, *PATA_PASS_THROUGH_DIRECT;


#endif
