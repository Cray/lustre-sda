/*! \file TCGCoreInterface.cpp
    \brief Basic implementations of base class members from <TCG/TCGCoreInterface.hpp>.

    These implementation shall be cross-platform and relatively generic.
    Some or all of them may be overloaded by derived classes.
    
    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.  No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee. 

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright © 2009.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.

*/

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4996)
#endif

//=================================
// Include files
//=================================
#if defined(__linux__)
   #include <sys/time.h> // nvn20110718
   // nvn20110719
   // try to be portable by using ostreamstring instead of sprintf_s
   #include <sstream>

   //#define _stricmp(s1, s2) strcasecmp(s1, s2)  // not used
   #define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#endif
#include "TCGCoreInterface.hpp"
#include "dtlcrypto.h"
#include "dta/Ata.hpp" // nvn20110701

using namespace dta;
using namespace dti;

static const unsigned int MIN_SLEEP_TIME = 1;
static const unsigned int MAX_SLEEP_TIME = 500;


//=======================================================================================
// CTcgCoreInterface
//=======================================================================================

CTcgCoreInterface::CTcgCoreInterface(dta::CDriveTrustSession* newSession)
                                    : CDriveTrustInterface(newSession), ITCGInterface(newSession),
                                      m_hasSilo(false), m_useSilo(false), m_Level0_SSC_Code(L0_DISCOVERY_FEATURECODE_UNSET),
                                      m_singleUserModeSupported(false), m_Level0_DataStoreTableFeatureSet(false),
                                      m_Level0_MaxNumOfDataStoreTables(0), m_Level0_MaxTotalSizeOfDataStoreTables(0), 
                                      m_Level0_DataStoreTableSizeAlignment(0), m_Level0_AlignmentRequired(false),
                                      m_Level0_LogicalBlockSize(512), m_Level0_AlignmentGranularity(8), m_Level0_LowestAlignedLBA(0),
                                      m_Level0_LogicalPortsAvailable(0), 
                                      m_orphanSessionDetected(false), m_useDynamicComID(false), m_sleepTime(3)
                                      
{
   m_MSID.resize(0);
   attemptUsingDmaIF4ATA();
   probeTcgCoreSSC();
   synchronizeHostTPerProperties();

#ifdef __TCGSILO
   searchForSilo();
#endif
} // CTcgCoreInterface

//=======================================================================================
// CTcgCoreInterface
//=======================================================================================

CTcgCoreInterface::CTcgCoreInterface(dta::CDriveTrustSession* newSession, const _tstring logFileName)
                                    : CDriveTrustInterface(newSession, logFileName), ITCGInterface(newSession, logFileName),
                                      m_hasSilo(false), m_useSilo(false), m_Level0_SSC_Code(L0_DISCOVERY_FEATURECODE_UNSET),
                                      m_singleUserModeSupported(false), m_Level0_DataStoreTableFeatureSet(false),
                                      m_Level0_MaxNumOfDataStoreTables(0), m_Level0_MaxTotalSizeOfDataStoreTables(0), 
                                      m_Level0_DataStoreTableSizeAlignment(0), m_Level0_AlignmentRequired(false),
                                      m_Level0_LogicalBlockSize(512), m_Level0_AlignmentGranularity(8), m_Level0_LowestAlignedLBA(0),
                                      m_Level0_LogicalPortsAvailable(0), 
                                      m_orphanSessionDetected(false), m_useDynamicComID(false), m_sleepTime(3)
{
   if( NULL != m_logFile )
   {
      //
      // Reset our version of the header section of the logging file
      //
      fseek( m_logFile, 0, SEEK_SET );

      fprintf( m_logFile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" );
      fprintf( m_logFile, "<!-- TCG Packet Log created by Seagate (C) DriveTrust Library -->\n\n" );
   
#if defined(_WIN32) // nvn20110701
      _ftprintf( m_logFile, TXT("<TCGLog device=\"%s\" "), serialNumber().c_str() );
#else
      fprintf( m_logFile, TXT("<TCGLog device=\"%s\" "), serialNumber().c_str() );
#endif
      fprintf( m_logFile, "time=\"%s\">\n", currentTime() );
   }

   m_MSID.resize(0);
   attemptUsingDmaIF4ATA();
   probeTcgCoreSSC();
   synchronizeHostTPerProperties();

#ifdef __TCGSILO
   searchForSilo();
#endif
} // CTcgCoreInterface

//=======================================================================================
CTcgCoreInterface::~CTcgCoreInterface()
{
   if( NULL != m_logFile )
   {
      fprintf( m_logFile, "<LoggingEnd time=\"%s\"/>\n", currentTime() );
      fprintf( m_logFile, "</TCGLog>\n" );
      fclose( m_logFile );

      m_logFile = NULL; // to prevent base class from adding its footer which is not appropriate.
   }

#ifdef __TCGSILO
   if( m_ACT )
      delete m_ACT;

   if( m_TCGSilo )
      delete m_TCGSilo;
#endif
} // ~CTcgCoreInterface

//=================================================================================
/// \brief Exchange TCG security IF Send/Recv packets between host and TPer.
///
/// \pre ComPacket has been prepared fully ready in m_commandBuffer, and the
/// expected size of response set in m_responseBuffer prior to calling this function.
///
/// \return status byte of the TCG IF-Send/Recv process.
//=================================================================================
TCG_STATUS CTcgCoreInterface::securityPacketExchange()
{
   // Pre-condition: ComPacket fully prepared ready in m_commandBuffer
   tUINT32 comID = m_packetManager.getExtendedComID() >> 16;
   memset( &m_responseBuffer[0], 0, m_responseBuffer.size() );

   if( logging() )
      logSecuritySend( SECURITY_PROTOCOLID_COMPACKET_IO, SWAPWORD((tUINT16)comID), true );

   // Use the current command Timeout setting if the TCG session Timeout not set.
   tUINT32 timeout = m_packetManager.getSessionTimeout() * 1000;
   if( 0 == timeout )
   {
      _tstring value;
      m_session->GetAttribute( TXT("Timeout"), value );
#if defined(_WIN32) // nvn20110718
      timeout = _tstoi( value.c_str() ) * 1000;
#else
      timeout = atoi( value.c_str() ) * 1000;
#endif
   }

#if defined(_WIN32) // nvn20110719
   timeBeginPeriod( 1 );
   tUINT32 startTime = timeGetTime();
#else
   struct timeval theTime;
   gettimeofday( &theTime, NULL );
   tUINT32 startTime = (tUINT32)theTime.tv_usec / 1000;
#endif

   M_TCGTry()
   {
#ifdef __TCGSILO
      if( useSilo() )
      {
         m_TCGSilo->executeTCGComPacketCmd( m_commandBuffer, m_responseBuffer, timeout, m_sleepTime );
      } // if
      else
#endif
      {
         if( !M_DtaSuccess( m_session->SecurityDataToDevice( SECURITY_PROTOCOLID_COMPACKET_IO, SWAPWORD((tUINT16)comID), m_commandBuffer ) ) )
            throw dta::Error(eGenericFatalError);

         //within SessionTimeout, checking the readiness of response
         while( true )
         {
            if( !M_DtaSuccess( m_session->SecurityDataFromDevice( SECURITY_PROTOCOLID_COMPACKET_IO, SWAPWORD((tUINT16)comID), m_responseBuffer ) ) )
               throw dta::Error(eGenericFatalError);

            m_packetManager.setComBuffer( m_responseBuffer, false );

            if( 0 == m_packetManager.getOustandingData() ) // if( 0 == *((tUINT32*)(&m_responseBuffer[0] + 8)) )
            {
               break; // data ready/completes
            }
            else if( 1 == m_packetManager.getOustandingData() ) // if( 0 == m_responseBuffer[8] && 0 == m_responseBuffer[9] && 0 == m_responseBuffer[10] && 1 == m_responseBuffer[11] )
            {
#if defined(_WIN32) // nvn20110719
               if( timeGetTime() - startTime < timeout )
               {
                  Sleep(m_sleepTime);
               }
               else
               {
                  //wcerr << TXT("Session timeout while waiting for Security-IN data") << std::endl;
                  throw dta::Error(eGenericTimeoutError);
               }
#else
               // nvn20110926 - remove sleep
               //gettimeofday( &theTime, NULL );
               //if( ((theTime.tv_usec / 1000) - startTime) < timeout )
               //{
                  usleep( m_sleepTime * 100 ); // nvn20110926 - generic sleep for USB and ATA
               //}

#endif
            } // else
            else // Not big enough receiving buffer??
            {
               if( 0 == m_packetManager.getComPacketPayloadLength() && m_packetManager.getOustandingData() == m_packetManager.getMinTransfer() )
               {
                  m_responseBuffer.resize( m_packetManager.getOustandingData() );
                  memset( &m_responseBuffer[0], 0, m_responseBuffer.size() );
               }
               else
               {
                  //std::wcerr << TXT("Corrupted data received while waiting for Security-IN data") << std::endl;
                  throw dta::Error(eGenericInvalidIdentifier);
               }
            } // else
         } // while

         if( *((tUINT32*)(&m_responseBuffer[4])) != *((tUINT32*)(&m_commandBuffer[4])) ) // ComID match
         {
            //wcout << TXT("Incorrect data received with the MethodCall reponse") << std::endl;
            throw dta::Error(eGenericInvalidIdentifier);
         } // if
      } // else
   } // try
   M_TCGCatch( false, false );
#if defined(_WIN32) // nvn20110719
   m_methodExecTimeMilliSecond = timeGetTime() - startTime; // Holds the time duration for this command exchange
   timeEndPeriod( 1 );
#else
   gettimeofday( &theTime, NULL );
   m_methodExecTimeMilliSecond = (theTime.tv_usec / 1000) - startTime;
#endif

   if( logging() )
      logSecurityRecv( SECURITY_PROTOCOLID_COMPACKET_IO, SWAPWORD((tUINT16)comID), true );

   M_TCGReturn( true );
} // securityPacketExchange

//=================================================================================
/// \brief Exchange TCG security IF Send/Recv byte-streams between host and TPer.
///
/// \param returnDataLengthPos   [IN]  Position of the returned data length in the response buffer.
///
/// \pre The byte-stream has been prepared fully ready in m_commandBuffer, and the
/// expected size of response set in m_responseBuffer prior to calling this function.
///
/// \return status byte of the TCG IF-Send/Recv process.
//=================================================================================
TCG_STATUS CTcgCoreInterface::securityByteStreamExchange( int returnDataLengthPos )
{
   // Pre-condition: ComPacket fully prepared ready in m_commandBuffer
   tUINT16 spSpecific = (tUINT16)(m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) >> 16 );
   tUINT32 requestCode = m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[4])) );
   
   memset( &m_responseBuffer[0], 0, m_responseBuffer.size() );

   if( logging() )
      logSecuritySend( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SWAPWORD( spSpecific ), false );

   // Use the current command Timeout setting if the TCG session Timeout not set.
   tUINT32 timeout = m_packetManager.getSessionTimeout() * 1000;
   if( 0 == timeout )
   {
      _tstring value;
      m_session->GetAttribute( TXT("Timeout"), value );
#if defined(_WIN32) // nvn20110719
      timeout = _tstoi( value.c_str() ) * 1000;
#else
      timeout = atoi( value.c_str() ) * 1000;
#endif
   }

#if defined(_WIN32) // nvn20110719
   timeBeginPeriod( 1 );
   tUINT32 startTime = timeGetTime();
#else
   struct timeval theTime;
   gettimeofday( &theTime, NULL );
   tUINT32 startTime = (tUINT32)theTime.tv_usec / 1000;
#endif

   M_TCGTry()
   {
      if( !M_DtaSuccess( m_session->SecurityDataToDevice( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SWAPWORD( spSpecific ), m_commandBuffer ) ) )
         throw dta::Error(eGenericFatalError);

      //within SessionTimeout, checking the readiness of response
      while( true )
      {
         if( !M_DtaSuccess( m_session->SecurityDataFromDevice( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SWAPWORD( spSpecific ), m_responseBuffer ) ) )
            throw dta::Error(eGenericFatalError);

         if( m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[4])) ) == requestCode )
         {
            if( 0 != m_responseBuffer[returnDataLengthPos] || 0 != m_responseBuffer[returnDataLengthPos+1] )
            {
               break; // ready
            }
            else
            {
#if defined(_WIN32) // nvn20110719
               if( timeGetTime() - startTime < timeout )
               {
                  Sleep(m_sleepTime);
               }
#else
               gettimeofday( &theTime, NULL );
               if( ((theTime.tv_usec / 1000) - startTime) < timeout )
               {
                  sleep(m_sleepTime);
               }
#endif
               else
               {
                  //std::wcerr << TXT("Session timeout while waiting for Security-IN data") << std::endl;
                  throw dta::Error(eGenericTimeoutError);
               }
            }
         }
         else
         {
            //std::wcerr << TXT("No-Response-Available returned while waiting for GetComIDResponse") << std::endl;
            throw dta::Error(eGenericInvalidIdentifier);
         }
      }

      if( *((tUINT32*)(&m_responseBuffer[0])) != *((tUINT32*)(&m_commandBuffer[0])) ) // ComID match
      {
         //std::wcout << TXT("Unmatched ComID data received with the GetComIDRequest reponse") << std::endl;
         throw dta::Error(eGenericInvalidIdentifier);
      }
   }
   M_TCGCatch( false, false );

#if defined(_WIN32) // nvn20110719
   m_methodExecTimeMilliSecond = timeGetTime() - startTime; // Holds the time duration for this command exchange
   timeEndPeriod( 1 );
#else
   gettimeofday( &theTime, NULL );
   m_methodExecTimeMilliSecond = (theTime.tv_usec / 1000) - startTime;
#endif

   if( logging() )
      logSecurityRecv( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SWAPWORD( spSpecific ), false );

   M_TCGReturn( true );
} // securityByteStreamExchange

//=================================================================================
/// \brief Exchange TCG security IF Send/Recv byte-stream data between host and TPer.
///
/// \param protcolID  [IN]  Protocol ID, eg. 0x02 for Com-ID management request.
/// \param spSpecific [IN]  SP-specific, works with a corresponding protocolID.
///
/// \pre IF-Send data has been prepared fully ready in m_commandBuffer, and the
/// expected size of response set in m_responseBuffer prior to calling this function.
///
/// \return status byte of the TCG IF-Send/Recv process.
//=================================================================================
TCG_STATUS CTcgCoreInterface::securityIFExchange( tUINT8 protcolID, tUINT16 spSpecific )
{
   memset( &m_responseBuffer[0], 0, m_responseBuffer.size() );

   if( logging() )
      logSecuritySend( protcolID, spSpecific, false );

#if defined(_WIN32) // nvn20110719
   timeBeginPeriod( 1 );
   tUINT32 startTime = timeGetTime();
#else
   struct timeval theTime;
   gettimeofday( &theTime, NULL );
   tUINT32 startTime = (tUINT32)theTime.tv_usec / 1000;
#endif

   M_TCGTry()
   {
      if( !M_DtaSuccess( m_session->SecurityDataExchange( protcolID, SWAPWORD(spSpecific), m_commandBuffer, m_responseBuffer ) ) )
         throw dta::Error(eGenericFatalError);
   }
   M_TCGCatch( false, false );

#if defined(_WIN32) // nvn20110719
   m_methodExecTimeMilliSecond = timeGetTime() - startTime; // Holds the time duration for this command exchange
   timeEndPeriod( 1 );
#else
   gettimeofday( &theTime, NULL );
   m_methodExecTimeMilliSecond = (theTime.tv_usec / 1000) - startTime;
#endif

   if( logging() )
      logSecurityRecv( protcolID, spSpecific, false );

   M_TCGReturn( true );
} // securityIFExchange

//=================================================================================
/// \brief Security IF-Send, usually used to send TPer/Comm level command (without IF-Recv) to the TPer.
///
/// \param protcolID  [IN]  Protocol ID, 0x02 (& spSpec=0x0004) for programmatic TPerReset.
/// \param spSpecific [IN]  SP-specific, works with protocolID as described above.
/// \param blocks     [IN]  Number of blocks to transfer.
///
/// \return status byte of the TCG IF-Send process.
//=================================================================================
TCG_STATUS CTcgCoreInterface::securityIFSend( tUINT8 protcolID, tUINT16 spSpecific, int blocks )
{
   // Pre-condition: ComPacket fully prepared ready in m_commandBuffer, if applicable
   if( logging() )
      logSecuritySend( protcolID, SWAPWORD( spSpecific ), false );

#if defined(_WIN32) // nvn20110822
   timeBeginPeriod( 1 );
   tUINT32 startTime = timeGetTime();
#else
   struct timeval theTime;
   gettimeofday( &theTime, NULL );
   tUINT32 startTime = (tUINT32)theTime.tv_usec / 1000;
#endif

   M_TCGTry()
   {
      if( !M_DtaSuccess( m_session->SecurityDataToDevice( protcolID, SWAPWORD( spSpecific ), m_commandBuffer ) ) )
         throw dta::Error(eGenericFatalError);

   }
   M_TCGCatch( false, false );

#if defined(_WIN32) // nvn20110822
   m_methodExecTimeMilliSecond = timeGetTime() - startTime; // Holds the time duration for this command exchange
   timeEndPeriod( 1 );
#else
   gettimeofday( &theTime, NULL );
   m_methodExecTimeMilliSecond = (theTime.tv_usec / 1000) - startTime;
#endif

   if( logging() )
      fprintf( m_logFile, "<Transporting MethodExecTimeMs='%u'/>\n", m_methodExecTimeMilliSecond );

   M_TCGReturn( true );
} // securityIFSend

//=================================================================================
/// \brief Security IF-Recv, usually used to retrieve security information (without prior IF-Send) from the TPer.
///
/// \param protcolID  [IN]  Protocol ID, 0x00 (& spSpec=0) for querying supported security protocol list;
///                         0x01 (& spSpec=0x0001) for Level 0 discovery.
/// \param spSpecific [IN]  SP-specific, works with protocolID as described above.
/// \param blocks     [IN]  Number of blocks to transfer.
///
/// \return status byte of the TCG IF-Recv process, with retrieved data saved in the m_responseBuffer.
//=================================================================================
TCG_STATUS CTcgCoreInterface::securityIFRecv( tUINT8 protcolID, tUINT16 spSpecific, int blocks )
{
   m_responseBuffer.resize( m_blockSize * blocks );
   memset( &m_responseBuffer[0], 0, m_responseBuffer.size() );

#if defined(_WIN32) // nvn20110719
   timeBeginPeriod( 1 );
   tUINT32 startTime = timeGetTime();
#else
   struct timeval theTime;
   gettimeofday( &theTime, NULL );
   tUINT32 startTime = (tUINT32)theTime.tv_usec / 1000;
#endif

   M_TCGTry()
   {
      if( !M_DtaSuccess( m_session->SecurityDataFromDevice( protcolID, SWAPWORD(spSpecific), m_responseBuffer ) ) )
         throw dta::Error(eGenericFatalError);
   }
   M_TCGCatch( false, false );

#if defined(_WIN32) // nvn20110719
   m_methodExecTimeMilliSecond = timeGetTime() - startTime; // Holds the time duration for this command exchange
   timeEndPeriod( 1 );
#else
   gettimeofday( &theTime, NULL );
   m_methodExecTimeMilliSecond = (theTime.tv_usec / 1000) - startTime;
#endif

   if( logging() )
      logSecurityRecv( protcolID, spSpecific, false );

   M_TCGReturn( true );
} // securityIFRecv

//=================================================================================
/// \brief Check the returned Call status for some the methods in the response packet from the TPer.
///
/// \param returnedCallStatus    [IN]  Returned call status subpacket payload.
/// \param resultPresent         [IN]  If the Result is present in the returned status subpacket payload (for CS2.0 only).
///
/// \return boid.
//=================================================================================
void CTcgCoreInterface::checkReturnedCallStatus( dta::tBytes &returnedCallStatus, bool resultPresent )
{
   if( returnedCallStatus.size() <3 )
      throw dta::Error(eGenericFatalError);

   if( !m_tokenProcessor.isStartList( returnedCallStatus[0] ) )
      throw dta::Error(eGenericInvalidIdentifier);

   if( 1 == m_tcgCoreSpecVersion || resultPresent )
   {
      if( 0x01 != m_tokenProcessor.getTinyAtomData( &returnedCallStatus[1] ) )
         throw dta::Error(eGenericWarning);  // Not successfully authenticated or empty data returned
   }
   else // CS2.0 and above with Result absent
   {
      if( !m_tokenProcessor.isEndList( returnedCallStatus[1] ) )
         throw dta::Error(eGenericWarning);  // Must be empty data
   }
} // checkReturnedCallStatus

//=================================================================================
/// \brief Request a new ComID (extended ID) from TPer, if it's supported.
///
/// \return tUINT32, an issued extended ComID by the TPer.
//=================================================================================
tUINT32 CTcgCoreInterface::getComID()
{
   securityIFRecv( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SPSPECIFIC_P02_GET_COM_ID );

   tUINT32 id = m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[0])) );

   if( 0 == id )
      throw dta::Error(eGenericInvalidParameter);

   m_packetManager.setExtendedComID( id );

   return id;
} // getComID

//=================================================================================
/// \brief Verify an extended ComID with the TPer, if it's supported.
///
/// \param extComID [IN]  Extended ComID.
///
/// \return enum value for the state of the given ComID.
//=================================================================================
etComIDState CTcgCoreInterface::verifyComID( tUINT32 extComID )
{
   m_commandBuffer.resize( m_blockSize );
   m_responseBuffer.resize( m_blockSize );
   memset( &m_commandBuffer[0], 0, m_commandBuffer.size() );

   *((tUINT32*)(&m_commandBuffer[0])) = m_swapper.HostToNet( extComID );
   *((tUINT32*)(&m_commandBuffer[4])) = m_swapper.HostToNet( (tUINT32)VERIFY_COMID_REQ_CODE );

   securityByteStreamExchange();

   if( m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[0]))) != extComID )
      throw dta::Error(eGenericInvalidIdentifier);

   return (etComIDState) m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[12])) );
} // verifyComID

//=================================================================================
/// \brief Select an issued ComID on the TPer.
///
/// \param extComID [IN]  Extended ComID to be used.
///
/// \return status of this process.
//=================================================================================
TCG_STATUS CTcgCoreInterface::selectComID( tUINT32 extComID )
{
   etComIDState st = verifyComID( extComID );
   if( !( evISSUED == st || evASSOCIATED == st ) )
      throw dta::Error(eGenericInvalidIdentifier);

   m_packetManager.setExtendedComID( extComID );
   return TS_SUCCESS;
} // selectComID

//=================================================================================
/// \brief TCG protocol stack reset for the given ComID on the TPer.
///
/// \param extComID [IN]  Extended ComID.
///
/// \return status byte of the response for this call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::stackReset( tUINT32 extComID )
{
#ifdef __TCGSILO
   // Call the silo reset, if in use
   if( useSilo() )
   {
      M_TCGTry()
      {
         m_TCGSilo->reset();
      }
      M_TCGCatch(false, true)
   } // if
   else
#endif
   {
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );
      memset( &m_commandBuffer[0], 0, m_commandBuffer.size() );

      *((tUINT32*)(&m_commandBuffer[0])) = m_swapper.HostToNet( extComID );
      *((tUINT32*)(&m_commandBuffer[4])) = m_swapper.HostToNet( (tUINT32)PROTOCOL_STACK_RESET_REQ_CODE );

      securityByteStreamExchange();

      if( m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[0]))) != extComID )
         throw dta::Error(eGenericInvalidIdentifier);

      if( 0x00 == m_responseBuffer[10] && 0x04 == m_responseBuffer[11] && 0 == *((tUINT32*)( &m_responseBuffer[12] ) ) ) // Status
      {
         //std::wcout << TXT("OK ") << milliSeconds << TXT("ms") << std::endl;
      }
      else
      {
         //std::wcerr << TXT("Reset failed.") << std::endl;
         throw dta::Error(eGenericFatalError);
      }

      return TS_SUCCESS;
   }
} // stackReset

//=================================================================================
/// \brief TCG programmatic TPer Reset on the TPer.
///
/// \return status byte of the response for this call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::programmaticTPerReset()
{
   // This is a SSC specific feature, to be implemented in OPAL SSC interface.
   return TS_DTL_ERROR;

} // programmaticTPerReset

//=================================================================================
/// \brief TCG Properties method - retrieving TCG Proterties information from the TPer.
///
/// \param propertyData [OUT]  Properties data to be returned.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::properties( dta::tBytes & propertyData )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID should have been set
      tUINT32 oldTPerSN = m_packetManager.getTPerSN();
      tUINT32 oldHostSN = m_packetManager.getHostSN();
      m_packetManager.setTPerSN( 0 );
      m_packetManager.setHostSN( 0 );

      m_packetManager.setBlockSize( m_blockSize );
      m_commandBuffer.resize( m_blockSize ); // Properties() method requires only one block
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallToken( p, UID_SESSION_MANAGER, UID_M_PROPERTIES );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      CTcgCoreInterface::securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_CALL, UID_SESSION_MANAGER, UID_M_PROPERTIES );

      p = &respSubPacketPayload[1];

      tUINT64 d;
      p = m_tokenProcessor.getShortAtomData( p, &d ); // SMUID, checked
      p = m_tokenProcessor.getShortAtomData( p, &d ); // PROPERTIES_UID, checked

      propertyData.resize( m_tokenProcessor.sizeofListToken( p ) );
      memcpy( &propertyData[0], p, propertyData.size() ); // [[ <name-value>, <name-value>, ... ]]

      if( !m_tokenProcessor.isStartList(*p++) )       // Generic returned list for any method call
         throw dta::Error(eGenericInvalidIdentifier);

      if( !m_tokenProcessor.isStartList(*p++) )       // Returned properties list, in form of <name=value>
         throw dta::Error(eGenericInvalidIdentifier);

      //
      // Parse and process Properties attribute items
      //
      dta::tBytes propertyName;
      while( !m_tokenProcessor.isEndList(*p) )
      {
         if( !m_tokenProcessor.isNamedValueToken( *p ) )
            throw dta::Error(eGenericInvalidIdentifier);

         p = m_tokenProcessor.getNamedValueTokenName( p, propertyName );
         p = m_tokenProcessor.getAtomData( p, &d );

         if( !m_tokenProcessor.isEndName( *p++ ) )
            throw dta::Error(eGenericInvalidIdentifier);

         // Pick and handle the property items with interest.
         //if( 0 == memcmp( &propertyName[0], "MaxComPacketSize", propertyName.size() ) )
      }

      if( !m_tokenProcessor.isEndList(*++p) )       // End of Generic returned list for any method call
         throw dta::Error(eGenericInvalidIdentifier);

      m_packetManager.setTPerSN( oldTPerSN );
      m_packetManager.setHostSN( oldHostSN );
   }
   M_TCGCatch( true, true );
} // properties

//=================================================================================
/// \brief Set HostProperties to and/or Retrieve Properties information from the TPer.
///
/// TCG method depiction
///   SessionManager.Properties[ HostProperties = [ name = value ... ] ]
///   => SessionManager.Properties[ Properties : [ name = value ... ], HostProperties = [ name = value ... ] ]
///
/// \param pHostPropertiesIn  [IN]   Pointer to a caller allocated buffer holding the TCG Host Properties data to set to SED. NULL indicates no setting of HostProperties.
/// \param pTPerProperties    [OUT]  Pointer to a caller allocated buffer to hold the returned TCG TPer Properties data. NULL indicates not interested.
/// \param pHostPropertiesOut [OUT]  Pointer to a caller allocated buffer to hold the returned TCG Host Properties data. NULL indicates not interested.
///
/// \return Status byte of the response ComPacket for this method call. Saved the protocol info in the internal Response buffer.
//=================================================================================
TCG_STATUS CTcgCoreInterface::properties( HostProperties *pHostPropertiesIn, TPerProperties *pTPerProperties, HostProperties *pHostPropertiesOut )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID should have been set
      tUINT32 oldTPerSN = m_packetManager.getTPerSN();
      tUINT32 oldHostSN = m_packetManager.getHostSN();
      m_packetManager.setTPerSN( 0 );
      m_packetManager.setHostSN( 0 );

      m_packetManager.setBlockSize( m_blockSize );
      m_commandBuffer.resize( m_blockSize ); // Properties() method requires only one block
      m_responseBuffer.resize( m_blockSize *2 );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_SESSION_MANAGER, UID_M_PROPERTIES );
      if( NULL != pHostPropertiesIn && !pHostPropertiesIn->isEmpty() )
      {
         p = encodeNamedValueName( p, "HostProperties", 0 );
         p = m_tokenProcessor.buildStartList( p );

         // Allow all the "HostProperties" passed in by caller to be set here, regardless of Seagate's permitted set.
         if( pHostPropertiesIn->MaxComPacketSize_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxComPacketSize", (tUINT32)strlen("MaxComPacketSize"), (tUINT64) pHostPropertiesIn->MaxComPacketSize );

         if( pHostPropertiesIn->MaxResponseComPacketSize_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxResponseComPacketSize", (tUINT32)strlen("MaxResponseComPacketSize"), (tUINT64) pHostPropertiesIn->MaxResponseComPacketSize );

         if( pHostPropertiesIn->MaxPacketSize_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxPacketSize", (tUINT32)strlen("MaxPacketSize"), (tUINT64) pHostPropertiesIn->MaxPacketSize );

         if( pHostPropertiesIn->MaxIndTokenSize_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxIndTokenSize", (tUINT32)strlen("MaxIndTokenSize"), (tUINT64) pHostPropertiesIn->MaxIndTokenSize );

         if( pHostPropertiesIn->MaxAggTokenSize_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxAggTokenSize", (tUINT32)strlen("MaxAggTokenSize"), (tUINT64) pHostPropertiesIn->MaxAggTokenSize );

         if( pHostPropertiesIn->MaxPackets_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxPackets", (tUINT32)strlen("MaxPackets"), (tUINT64) pHostPropertiesIn->MaxPackets );

         if( pHostPropertiesIn->MaxSubpackets_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxSubpackets", (tUINT32)strlen("MaxSubpackets"), (tUINT64) pHostPropertiesIn->MaxSubpackets );

         if( pHostPropertiesIn->MaxMethods_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"MaxMethods", (tUINT32)strlen("MaxMethods"), (tUINT64) pHostPropertiesIn->MaxMethods );

         if( pHostPropertiesIn->ContinuedTokens_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"ContinuedTokens", (tUINT32)strlen("ContinuedTokens"), (tUINT64) pHostPropertiesIn->ContinuedTokens );

         if( pHostPropertiesIn->SequenceNumbers_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"SequenceNumbers", (tUINT32)strlen("SequenceNumbers"), (tUINT64) pHostPropertiesIn->SequenceNumbers );

         if( pHostPropertiesIn->AckNak_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"AckNak", (tUINT32)strlen("AckNak"), (tUINT64) pHostPropertiesIn->AckNak );

         if( pHostPropertiesIn->Asynchronous_isValid )
            p = m_tokenProcessor.buildNamedValueToken( p, (tUINT8 *)"Asynchronous", (tUINT32)strlen("Asynchronous"), (tUINT64) pHostPropertiesIn->Asynchronous );

         p = m_tokenProcessor.buildEndList( p );
         p = m_tokenProcessor.buildEndName( p );
      }
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_CALL, UID_SESSION_MANAGER, UID_M_PROPERTIES );

      p = &respSubPacketPayload[1];
      p += m_tokenProcessor.sizeofShortAtom( p ); // SMUID, checked
      p += m_tokenProcessor.sizeofShortAtom( p ); // PROPERTIES_UID, checked

      if( !m_tokenProcessor.isStartList(*p) )     // Generic returned list for any method call
         throw dta::Error(eGenericInvalidIdentifier);

      //
      // Parse and process Properties attribute items
      //
      tUINT32 totalLength = m_tokenProcessor.sizeofListTokenData( p++ );
      tUINT32 length;
      tUINT8 *p1;

      // First, TPer Properties list in [ name = value ... ]
      length = m_tokenProcessor.sizeofListTokenData( p );
      if( !m_tokenProcessor.isListToken( *p ) || 0 == length )
         throw dta::Error(eGenericInvalidIdentifier);

      if( NULL != pTPerProperties && !pTPerProperties->isEmpty() )
      {
         if( pTPerProperties->MaxComPacketSize_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxComPacketSize", sizeof("MaxComPacketSize")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxComPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxComPacketSize_isValid = false;
         } // if( pTPerProperties->MaxComPacketSize_isValid )

         if( pTPerProperties->MaxResponseComPacketSize_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxResponseComPacketSize", sizeof("MaxResponseComPacketSize")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxResponseComPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxResponseComPacketSize_isValid = false;
         } // if( pTPerProperties->MaxResponseComPacketSize_isValid )

         if( pTPerProperties->MaxPacketSize_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxPacketSize", sizeof("MaxPacketSize")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxPacketSize_isValid = false;
         } // if( pTPerProperties->MaxPacketSize_isValid )

         if( pTPerProperties->MaxIndTokenSize_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxIndTokenSize", sizeof("MaxIndTokenSize")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxIndTokenSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxIndTokenSize_isValid = false;
         } // if( pTPerProperties->MaxIndTokenSize_isValid )

         if( pTPerProperties->MaxAggTokenSize_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxAggTokenSize", sizeof("MaxAggTokenSize")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxAggTokenSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxAggTokenSize_isValid = false;
         } // if( pTPerProperties->MaxAggTokenSize_isValid )

         if( pTPerProperties->MaxPackets_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxPackets", sizeof("MaxPackets")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxPackets = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxPackets_isValid = false;
         } // if( pTPerProperties->MaxPackets_isValid )

         if( pTPerProperties->MaxSubpackets_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxSubpackets", sizeof("MaxSubpackets")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxSubpackets = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxSubpackets_isValid = false;
         } // if( pTPerProperties->MaxSubpackets_isValid )

         if( pTPerProperties->MaxMethods_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxMethods", sizeof("MaxMethods")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxMethods = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxMethods_isValid = false;
         } // if( pTPerProperties->MaxMethods_isValid )

         if( pTPerProperties->MaxSessions_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxSessions", sizeof("MaxSessions")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxSessions = (tUINT16) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxSessions_isValid = false;
         } // if( pTPerProperties->MaxSessions_isValid )

         if( pTPerProperties->MaxReadSessions_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxReadSessions", sizeof("MaxReadSessions")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxReadSessions = (tUINT16) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxReadSessions_isValid = false;
         } // if( pTPerProperties->MaxReadSessions_isValid )

         if( pTPerProperties->MaxAuthentications_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxAuthentications", sizeof("MaxAuthentications")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxAuthentications = (tUINT16) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxAuthentications_isValid = false;
         } // if( pTPerProperties->MaxAuthentications_isValid )

         if( pTPerProperties->MaxTransactionLimit_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxTransactionLimit", sizeof("MaxTransactionLimit")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxTransactionLimit = (tUINT16) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxTransactionLimit_isValid = false;
         } // if( pTPerProperties->MaxTransactionLimit_isValid )

         if( pTPerProperties->DefSessionTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"DefSessionTimeout", sizeof("DefSessionTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->DefSessionTimeout = m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->DefSessionTimeout_isValid = false;
         } // if( pTPerProperties->DefSessionTimeout_isValid )

         if( pTPerProperties->MaxSessionTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxSessionTimeout", sizeof("MaxSessionTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxSessionTimeout = m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxSessionTimeout_isValid = false;
         } // if( pTPerProperties->MaxSessionTimeout_isValid )

         if( pTPerProperties->MinSessionTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MinSessionTimeout", sizeof("MinSessionTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->MinSessionTimeout = m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MinSessionTimeout_isValid = false;
         } // if( pTPerProperties->MinSessionTimeout_isValid )

         if( pTPerProperties->DefTransTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"DefTransTimeout", sizeof("DefTransTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->DefTransTimeout = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->DefTransTimeout_isValid = false;
         } // if( pTPerProperties->DefTransTimeout_isValid )

         if( pTPerProperties->MaxTransTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxTransTimeout", sizeof("MaxTransTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxTransTimeout = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxTransTimeout_isValid = false;
         } // if( pTPerProperties->MaxTransTimeout_isValid )

         if( pTPerProperties->MinTransTimeout_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MinTransTimeout", sizeof("MinTransTimeout")-1 );
            if( NULL != p1 )
               pTPerProperties->MinTransTimeout = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MinTransTimeout_isValid = false;
         } // if( pTPerProperties->MinTransTimeout_isValid )

         if( pTPerProperties->MaxComIDTime_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxComIDTime", sizeof("MaxComIDTime")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxComIDTime = m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxComIDTime_isValid = false;
         } // if( pTPerProperties->MaxComIDTime_isValid )

         if( pTPerProperties->MaxComIDCMD_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxComIDCMD", sizeof("MaxComIDCMD")-1 );
            if( NULL != p1 )
               pTPerProperties->MaxComIDCMD = (tUINT32) m_tokenProcessor.getAtomData( p1 );
            else
               pTPerProperties->MaxComIDCMD_isValid = false;
         } // if( pTPerProperties->MaxComIDCMD_isValid )

         if( pTPerProperties->ContinuedTokens_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"ContinuedTokens", sizeof("ContinuedTokens")-1 );
            if( NULL != p1 )
                pTPerProperties->ContinuedTokens = m_tokenProcessor.getAtomData( p1 ) ? true : false;
            else
               pTPerProperties->ContinuedTokens_isValid = false;
         } // if( pTPerProperties->ContinuedTokens_isValid )

         if( pTPerProperties->SequenceNumbers_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"SequenceNumbers", sizeof("SequenceNumbers")-1 );
            if( NULL != p1 )
                pTPerProperties->SequenceNumbers = m_tokenProcessor.getAtomData( p1 ) ? true : false;
            else
               pTPerProperties->SequenceNumbers_isValid = false;
         } // if( pTPerProperties->SequenceNumbers_isValid )

         if( pTPerProperties->AckNak_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"AckNak", sizeof("AckNak")-1 );
            if( NULL != p1 )
                pTPerProperties->AckNak = m_tokenProcessor.getAtomData( p1 ) ? true : false;
            else
               pTPerProperties->AckNak_isValid = false;
         } // if( pTPerProperties->AckNak_isValid )

         if( pTPerProperties->Asynchronous_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"Asynchronous", sizeof("Asynchronous")-1 );
            if( NULL != p1 )
                pTPerProperties->Asynchronous = m_tokenProcessor.getAtomData( p1 ) ? true : false;
            else
               pTPerProperties->Asynchronous_isValid = false;
         } // if( pTPerProperties->Asynchronous_isValid )

         if( pTPerProperties->RealTimeClock_isValid )
         {
            p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"RealTimeClock", sizeof("RealTimeClock")-1 );
            if( NULL != p1 )
                pTPerProperties->RealTimeClock = m_tokenProcessor.getAtomData( p1 ) ? true : false;
            else
               pTPerProperties->RealTimeClock_isValid = false;
         } // if( pTPerProperties->RealTimeClock_isValid )
      } // if( NULL != pTPerProperties && !pTPerProperties->isEmpty() )


      // Next, Host Properties list in 0 = [ name = value ... ], if any
      if( NULL != pHostPropertiesOut && !pHostPropertiesOut->isEmpty() )
      {
         p += length + 2; // skip the TPerProperties list
         p1 = decodeNamedValueName( p, totalLength - length -2, "HostProperties", 0 );
         if( NULL == p1 )
         {
            pHostPropertiesOut->setStateAll( false );
            p += totalLength - length -2;
         }
         else
         {
            // Found HostProperties list
            p = p1;
            length = m_tokenProcessor.sizeofListTokenData( p );
            if( !m_tokenProcessor.isListToken( *p ) )
            {
               throw dta::Error(eGenericInvalidIdentifier);
            }
            else if( 0 == length )
            {
               pHostPropertiesOut->setStateAll( false );
            }
            else
            {
               if( pHostPropertiesOut->MaxComPacketSize_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxComPacketSize", sizeof("MaxComPacketSize")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxComPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxComPacketSize_isValid = false;
               } // if( pHostPropertiesOut->MaxComPacketSize_isValid )

               if( pHostPropertiesOut->MaxResponseComPacketSize_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxResponseComPacketSize", sizeof("MaxResponseComPacketSize")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxResponseComPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxResponseComPacketSize_isValid = false;
               } // if( pHostPropertiesOut->MaxResponseComPacketSize_isValid )

               if( pHostPropertiesOut->MaxPacketSize_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxPacketSize", sizeof("MaxPacketSize")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxPacketSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxPacketSize_isValid = false;
               } // if( pHostPropertiesOut->MaxPacketSize_isValid )

               if( pHostPropertiesOut->MaxIndTokenSize_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxIndTokenSize", sizeof("MaxIndTokenSize")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxIndTokenSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxIndTokenSize_isValid = false;
               } // if( pHostPropertiesOut->MaxIndTokenSize_isValid )

               if( pHostPropertiesOut->MaxAggTokenSize_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxAggTokenSize", sizeof("MaxAggTokenSize")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxAggTokenSize = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxAggTokenSize_isValid = false;
               } // if( pHostPropertiesOut->MaxAggTokenSize_isValid )

               if( pHostPropertiesOut->MaxPackets_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxPackets", sizeof("MaxPackets")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxPackets = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxPackets_isValid = false;
               } // if( pHostPropertiesOut->MaxPackets_isValid )

               if( pHostPropertiesOut->MaxSubpackets_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxSubpackets", sizeof("MaxSubpackets")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxSubpackets = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxSubpackets_isValid = false;
               } // if( pHostPropertiesOut->MaxSubpackets_isValid )

               if( pHostPropertiesOut->MaxMethods_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"MaxMethods", sizeof("MaxMethods")-1 );
                  if( NULL != p1 )
                     pHostPropertiesOut->MaxMethods = (tUINT32) m_tokenProcessor.getAtomData( p1 );
                  else
                     pHostPropertiesOut->MaxMethods_isValid = false;
               } // if( pHostPropertiesOut->MaxMethods_isValid )

               if( pHostPropertiesOut->ContinuedTokens_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"ContinuedTokens", sizeof("ContinuedTokens")-1 );
                  if( NULL != p1 )
                      pHostPropertiesOut->ContinuedTokens = m_tokenProcessor.getAtomData( p1 ) ? true : false;
                  else
                     pHostPropertiesOut->ContinuedTokens_isValid = false;
               } // if( pHostPropertiesOut->ContinuedTokens_isValid )

               if( pHostPropertiesOut->SequenceNumbers_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"SequenceNumbers", sizeof("SequenceNumbers")-1 );
                  if( NULL != p1 )
                      pHostPropertiesOut->SequenceNumbers = m_tokenProcessor.getAtomData( p1 ) ? true : false;
                  else
                     pHostPropertiesOut->SequenceNumbers_isValid = false;
               } // if( pHostPropertiesOut->SequenceNumbers_isValid )

               if( pHostPropertiesOut->AckNak_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"AckNak", sizeof("AckNak")-1 );
                  if( NULL != p1 )
                      pHostPropertiesOut->AckNak = m_tokenProcessor.getAtomData( p1 ) ? true : false;
                  else
                     pHostPropertiesOut->AckNak_isValid = false;
               } // if( pHostPropertiesOut->AckNak_isValid )

               if( pHostPropertiesOut->Asynchronous_isValid )
               {
                  p1 = m_tokenProcessor.retrieveNamedDataFromStream( p+1, length, (tUINT8*)"Asynchronous", sizeof("Asynchronous")-1 );
                  if( NULL != p1 )
                      pHostPropertiesOut->Asynchronous = m_tokenProcessor.getAtomData( p1 ) ? true : false;
                  else
                     pHostPropertiesOut->Asynchronous_isValid = false;
               } // if( pHostPropertiesOut->Asynchronous_isValid )
            }

            p += length + 3; // skip the HostProperties list and EON
         }
      } 
      else
      {
         p += totalLength; // skip the entire method returned data list contents
      } // if( NULL != pHostPropertiesOut && !pHostPropertiesOut->isEmpty() )

      if( !m_tokenProcessor.isEndList(*p) )       // End of Generic returned list for any method call
         throw dta::Error(eGenericInvalidIdentifier);

      m_packetManager.setTPerSN( oldTPerSN );
      m_packetManager.setHostSN( oldHostSN );
   }
   M_TCGCatch( true, true );
} // properties

//=================================================================================
/// \brief Request supported security protocol ID list from the TPer.
///
/// \param numberIDs    [OUT]  Number of protocol IDs returned.
/// \param IDs          [OUT]  Returned ID list, one byte each.
///
/// \return status byte of the IF-Recv for this call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::getSupportedProtocolIDs( tUINT16 & numberIDs, dta::tBytes & IDs )
{
   securityIFRecv( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY, SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST );
   numberIDs = m_swapper.NetToHost( *((tUINT16*)(&m_responseBuffer[6])) ); //Byte 6 (MSB) & 7 (LSB)
   if( numberIDs + 8 > m_blockSize )
   {
      numberIDs = 0;
      throw dta::Error(eGenericInvalidIdentifier);
   }

   IDs.resize( numberIDs );
   if( numberIDs > 0 )
      memcpy( &IDs[0], &m_responseBuffer[8], numberIDs );

   return TS_SUCCESS;
} // getSupportedProtocolIDs

//=================================================================================
/// \brief Request FIPS Compliance Descriptor Info, if available, from the TPer. 
///
/// \param Revision     [OUT]  Char '2' or '3' indicating FIPS 140- level; Char ' ' means no Compliance descriptor.
/// \param OverallLevel [OUT]  Char '1' to '4' indicating Overall compliance level.
/// \param HardwareVer  [OUT]  ATA String (128 chars max)
/// \param FirmwareVer  [OUT]  ATA String (128 chars max)
/// \param ModuleName   [OUT]  ATA String (256 chars max)
///
/// \return status byte of the IF-Recv command. If command supported but no info to report, return default "no-FIPS" values.
//=================================================================================
TCG_STATUS CTcgCoreInterface::getFipsComplianceInfo( char & Revision, char & OverallLevel,
                                                     std::string &HardwareVer, std::string &FirmwareVer,
                                                     std::string &ModuleName )
{
   // This function added jls 20120812 - TCG1_2_0


   M_TCGTry()
   {
      // Make sure to read at least two blocks of data since Crypto Module descriptor is larger than 512.
      securityIFRecv( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY, SPSPECIFIC_P00_SECURITY_COMPLIANCE_INFO, 2 );
   }
   M_TCGCatchOnly( false );      // Don't throw an error if command fails

   // If drive does not support this feature, it will abort the command and we must get FIPS info elsewhere. 
   if( ! M_TCGResultOK() )
   {
      dta::DTA_ERROR err = getLastError();
      if( err.Info.Category != eDtaCategoryDirect || err.Info.Detail != eDirectDeviceAbort )
         return M_TCGResult();   // Some other error that user must deal with.

      return TS_FAIL;      // Let caller know the Security Compliance query was aborted by drive.
   }
   
   // The command is supported, so scan results to see if Security Compliance descriptor is returned.
   tUINT32 lenDescriptors = m_swapper.NetToHost(*((tUINT32*)(&m_responseBuffer[0])) ); // Bytes 0 to 3

   // Newer non-FIPS SEDs return length of Descriptors as 0, meaning drive has no Security Compliance
   // info, but this is an expected condition so return default Security Compliance values and Success.
   if( lenDescriptors == 0 )
   {
     // Set default return values to "non-FIPS" to indicate zero-length Security Compliance data.
      Revision = ' ';
      OverallLevel = ' ';
      return TS_SUCCESS;   // Zero-length descriptor is OK; just return default non-FIPS reply.
   }

   // If Length of Security Compliance Descriptors is non-zero, then walk the descriptor list
   // looking for the Compliance Descriptor Tag SPS_SEC_REQ_FOR_CRYPTOGRAPHIC_MODULES_TYPE (0x0001),
   // which is the "Compliance Requirements for Cryptographic Modules" descriptor.
    
   tUINT32 offset = 4;    // Offset to start of current descriptor in responseBuffer

   while( offset < lenDescriptors )
   {
      // Bytes 0,1 in descriptor are Descriptor Type Field
      tUINT16 descType = *((tUINT16*)(&m_responseBuffer[offset])); 

      // Bytes 4 to 7 are length of the descriptor not including the first 8 bytes of header info.
      tUINT32 length = *((tUINT32*)(&m_responseBuffer[offset+4]));

      // Check for malformed results and return a catastrophic error if something's wrong.
      if( length == 0 || lenDescriptors < length )
      {
            throw( TS_TPER_MALFUNCTION );    // BUGBUG: Is this the correct thing to throw? Probably not.  jls
      }

      // Is this the Security Compliance descriptor we are looking for?
      if( descType == SPS_SEC_REQ_FOR_CRYPTOGRAPHIC_MODULES_TYPE )
      {
         // Walk thru descriptor info returned to parse descriptor
         Revision = m_responseBuffer[offset + 8];        // FIPS 140 revision (2 or 3)
         OverallLevel = m_responseBuffer[offset + 9];    // FIPS 140 Rev X Level (1 to 4)

         // ATA Strings are blank padded (but I have seen null padding), and stored in "network" byte order.
         // Search from end of buffer to find first non-pad char marking length of ATA String.

         // Scan HardwareVersion field
         tUINT16 first = 16 + offset; // First char of HW Version field
         tUINT16 last = first + 128;  // Last char of HW Version field
         
         // Find last non-blank or non-null char
         while( last-- > first && ( (char)m_responseBuffer[last] == ' ' || (char)m_responseBuffer[last] == '\000') )
            ;
         last += (last & 1);              // round up to char pair size so byte-swap doesn't fail.
         HardwareVer.resize( last - first + 1 );
         // Copy descriptor ATA String to HardwareVer
         for( tUINT16 i = 0; first < last; first+=2, i+=2 )
         {
            HardwareVer[i] = m_responseBuffer[first+1];
            HardwareVer[i+1] = m_responseBuffer[first];
         }  
         
         // Scan FirmwareVersion field
         first = 144 + offset; // First char of FW Version field
         last = first + 128;  // Last char of FW Version field
         // Find last non-blank or non-null char
         while( last-- > first && ( (char)m_responseBuffer[last] == ' ' || (char)m_responseBuffer[last] == '\000') )
            ;
         last += (last & 1);              // round up to char pair size so byte-swap doesn't fail.
         FirmwareVer.resize( last - first + 1 );
         // Copy ATA String to FirmwareVer
         for( tUINT16 i = 0; first < last; first+=2, i+=2 )
         {
            FirmwareVer[i] = m_responseBuffer[first+1];
            FirmwareVer[i+1] = m_responseBuffer[first];
         }  
                  
         // Scan ModuleName field
         first = 272 + offset;   // First char of field
         last = first + 256;     // Last char of field

         while( last-- > first && ( (char)m_responseBuffer[last] == ' ' || (char)m_responseBuffer[last] == '\000') )
            ;
         last += (last & 1);              // round up to char pair size so byte-swap doesn't fail.
         ModuleName.resize( last - first + 1 );
         // Copy ATA String to ModuleName
         for( tUINT16 i = 0; first < last; first+=2, i+=2 )
         {
            ModuleName[i] = m_responseBuffer[first+1];
            ModuleName[i+1] = m_responseBuffer[first];
         }  
         
      } // if( descType == SPS_SEC_REQ_FOR_CRYPTOGRAPHIC_MODULES_TYPE )

      // Add other Compliance Descriptor Type Parsing here
      //  (Current spec lists no other types)

      // Adjust offset to start of next descriptor, if any.
      offset += (length + 8);
   } // while

   return TS_SUCCESS;

} // getFipsComplianceInfo


//=================================================================================
/// \brief Request Level 0 device discovery data from the TPer.
///
/// \return status byte of the IF-Recv for this call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::refreshLevel0DiscoveryData()
{
   tUINT32 length;

#ifdef __TCGSILO
   if( useSilo() )
   {
      tUINT16 siloComID;
      m_TCGSilo->getSiloCapabilites(m_responseBuffer, &siloComID);
      length = m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[0])) ) + sizeof(tUINT32);
      m_packetManager.setExtendedComID( (((tUINT32) siloComID) << 16 ) & 0xFFFF0000 );
   } // if
   else
#endif
   {
      securityIFRecv( SECURITY_PROTOCOLID_COMPACKET_IO, SPSPECIFIC_P01_LEVEL0_DISCOVERY );

      // parsing the details here
      length = m_swapper.NetToHost( *((tUINT32*)(&m_responseBuffer[0])) ) + sizeof(tUINT32);
      if( length > m_blockSize )
         securityIFRecv( SECURITY_PROTOCOLID_COMPACKET_IO, SPSPECIFIC_P01_LEVEL0_DISCOVERY, (length + m_blockSize -1)/m_blockSize );
   } // else

   if( length < L0_DISCOVERY_HEADER_SIZE + L0_DISCOVERY_TPERDESCRIPTOR_SIZE + L0_DISCOVERY_LOCKINGDESCRIPTOR_SIZE + L0_DISCOVERY_SSCDESCRIPTOR_SIZE )
      throw dta::Error(eGenericInvalidIdentifier);

   // Vendor-specific fields in header
   m_Level0_LifeCycleState = m_responseBuffer[17]; 
   m_Level0_VendorFeatureSupported = m_responseBuffer[19];
   m_Level0_VendorFeatureEnabled = m_responseBuffer[21];

   tUINT8* p = &m_responseBuffer[L0_DISCOVERY_HEADER_SIZE];
   if( L0_DISCOVERY_FEATURECODE_TPER != m_swapper.NetToHost( *((tUINT16*)p) ) ) // Expecting TPER as the first descriptor
      throw dta::Error(eGenericInvalidIdentifier);

   m_Level0_Tper_Data[0] = *(p + 4);      // TPer Descriptor

   p += 4 + *(p + 3);
   if( L0_DISCOVERY_FEATURECODE_LOCKING != m_swapper.NetToHost( *((tUINT16*)p) ) ) // Expecting Locking as the 2nd descriptor
      throw dta::Error(eGenericInvalidIdentifier);

   m_Level0_Locking_Data[0] = *(p + 4);   // Locking Descriptor

   p += 4 + *(p + 3);
   m_Level0_SSC_Code = m_swapper.NetToHost( *((tUINT16*)p) ); // Expecting SSC descriptor
   switch( m_Level0_SSC_Code )
   {
      case L0_DISCOVERY_FEATURECODE_SSC_ENTERPRISE:
         if( 0 == m_Level0_MaxTotalSizeOfDataStoreTables )
            m_Level0_MaxTotalSizeOfDataStoreTables = 1024;
      
      case L0_DISCOVERY_FEATURECODE_SSC_OPAL:
         m_Level0_SSC_BaseComID = m_swapper.NetToHost( *((tUINT16*)(p+4)) );
         m_Level0_SSC_NumberComID = m_swapper.NetToHost( *((tUINT16*)(p+6)) );
         m_Level0_SSC_RangeCrossingAllowed = *(p + 8);  // jls20120227
         // Set default values for drives that don't report DataStore Table info.
         m_Level0_DataStoreTableFeatureSet = true;
         m_Level0_MaxNumOfDataStoreTables = 1;
         if( 0 == m_Level0_MaxTotalSizeOfDataStoreTables )
            m_Level0_MaxTotalSizeOfDataStoreTables = 1024 * 1024 * 10;
         m_Level0_DataStoreTableSizeAlignment = 1;
         break;

      case L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2: // nvn20110520
         m_Level0_SSC_BaseComID = m_swapper.NetToHost( *((tUINT16*)(p+4)) );
         m_Level0_SSC_NumberComID = m_swapper.NetToHost( *((tUINT16*)(p+6)) );
         m_Level0_SSC_RangeCrossingAllowed = *(p + 8);  // jls20120227
         // Byte 8:B0: Range Crossing (1 - no range crossing allowed).
         // Bytes 9-10: Max LockingSP Admins, Bytes 11-12: MaxLockingSP Users,
         // Byte 13: initial 0x00(SID = MSID) or 0xff(SID=unknown),
         // Byte 14: on Revert, 0x00(SID=MSID) or 0xff(SID=unknown).
         m_Level0_SSC_MaxLockingAdmins =  m_swapper.NetToHost( *((tUINT16*)(p+9)) ); // jls20120227
         m_Level0_SSC_MaxLockingUsers =  m_swapper.NetToHost( *((tUINT16*)(p+11)) );
         m_Level0_SSC_DefaultSIDisMSID = *(p + 13);
         m_Level0_SSC_OnRevertSIDisMSID = *(p + 14);
         break;

      default: // unrecognized or invalid descriptor ID
         m_Level0_SSC_Code = L0_DISCOVERY_FEATURECODE_UNSET;
         throw dta::Error(eGenericInvalidIdentifier);
   }

   // Look through remaining optional descriptors for those of interest that may be returned by the TPer
   while( 1 )
   {
      p += 4 + *(p + 3);
      if( p >= &m_responseBuffer[0] + length )
         break;

      tUINT16 code = m_swapper.NetToHost( *((tUINT16*)p) );
      switch( code )
      {
         case L0_DISCOVERY_FEATURECODE_SSC_OPAL_SINGLEUSERMODE:
            m_singleUserModeSupported = true;
            m_Level0_SingleUserFixedACL_NumLockingObjects = m_swapper.NetToHost( *((tUINT32*)(p + 4)) );
            m_Level0_SingleUserFixedACL_Mode = *(p + 8);
            break;

         case L0_DISCOVERY_FEATURECODE_SSC_OPAL_DATASTORETABLE:
            m_Level0_DataStoreTableFeatureSet = true;
            m_Level0_MaxNumOfDataStoreTables = m_swapper.NetToHost( *((tUINT16*)(p + 6)) );
            m_Level0_MaxTotalSizeOfDataStoreTables = m_swapper.NetToHost( *((tUINT32*)(p + 8)) );
            m_Level0_DataStoreTableSizeAlignment = m_swapper.NetToHost( *((tUINT32*)(p + 12)) );
            break;

         case L0_DISCOVERY_FEATURECODE_SSC_OPAL_GEOMETRY:
            m_Level0_AlignmentRequired = (((*(tUINT8*)(p + 4)) & 0x01) == 0x01);
            m_Level0_LogicalBlockSize = m_swapper.NetToHost( *((tUINT32*)(p + 12)) );
            m_Level0_AlignmentGranularity = m_swapper.NetToHost( *((tUINT64*)(p + 16)) );
            m_Level0_LowestAlignedLBA = m_swapper.NetToHost( *((tUINT64*)(p + 24)) );
            break;

         case L0_DISCOVERY_FEATURECODE_VU_STX_LOGICALPORT:
            tUINT16 len = *((tUINT8*)(p + 3));
            m_Level0_LogicalPortsAvailable = len/8;

            if( m_Level0_LogicalPortsAvailable > 0 )
            {
               m_Level0_LogicalPortData.resize( len );
               memcpy( &m_Level0_LogicalPortData[0], p + 4, m_Level0_LogicalPortData.size() );
            }
            break;

            //
            // Add in parsing code here when the need arises for new Level 0 descriptors.
            //
            break;
      }
   }

   return TS_SUCCESS;
} // refreshLevel0DiscoveryData

//=================================================================================
/// \brief Request Level 0 device discovery data from the TPer.
///
/// \param data         [OUT]  Returned Level 0 device discovery data.
///
/// \return status byte of the IF-Recv for this call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::getLevel0DiscoveryData( dta::tBytes & data )
{
   TCG_STATUS status = refreshLevel0DiscoveryData();
   data.resize( m_responseBuffer.size() );
   memcpy( &data[0], &m_responseBuffer[0], data.size() );

   return status;
} // getLevel0DiscoveryData

//=================================================================================
/// \brief Check if the device supports TCG ComPacket protocol, based on Protocol 0 discovery.
/// \return true if TCG protocol supported, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isTCGProtocolSupported()
{
   tUINT16 numberIDs;
   dta::tBytes IDs;

   getSupportedProtocolIDs( numberIDs, IDs );

   for( int ii=0; ii<numberIDs; ii++ )
   {
      if( SECURITY_PROTOCOLID_COMPACKET_IO == IDs[ii] )
         return true;
   }

   return false;
} // isTCGProtocolSupported

//=================================================================================
/// \brief Check if TPer supports ComID Management through the flag bit in TPer SSC desciptor.
/// \return true if ComIDMgmt Supported, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isComIDMgmtSupported()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_Tper_Data[0] & 0x40 ) ? true : false;
} // isComIDMgmtSupported

//=================================================================================
/// \brief Check if it is an Enterprise SSC device, based on Level 0 discovery.
/// \return true if Enterprise SSC, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceEnterpriseSSC()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( L0_DISCOVERY_FEATURECODE_SSC_ENTERPRISE == m_Level0_SSC_Code ) ? true : false;
} // isDeviceEnterpriseSSC

//=================================================================================
/// \brief Check if it is an Opal SSC device, based on Level 0 discovery.
/// \return true if Opal SSC, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceOpalSSC()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   if ( L0_DISCOVERY_FEATURECODE_SSC_OPAL == m_Level0_SSC_Code ||
        L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2 == m_Level0_SSC_Code ) // nvn20110520
   {
	   return true;
   }
   else
   {
	   return false;
   }
} // isDeviceOpalSSC

//=================================================================================
/// \brief Check if it is an Opal SSC Version 2 device, based on Level 0 discovery.
/// \return true if Opal SSC Version 2, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceOpalSSCVersion2()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   if ( L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2 == m_Level0_SSC_Code )
   {
	   return true;
   }
   else
   {
	   return false;
   }
} // isDeviceOpalSSCVersion2

//=================================================================================
/// \brief Check if it is a Marble SSC device, based on Level 0 discovery.
/// \return true if Marble SSC, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceMarbleSSC()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( L0_DISCOVERY_FEATURECODE_SSC_MARBLE == m_Level0_SSC_Code ) ? true : false;
} // isDeviceMarbleSSC

//=================================================================================
/// \brief Turn on or off the flag of using TCG Silo, and prepare a proper COM ID for it.
/// \return void.
//=================================================================================
void CTcgCoreInterface::setUseSilo(const bool newUseSilo)
{
   m_useSilo = newUseSilo;

   if( !m_hasSilo )
      return;

   refreshLevel0DiscoveryData();

   if( !m_useSilo )
      m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );

} // setUseSilo

//=================================================================================
/// \brief Returns the Base ComID, based on Level 0 discovery data.
/// \return Base ComID value.
//=================================================================================
tUINT16 CTcgCoreInterface::getBaseComID()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_BaseComID;
} // getBaseComID

//=================================================================================
/// \brief Returns Max Number of ComIDs, based on Level 0 discovery data.
/// \return Base MaxComID value.
//=================================================================================
tUINT16 CTcgCoreInterface::getNumberOfComIDs()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_NumberComID;
} // getNumberOfComIDs

// jls20120227
//=================================================================================
/// \brief Returns RangeCrossingAllowed, based on Level 0 discovery data.
/// \return RangeCrossingAllowed value.
//=================================================================================
tUINT8 CTcgCoreInterface::getRangeCrossingAllowed()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_RangeCrossingAllowed;
} // getRangeCrossingAllowed

// jls20120227
//=================================================================================
/// \brief Returns Maximum LockingSP Admins, based on Level 0 discovery data.
/// \return MaxLockingSPAdmins value.
//=================================================================================
tUINT16 CTcgCoreInterface::getMaxLockingSPAdmins()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_MaxLockingAdmins;
} // getMaxLockingSPAdmins

// jls20120227
//=================================================================================
/// \brief Returns Maximum LockingSP Users, based on Level 0 discovery data.
/// \return MaxLockingSPUsers value.
//=================================================================================
tUINT16 CTcgCoreInterface::getMaxLockingSPUsers()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_MaxLockingUsers;
} // getMaxLockingSPUsers

// jls20120227
//=================================================================================
/// \brief Returns default SID Value, based on Level 0 discovery data.
/// \return DefaultSIDisMSID value.
//=================================================================================
tUINT8 CTcgCoreInterface::getSIDdefaultValue()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_DefaultSIDisMSID;
} // getSIDdefaultValue

// jls20120227
//=================================================================================
/// \brief Returns SID value after Reset, based on Level 0 discovery data.
/// \return OnRevertSIDvalue.
//=================================================================================
tUINT8 CTcgCoreInterface::getSIDOnRevertValue()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_SSC_OnRevertSIDisMSID;
} // getSIDOnRevertValue


//=================================================================================
/// \brief Check if one or more the LBA ranges are locked, based on Level 0 discovery (always refresh).
/// \return true if locked, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceLocked( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_Locking_Data[0] & L0_DISCOVERY_LOCK_LOCKED_MASK ) ? true : false;
} // isDeviceLocked

//=================================================================================
/// \brief Check if MBR Done bit set, based on Level 0 discovery (always refresh).
/// \return true if MBR Done set, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceMBRDone( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_Locking_Data[0] & L0_DISCOVERY_LOCK_MBRDONE_MASK ) ? true : false;
} // isDeviceMBRDone

//=================================================================================
/// \brief Check if MBR enabled, based on Level 0 discovery (always refresh).
/// \return true if MBR enabled, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isDeviceMBREnabled( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_Locking_Data[0] & L0_DISCOVERY_LOCK_MBRENABLED_MASK ) ? true : false;
} // isDeviceMBREnabled

//=================================================================================
/// \brief Check if the Single-User-Mode descriptor is returned by TPer via Level 0 discovery.
/// \return true if Single-User-Mode descriptor is returned, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isSingleUserModeSupported()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_singleUserModeSupported;
} // isSingleUserModeSupported

//=================================================================================
/// \brief Check if the "Any" bit set in the Single-User-Mode descriptor of Level 0 discovery (always refresh).
/// \return true if Any bit = 1, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isAnyInSingleUserMode( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_SingleUserFixedACL_Mode & L0_DISCOVERY_OPAL_SINGLEUSERMODE_ANY_MASK ) ? true : false;
} // isAnyInSingleUserMode

//=================================================================================
/// \brief Check if the "All" bit set in the Single-User-Mode descriptor of Level 0 discovery (always refresh).
/// \return true if All bit = 1, false otherwise.
//=================================================================================
bool CTcgCoreInterface::areAllInSingleUserMode( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_SingleUserFixedACL_Mode & L0_DISCOVERY_OPAL_SINGLEUSERMODE_ALL_MASK ) ? true : false;
} // areAllInSingleUserMode

//=================================================================================
/// \brief Check if the "Policy" bit set in the Single-User-Mode descriptor of Level 0 discovery (always refresh).
/// \return true if Policy bit = 1, false otherwise.
//=================================================================================
bool CTcgCoreInterface::isSingleUserModePolicyOwnedByAdmin( bool refresh )
{
   if( refresh || L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return ( m_Level0_SingleUserFixedACL_Mode & L0_DISCOVERY_OPAL_SINGLEUSERMODE_POLICY_MASK ) ? true : false;
} // isSingleUserModePolicyOwnedByAdmin

//=================================================================================
/// \brief Get the number of Locking Objects from the Level0 data if Single-User-Mode is supported.
/// \return the number of Locking Objects if Single-User-Mode is supported, otherwise 0.
//=================================================================================
tUINT32 CTcgCoreInterface::getSingleUserModeNumLockingObjects()
{
   if( isSingleUserModeSupported() )
      return m_Level0_SingleUserFixedACL_NumLockingObjects;
   else
      return 0;
} // getSingleUserModeNumLockingObjects


//=================================================================================
/// \brief Determine if DataStoreTableFeatureSet was Reported in Level0 data.
/// \return true if DataStoreTableFeatureSet was Reported, otherwise return false.
//=================================================================================
bool CTcgCoreInterface::isDataStoreTableFeatureSupported()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_DataStoreTableFeatureSet;
} // isDataStoreTableFeatureSupported

//=================================================================================
/// \brief Get the Maximum Number of DataStore Tables from the Level0 data if reported.
/// \return the Maximum Number of DataStore Tables, if reported, otherwise 0.
//=================================================================================
tUINT16 CTcgCoreInterface::getMaxNumberOfDataStoreTables()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_MaxNumOfDataStoreTables;
} // getMaxNumberOfDataStoreTables

//=================================================================================
/// \brief Get the Maximum Total Size Of DataStore Tables from the Level0 data if reported.
/// \return the Maximum Total Size Of DataStore Tables, if reported, otherwise 0.
//=================================================================================
tUINT32 CTcgCoreInterface::getMaxTotalSizeOfDataStoreTables()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_MaxTotalSizeOfDataStoreTables;
} // getMaxTotalSizeOfDataStoreTables

//=================================================================================
/// \brief Get the DataStore Table Size Alignment from the Level0 data if reported.
/// \return the DataStore Table Size Alignment, if reported, otherwise 0.
//=================================================================================
tUINT32 CTcgCoreInterface::getDataStoreTableSizeAlignment()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_DataStoreTableSizeAlignment;
} // getDataStoreTableSizeAlignment

//=================================================================================
/// \brief See if Alignment Required from Level0 Geometry descriptor if reported.
/// \return true if Alignment Required was reported, otherwise return false.
//=================================================================================
bool CTcgCoreInterface::isGeometryAlignmentRequired()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_AlignmentRequired;
}

//=================================================================================
/// \brief Get the Logical Block Size from Level0 Geometry descriptor if reported.
/// \return the Logical BLock Size, if reported, otherwise return default 4k.
//=================================================================================
tUINT32 CTcgCoreInterface::getGeometryLogicalBlockSize()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_LogicalBlockSize;
} // getGeometryLogicalBlockSize

//=================================================================================
/// \brief Get the Alignment Granularity from Level0 Geometry descriptor if reported.
/// \return the Alignment Granularity, if reported, otherwise return default 4k.
//=================================================================================
tUINT64 CTcgCoreInterface::getGeometryAlignmentGranularity()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_AlignmentGranularity;
} // getGeometryAlignmentGranularity

//=================================================================================
/// \brief Get the Lowest Aligned LBA from the Level0 Geometry descriptor if reported.
/// \return the Lowest Aligned LBA, if reported, otherwise 0.
//=================================================================================
tUINT64 CTcgCoreInterface::getGeometryLowestAlignedLBA()
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   return m_Level0_LowestAlignedLBA;
} // getGeometryLowestAlignedLBA

//=================================================================================
/// \brief Retrieve current Level0 LifeCycleState of drive.
/// \return true if Alignment Required was reported, otherwise return false.
//=================================================================================
tUINT8 CTcgCoreInterface::getLifeCycleState( bool Refresh )
{
   if( Refresh || (L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code) )
      refreshLevel0DiscoveryData();

   return m_Level0_LifeCycleState;
} // getLifeCycleState



//=================================================================================
/// \brief Synchronize the TCG communication Properties between Host and TPer via Properties method.
/// \return true if successful, otherwise false.
//=================================================================================
bool CTcgCoreInterface::synchronizeHostTPerProperties()
{
   M_TCGTry()
   {
      HostProperties hostProp;
      TPerProperties tperProp;

      if( properties( NULL, &tperProp, NULL ) != TS_SUCCESS )
         return false;

      hostProp.MaxComPacketSize = tperProp.MaxComPacketSize;
      hostProp.MaxComPacketSize_isValid = true;

      hostProp.MaxPacketSize = tperProp.MaxPacketSize;
      hostProp.MaxPacketSize_isValid = true;

      hostProp.MaxIndTokenSize = tperProp.MaxIndTokenSize;
      hostProp.MaxIndTokenSize_isValid = true;

      if( tperProp.MaxComPacketSize_isValid && tperProp.MaxPacketSize_isValid && tperProp.MaxIndTokenSize_isValid )
      {
         if( hostProp.MaxComPacketSize > 0 ) // 0 is a valid value, meaning no indication of size
         {
            m_commandBuffer.reserve( hostProp.MaxComPacketSize );
            m_responseBuffer.reserve( hostProp.MaxComPacketSize );
         }

         m_packetManager.setMaxComPacketSize( hostProp.MaxComPacketSize );
         m_packetManager.setMaxPacketSize( hostProp.MaxPacketSize );
         m_packetManager.setSessionTimeout( tperProp.DefSessionTimeout_isValid ? (tUINT32)tperProp.DefSessionTimeout : 0 );

         if( properties( &hostProp, NULL, NULL ) != TS_SUCCESS )
            return false;
      }
      else
      {
         // Set the defaults
         if( isDeviceEnterpriseSSC() )
         {
            m_commandBuffer.reserve( 1024 );
            m_responseBuffer.reserve( 1024 );
            m_packetManager.setMaxComPacketSize( 1024 );
            m_packetManager.setMaxPacketSize( 1004 );
         }

         if( isDeviceOpalSSC() )
         {
            m_commandBuffer.reserve( 2048 );
            m_responseBuffer.reserve( 2048 );
            m_packetManager.setMaxComPacketSize( 2048 );
            m_packetManager.setMaxPacketSize( 2028 );
         }

         m_packetManager.setSessionTimeout( 0 );
      }
   }
   M_TCGCatchOnly( false );

   return M_TCGResultOK();
} // synchronizeHostTPerProperties

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer.
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  HostChallenge = bytes,
///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param hostSigningAuthority   [IN]  UID ref value of the host signing authority. 0 indicates omitted parameter.      
/// \param hostChallenge          [IN]  Host-Challenge/password. NULL indicates omitted parameter.
/// \param hostChallengeLength    [IN]  Length of the Host-Challenge/password. Zero(0) indicates omitted parameter.
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                                 TCG_UID targetSP,
                                 TCG_UID hostSigningAuthority,
                                 tUINT8 *hostChallenge,
                                 tUINT16 hostChallengeLength,
                                 bool writeSession,
                                 tUINT32 HostSN,
                                 tINT64 sessionTimeout,
                                 bool syncHostTPerProperties )
{
   if( NULL == hostChallenge && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      hostChallenge = &m_MSID[0];
      hostChallengeLength = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
#ifdef TCGSILO_SPEC_R12  ///+++ For testing P22 R12 only, not required for subsequent newer specs
#ifdef __TCGSILO
      if( useSilo() )
      {
         tUINT16 siloComID;
         m_TCGSilo->getSiloCapabilites(m_responseBuffer, &siloComID);
         m_packetManager.setExtendedComID( (((tUINT32) siloComID) << 16 ) & 0xFFFF0000 );
      }
#endif
#endif  ///--- For TCGSILO_SPEC_R12

      if( m_useDynamicComID && isComIDMgmtSupported() )
      {
#ifdef __TCGSILO
         if( !useSilo() )
#endif
         {
            getComID();
#if defined(_WIN32) // TODO: // nvn20110719 - port to c++ assert
            _ASSERT( verifyComID( m_packetManager.getExtendedComID() ) == evISSUED );
#endif
         }
      }

      if( syncHostTPerProperties )
      {
         if( !synchronizeHostTPerProperties() )
            throw dta::Error(eGenericFatalError);
      }

      // Set to Session Manager, ComID should have been set
      m_packetManager.setTPerSN( 0 );
      m_packetManager.setHostSN( HostSN );

      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      // Construct a StartSession method call tokens
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_SESSION_MANAGER, UID_M_START_SESSION );
      p = m_tokenProcessor.buildIntAtom( p, (tUINT64)m_packetManager.getHostSN() );
      p = m_tokenProcessor.buildUID( p, targetSP );
      p = m_tokenProcessor.buildTinyAtom( p, (tUINT8)(writeSession ? 1:0) );

      if( UID_NULL != hostSigningAuthority && NULL != hostChallenge )
      {
         p = encodeNamedValue_Bytes( p, hostChallenge, hostChallengeLength, "HostChallenge", 0 );
         p = encodeNamedValue_UID( p, hostSigningAuthority, "HostSigningAuthority", 3 );
      }

      if( -1 != sessionTimeout )
         p = encodeNamedValue_Integer( p, (tUINT64)sessionTimeout, "SessionTimeout", 5 );

      p = m_tokenProcessor.buildCallTokenFooter( p );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      CTcgCoreInterface::securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_CALL, UID_SESSION_MANAGER, UID_M_SYNC_SESSION );

      // Check the returned call-token data
      p = &respSubPacketPayload[1];

      tUINT64 d;
      p = m_tokenProcessor.getShortAtomData( p, &d ); // SMUID, checked
      p = m_tokenProcessor.getShortAtomData( p, &d ); // SYNC_SESSION_UID, checked

      if( !m_tokenProcessor.isStartList(*p++) )
         throw dta::Error(eGenericInvalidIdentifier);

      p = m_tokenProcessor.getAtomData( p, &d ); // HostSN (adjustable length, up to 8B)
      p = m_tokenProcessor.getAtomData( p, &d ); // TPerSN (adjustable length, up to 8B)

      m_packetManager.setTPerSN( (tUINT32)d );
   }
   M_TCGCatch( true, true );
} // _startSession

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer.
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  HostChallenge = bytes,
///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param TPerSN                 [OUT] TPer session ID returned upon successful.
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param hostSigningAuthority   [IN]  UID ref value of the host signing authority. 0 indicates omitted parameter.      
/// \param hostChallenge          [IN]  Host-Challenge/password. NULL indicates omitted parameter.
/// \param hostChallengeLength    [IN]  Length of the Host-Challenge/password. Zero(0) indicates omitted parameter.
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                                 tUINT32 &TPerSN,
                                 TCG_UID targetSP,
                                 TCG_UID hostSigningAuthority,
                                 tUINT8 *hostChallenge,
                                 tUINT16 hostChallengeLength,
                                 bool writeSession,
                                 tUINT32 HostSN,
                                 tINT64 sessionTimeout,
                                 bool syncHostTPerProperties )
{
   TCG_STATUS status = _startSession( targetSP, hostSigningAuthority, hostChallenge, hostChallengeLength, writeSession, HostSN, sessionTimeout, syncHostTPerProperties );
   TPerSN = m_packetManager.getTPerSN();
   return status;
} // _startSession

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer.
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                                 TCG_UID targetSP,
                                 bool writeSession,
                                 tUINT32 HostSN,
                                 tINT64 sessionTimeout,
                                 bool syncHostTPerProperties )
{
   return _startSession( targetSP, UID_NULL, NULL, 0, writeSession, HostSN, sessionTimeout, syncHostTPerProperties );
} // _startSession

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer.
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param TPerSN                 [OUT] TPer session ID returned upon successful.
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                                 tUINT32 &TPerSN,
                                 TCG_UID targetSP,
                                 bool writeSession,
                                 tUINT32 HostSN,
                                 tINT64 sessionTimeout,
                                 bool syncHostTPerProperties )
{
   TCG_STATUS status = _startSession( targetSP, UID_NULL, NULL, 0, writeSession, HostSN, sessionTimeout, syncHostTPerProperties );
   TPerSN = m_packetManager.getTPerSN();
   return status;
} // _startSession

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  HostChallenge = bytes,
///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param TPerSN                 [OUT] TPer session ID returned upon successful.
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param authent                [IN]  AuthenticationParameter for authentication.      
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                            tUINT32 & TPerSN,
                            TCG_UID targetSP,
                            AuthenticationParameter & authent,
                            bool writeSession,
                            tUINT32 HostSN,
                            tINT64 sessionTimeout,
                            bool syncHostTPerProperties )
{
   TCG_STATUS status = _startSession( targetSP, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength, writeSession, HostSN, sessionTimeout, syncHostTPerProperties );
   TPerSN = m_packetManager.getTPerSN();
   return status;
} // _startSession

//=================================================================================
/// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
///
/// TCG method depiction
///   SessionManager.StartSession[   HostSessionID : uinteger,
///                                  SP : uid, 
///                                  Write : boolean,
///                                  HostChallenge = bytes,
///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
///                                  SessionTimeOut = uinteger ]
///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
///
/// \param targetSP               [IN]  UID of the target SP to establish the session with.
/// \param authent                [IN]  AuthenticationParameter for authentication.
/// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
/// \param HostSN                 [IN]  Host session ID specified, default is zero.
/// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startSession( 
                            TCG_UID targetSP,
                            AuthenticationParameter & authent,
                            bool writeSession,
                            tUINT32 HostSN,
                            tINT64 sessionTimeout,
                            bool syncHostTPerProperties )
{
   return _startSession( targetSP, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength, writeSession, HostSN, sessionTimeout, syncHostTPerProperties );
} // _startSession

//=================================================================================
/// \brief Close the currently open session.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_closeSession()
{
   if( 0 == m_packetManager.getTPerSN() )
      return TS_SUCCESS;

   M_TCGTry()
   {
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildEOS( p );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_END_OF_SESSION );

      m_packetManager.setTPerSN( 0 );
      if( m_useDynamicComID && isComIDMgmtSupported() )
      {
#ifdef __TCGSILO
         if( !useSilo() )
#endif
         {
            m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );
         }
      }
   }
   M_TCGCatch( true, true );
} // _closeSession

//=================================================================================
/// \brief Start a TCG transaction within the current open session.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_startTransaction()
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildStartTransaction( p, (tUINT8)TS_SUCCESS );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      TCG_STATUS status = m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_START_TRANSACTION );
      if( TS_SUCCESS != status )
         throw status;
   }
   M_TCGCatch( true, true );
} // _startTransaction

//=================================================================================
/// \brief End/Close the present TCG transaction within the cureent open session.
///
/// \param commitTransaction [IN]  Whether to commit(true) or abort(false) the present transaction.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_endTransaction( bool commitTransaction )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildEndTransaction( p, (tUINT8)( commitTransaction ? TS_SUCCESS : 0x01 ) ); // 01 to abort the transaction
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      TCG_STATUS status = m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload, TOKEN_TYPE_END_TRANSACTION );
      if( TS_SUCCESS != status ) // if( ( commitTransaction ? TS_SUCCESS : 0x01 ) != status )
         throw status;
   }
   M_TCGCatch( true, true );
} // _endTransaction

//=================================================================================
/// \brief Authenticate to a SP table/object with the given credential on the TPer.
///
/// TCG method depiction
///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
///   =>
///   [ typeOr {Success : boolean, Response : bytes} ]
///
/// \param authorityID     [IN]  Authority to authenticate with.
/// \param challenge       [IN]  Credential (key or password) to be used for the authentication. NULL indicates requesting 'nonce' from TPer.
/// \param challengeLength [IN]  Length of the challenge/credential.
/// \param response        [OUT] Bytes of the "response" returned by the TPer for a Challenge-Response type of authority (with the first step authentication only), not used otherwise.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_authenticate( TCG_UID authorityID, dta::tByte* challenge, tUINT16 challengeLength, dta::tBytes & response )
{
   // 'challenge' should have a prior set value, either as challenge/key/password when not empty, 
   // or upon empty (NULL) as an indicator for requesting 'nonce' and no longer assumed to use MSID.

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      // Construct Authenticate method call tokens
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_THIS_SP, (isDeviceTCGCoreVersion1() ? UID_M_AUTHENTICATE1 : UID_M_AUTHENTICATE2) );
      p = m_tokenProcessor.buildUID( p, authorityID );

      if( NULL != challenge )
         p = encodeNamedValue_Bytes( p, challenge, challengeLength, "Challenge", 0 );

      p = m_tokenProcessor.buildCallTokenFooter( p );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      m_tokenProcessor.getAtomData( &respSubPacketPayload[1], response );
      if( NULL != challenge )
         checkReturnedCallStatus( respSubPacketPayload );
      else if( response.size() == 0 )
         throw dta::Error(eGenericWarning);  // Empty data returned
   }
   M_TCGCatch( true, true );
} // _authenticate

//=================================================================================
/// \brief Authenticate to a SP table/object with the given credential on the TPer.
///
/// TCG method depiction
///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
///   =>
///   [ typeOr {Success : boolean, Response : bytes} ]
///
/// \param authent      [IN]  AuthenticationParameter used with the authentication.
/// \param response     [OUT] Bytes of the "response" returned by the TPer for a Challenge-Response type of authority (with the first step authentication only), not used otherwise.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_authenticate( AuthenticationParameter & authent, dta::tBytes & response )
{
   return _authenticate( mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength, response );
} // _authenticate

//=================================================================================
/// \brief Authenticate to a SP table/object with the given credential (regardless of the Challenge-Response return).
///
/// \param authorityID  [IN]  Authority to authenticate with.
/// \param key          [IN]  Credential (key or password) to be used for the authentication.
/// \param keyLength    [IN]  Length of the credential.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_authenticate( TCG_UID authorityID, dta::tByte* key, tUINT16 keyLength )
{
   if( NULL == key && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      key = &m_MSID[0];
      keyLength = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      // Construct Authenticate method call tokens
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_THIS_SP, (isDeviceTCGCoreVersion1() ? UID_M_AUTHENTICATE1 : UID_M_AUTHENTICATE2) );
      p = m_tokenProcessor.buildUID( p, authorityID );

      if( NULL != key )
         p = encodeNamedValue_Bytes( p, key, keyLength, "Challenge", 0 );

      p = m_tokenProcessor.buildCallTokenFooter( p );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      checkReturnedCallStatus( respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _authenticate

//=================================================================================
/// \brief Authenticate to a SP table/object with the given credential (regardless of the Challenge-Response return).
///
/// TCG method depiction
///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
///   =>
///   [ typeOr {Success : boolean, Response : bytes} ]
///
/// \param authent      [IN]  AuthenticationParameter used with the authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_authenticate( AuthenticationParameter & authent )
{
   return _authenticate( mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // _authenticate

//=================================================================================
/// \brief Table/Object method: Fetch the values of selected table cells(row) from a table/object on the TPer.
///
/// TCG method depiction
///   TargetUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID  [IN]  Table/Object to be read from.
/// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, dta::tBytes & data )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, ( isDeviceTCGCoreVersion1() ? UID_M_GET1 : UID_M_GET2 ) );
      p = m_tokenProcessor.buildListToken( p, NULL, 0 ); // An empty list for the entire table/object space.
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         if( isDeviceTCGCoreVersion1() )
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[1], data );
         else
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Object-Table method: Fetch the values from a row of an Object table on the TPer.
///
/// TCG method depiction
///   TableUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID  [IN]  Object-Table to be read from.
/// \param rowID     [IN]  UID of the row object.
/// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, ( isDeviceTCGCoreVersion1() ? UID_M_GET1 : UID_M_GET2 ) );
      p = m_tokenProcessor.buildStartList( p );

      if( UID_NULL != rowID )
         p = encodeNamedValue_UID( p, rowID, "startRow", evStartRow );

      p = m_tokenProcessor.buildEndList( p );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         if( isDeviceTCGCoreVersion1() )
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[1], data );
         else
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Object-Table method: Fetch the values from a row of an Object table on the TPer.
///
/// TCG method depiction (CS2.0 only)
///   TableUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID     [IN]  Object-Table to be read from.
/// \param rowID        [IN]  UID of the row object.
/// \param startColumn  [IN]  start column number, -1 indicates an omitted parameter, meaning "first" column.
/// \param endColumn    [IN]  end column number, -1 indicates an omitted parameter, meaning "last" column.
/// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, TCG_UID rowID, int startColumn, int endColumn, dta::tBytes & data )
{
   if( isDeviceTCGCoreVersion1() )
   {
      data.resize( 0 );
      return TS_INVALID_PARAMETER; // CS1.0 does not support integer-indexed optional parameters
   }

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_GET2 );
      p = m_tokenProcessor.buildStartList( p );

      if( UID_NULL != rowID )
         p = m_tokenProcessor.buildNamedValueToken( p, evStartRow, (tUINT64)rowID, (int)sizeof(TCG_UID), true );

      if( -1 != startColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, evStartColumn, (tUINT64) startColumn );

      if( -1 != endColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, evEndColumn, (tUINT64) endColumn );

      p = m_tokenProcessor.buildEndList( p );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Byte-Table method: Fetch the values from a range of a Byte-table on the TPer.
///
/// TCG method depiction
///   TargetUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID  [IN]  Bte-Table to be read from.
/// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
/// \param startRow  [IN]  start row, -1 indicates an omitted parameter, meaning "first" row.
/// \param endRow    [IN]  end row, -1 indicates an omitted parameter, meaning "last" row.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, ( isDeviceTCGCoreVersion1() ? UID_M_GET1 : UID_M_GET2 ) );
      p = m_tokenProcessor.buildStartList( p );

      if( -1 != startRow )
         p = encodeNamedValue_Integer( p, (tUINT64)startRow, "startRow", evStartRow );

      if( -1 != endRow )
         p = encodeNamedValue_Integer( p, (tUINT64)endRow, "endRow", evEndRow );

      p = m_tokenProcessor.buildEndList( p );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         if( isDeviceTCGCoreVersion1() )
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[1], data );
         else
            m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Array/Object Table method: Fetch the values from a row of a Array table or Object table on the TPer.
///
/// TCG method depiction (CS2.0)
///   TargetUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID     [IN]  Array-table or Object-table to be read from.
/// \param startColumn  [IN]  start column number, -1 indicates an omitted parameter, meaning "first" column.
/// \param endColumn    [IN]  end column number, -1 indicates an omitted parameter, meaning "last" column.
/// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, int startColumn, int endColumn, dta::tBytes & data )
{
   if( isDeviceTCGCoreVersion1() )
   {
      data.resize( 0 );
      return TS_INVALID_PARAMETER; // CS1.0 does not support integer-indexed optional parameters
   }

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_GET2 );

      p = m_tokenProcessor.buildStartList( p );
      if( -1 != startColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, evStartColumn, (tUINT64) startColumn );

      if( -1 != endColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, evEndColumn, (tUINT64) endColumn );
      p = m_tokenProcessor.buildEndList( p );

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Array/Object Table method: Fetch the values from a row of a Array table or Object table on the TPer.
///
/// TCG method depiction (CS1.0)
///   TargetUID.Get [ Cellblock : cell_block ]
///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
///
/// \param targetID     [IN]  Array-table or Object-table to be read from.
/// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
/// \param startColumn  [IN]  start column, 0-terminated ASCII string, NULL means "first" column, omitted.
/// \param endColumn    [IN]  end column, 0-terminated ASCII string, NULL means "last" column, omitted.
/// \param rowID        [IN]  UID of the row object, optional, UID_NULL indicating omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn, TCG_UID rowID )
{
   if( !isDeviceTCGCoreVersion1() )
   {
      data.resize( 0 );
      return TS_INVALID_PARAMETER; // CS2.0 does not allow char-string named optional parameters
   }

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( (m_packetManager.getMaxComPacketSize() > 0) ? m_packetManager.getMaxComPacketSize() : m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_GET1 );

      p = m_tokenProcessor.buildStartList( p );

      if( UID_NULL != rowID )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"startRow", sizeof("startRow")-1, (tUINT64)rowID, sizeof(TCG_UID), true );

      if( NULL != startColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"startColumn", sizeof("startColumn")-1, (dta::tByte*)startColumn, (tUINT32) strlen(startColumn) );

      if( NULL != endColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"endColumn", sizeof("endColumn")-1, (dta::tByte*)endColumn, (tUINT32) strlen(endColumn) );

      p = m_tokenProcessor.buildEndList( p );

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      if( m_tokenProcessor.isListToken(respSubPacketPayload[1]) )
      {
         // data will be retrieved from the "Data" part of the Result ListToken in the form of [ {namedValue pairs} ].
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[1], data );
      }
      else
      {
         // Raw Bytes (Atom)
         m_tokenProcessor.getListTokenData( &respSubPacketPayload[0], data );
      }
   }
   M_TCGCatch( true, true );
} // _get

//=================================================================================
/// \brief Table/Object method: Set the table/object content for a table/object-rows on the TPer.
///
/// \param targetID  [IN]  Table/Object to be written to.
/// \param data      [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_set( TCG_UID targetID, dta::tBytes & data )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( data.size() + m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      if( isDeviceTCGCoreVersion1() )
      {
         p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SET1 ); // CS1.0
         p = m_tokenProcessor.buildListToken( p, NULL, 0 ); // Empty list to indicate the entire table/row space.
         if( m_tokenProcessor.isListToken( data[0] ) )
            p = m_tokenProcessor.buildListToken( p, &data[0], (tUINT32)data.size() ); // in the form of [[ {namedValue pairs} ]]
         else
            p = m_tokenProcessor.addListElement( p, &data[0], (tUINT32)data.size() ); // raw bytes Atom
      }
      else
      {
         p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SET2 ); // CS2.0
         p = m_tokenProcessor.buildNamedValueToken( p, evValues, &data[0], (tUINT32)data.size(), true ); // in the form of Values = [ {namedValue pairs} ] or raw bytesAtom
      }
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      checkReturnedCallStatus( respSubPacketPayload, false );
   }
   M_TCGCatch( true, true );
} // _set

//=================================================================================
/// \brief Byte-Table method: Set the table content for a Byte table  or an object row on the TPer.
///
/// \param targetID  [IN]  Byte Table to be written to.
/// \param data      [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
/// \param startRow  [IN]  start row, -1 indicates an omitted parameter, meaning "first" row.
/// \param endRow    [IN]  end row, -1 indicates an omitted parameter, meaning "last" row.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_set( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( data.size() + m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      if( isDeviceTCGCoreVersion1() )
      {
         p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SET1 ); // CS1.0

         p = m_tokenProcessor.buildStartList( p );
         if( -1 != startRow )
            p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"startRow", sizeof("startRow")-1, (tUINT64)startRow );

         if( -1 != endRow )
            p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"endRow", sizeof("endRow")-1, (tUINT64)endRow );
         p = m_tokenProcessor.buildEndList( p );

         if( m_tokenProcessor.isListToken( data[0] ) )
            p = m_tokenProcessor.buildListToken( p, &data[0], (tUINT32)data.size() ); // in the form of [[ {namedValue pairs} ]]
         else
            p = m_tokenProcessor.addListElement( p, &data[0], (tUINT32)data.size() ); // raw bytesAtom
      }
      else
      {
         p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SET2 ); // CS2.0

         if( -1 != startRow )
            p = m_tokenProcessor.buildNamedValueToken( p, evWhere, (tUINT64)startRow );

         // Note: no endRow in CS2.0. It's determined by the size of data supplied.

         p = m_tokenProcessor.buildNamedValueToken( p, evValues, &data[0], (tUINT32)data.size(), true ); // in the form of Values = [ {namedValue pairs} ] or raw bytesAtom
      }

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      checkReturnedCallStatus( respSubPacketPayload, false );
   }
   M_TCGCatch( true, true );
} // _set

//=================================================================================
/// \brief Object-Table method: Set the table row content for a Byte table  or an object row on the TPer. (CS1.0 & 2.0)
///
/// \param targetID  [IN]  Byte Table to be written to.
/// \param rowID     [IN]  UID of the row object to set value to.
/// \param data      [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_set( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( data.size() + m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );

      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, ( isDeviceTCGCoreVersion1() ? UID_M_SET1 : UID_M_SET2 ) ); // CS2.0

      if( isDeviceTCGCoreVersion1() )
      {
         p = m_tokenProcessor.buildStartList( p );

         if( UID_NULL != rowID )
            p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"startRow", sizeof("startRow")-1, rowID, sizeof(TCG_UID), true );

         p = m_tokenProcessor.buildEndList( p );

         if( m_tokenProcessor.isListToken( data[0] ) )
            p = m_tokenProcessor.buildListToken( p, &data[0], (tUINT32)data.size() ); // in the form of [[ {namedValue pairs} ]]
         else
            p = m_tokenProcessor.addListElement( p, &data[0], (tUINT32)data.size() ); // raw bytesAtom
      }
      else
      {
         if( UID_NULL != rowID )
            p = m_tokenProcessor.buildNamedValueToken( p, evWhere, rowID, (int)sizeof(TCG_UID), true );

         p = m_tokenProcessor.buildNamedValueToken( p, evValues, &data[0], (tUINT32)data.size(), true ); // in the form of Values = [ {namedValue pairs} ] or raw bytesAtom
      }

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      checkReturnedCallStatus( respSubPacketPayload, false );
   }
   M_TCGCatch( true, true );
} // _set

//=================================================================================
/// \brief Array/Object Table method: Set the table content for an Array or Object table row on the TPer. (CS1.0)
///
/// \param targetID     [IN]  Array or Object Table to be written to.
/// \param data         [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or BytesAtom.
/// \param startColumn  [IN]  start column, 0-terminated ASCII string, NULL means "first" column, omitted.
/// \param endColumn    [IN]  end column, 0-terminated ASCII string, NULL means "last" column, omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_set( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn )
{
   if( !isDeviceTCGCoreVersion1() )
      return TS_INVALID_PARAMETER; // CS2.0 does not allow char-string named optional parameters

   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( data.size() + m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SET1 );

      p = m_tokenProcessor.buildStartList( p );
      if( NULL != startColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"startColumn", sizeof("startColumn")-1, (dta::tByte*)startColumn, (tUINT32) strlen(startColumn) );

      if( NULL != endColumn )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte*)"endColumn", sizeof("endColumn")-1, (dta::tByte*)endColumn, (tUINT32) strlen(endColumn) );
      p = m_tokenProcessor.buildEndList( p );

      if( m_tokenProcessor.isListToken( data[0] ) )
         p = m_tokenProcessor.buildListToken( p, &data[0], (tUINT32)data.size() ); // in the form of [[ {namedValue pairs} ]]
      else
         p = m_tokenProcessor.addListElement( p, &data[0], (tUINT32)data.size() ); // raw bytesAtom

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      checkReturnedCallStatus( respSubPacketPayload, false );
   }
   M_TCGCatch( true, true );
} // _set

//=================================================================================
/// \brief Objecy table method: Fetch the next few object UIDs from the UID cloumn of the specified table.
///
/// TCG method depiction
///   TableUID.Next [ Where = uidref, Count = uinteger ]
///   => [ Result : list [ uidref ... ] ]
///
/// \param pNextUID  [OUT] Pointer to a caller supplied storage of size of count UIDs to keep the returned UIDs. UID_NULL (0) is filled if not enough number of UIDs are returned.
/// \param tableID   [IN]  Table to be read from.
/// \param objectID  [IN]  Object to be referenced for its next row in the table.
/// \param count     [IN]  Number of the next rows to be read from.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_next( TCG_UID *pNextUID, TCG_UID tableID, TCG_UID objectID, int count )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, tableID, UID_M_NEXT );

      if( UID_NULL != objectID )
         p = encodeNamedValue_UID( p, objectID, "Where", 0 );

      if( -1 != count )
         p = encodeNamedValue_Integer( p, (tUINT64) count, "Count", 1 );

      p = m_tokenProcessor.buildCallTokenFooter( p );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      p = &respSubPacketPayload[2];
      memset( pNextUID, 0, count * sizeof(TCG_UID) );
      while( !m_tokenProcessor.isEndList( *p ) )
      {
         if( count > 0 )
         {
            p = m_tokenProcessor.getAtomData( p, (tUINT64*)pNextUID++ );
            count --;
         }
         else
         {
            break; // more items returned and ignored (error??)
         }
      }
   }
   M_TCGCatch( true, true );
} // _next

//=================================================================================
/// \brief Table method: Retrieve the Access Control List (ACL) value for the given target and method.
///
/// TCG method depiction
///   MethodTableUID.GetACL [ InvokingID : table_object_ref, MethodID : MethodID_ref ]
///   => [ ACL : ACL ]
///
/// \param targetID  [IN]  ThisSP/Table/Object to be read from.
/// \param methodID  [IN]  Method UID to query ACL for.
/// \param acl       [OUT] A vector of UIDs as the ACL returned.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getACL( TCG_UID targetID, TCG_UID methodID, TCG_UIDs & acl )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_TABLE_ACCESSCONTROL, UID_M_GET_ACL );
      p = m_tokenProcessor.buildUID( p, targetID );
      p = m_tokenProcessor.buildUID( p, methodID );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );

      // data is the form of [[ {UIDs} ]].
      int count = m_tokenProcessor.numberOfListItems( &respSubPacketPayload[1] );
      acl.resize( count );
      p = &respSubPacketPayload[2];
      for( int ii=0; ii < count; ii++ )
         p = m_tokenProcessor.getAtomData( p, &acl[ii] );
   }
   M_TCGCatch( true, true );
} // _getACL

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer.
///
/// \param bandID  [IN]  Band/range to be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_erase( TCG_UID bandID )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _erase

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer.
///
/// \param bandNo  [IN]  Band/range number be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_erase( int bandNo )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _erase

//=================================================================================
/// \brief Generate a Key by the specified credential object.
///
/// \param target          [IN]  UID of target credential object to generate the key.
/// \param publicExponent  [IN]  PublicExponent to be used when invoked on a C_RSA_1024 or C_RSA_2048 object. Optional, -1 indicates omitted.
/// \param pinLength       [IN]  Pin length. Optional, -1 indicates omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_genKey( TCG_UID target, tINT64 publicExponent, int pinLength )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _genKey

//=================================================================================
/// \brief Request the this SP to generate an array of random bytes.
///
/// \param randomData [IN/OUT]  Random numbers generated with the length set prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_random( dta::tBytes & randomData )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_THIS_SP, UID_M_RANDOM );
      p = m_tokenProcessor.buildIntAtom( p, (tUINT64) randomData.size() );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      TCG_STATUS status = m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      if( TS_SUCCESS != status )
         throw status;

      tUINT64 randmonBytes = randomData.size();
      m_tokenProcessor.getAtomData( &respSubPacketPayload[1], randomData );
      if( randomData.size() != randmonBytes )
         throw dta::Error(eGenericInvalidParameter);
   }
   M_TCGCatch( true, true );
} // _random

//=================================================================================
/// \brief Sign a set of data by the specified TPerSign authority object on the TPer.
///
/// TCG method depiction
///   TPerSignAuthorityObject.Sign[ DataToSign : bytes ]
///   => [ SignedData : bytes ]
///
/// \param targetID    [IN]  TPer signing authority object.
/// \param dataToSign  [IN]  Bytes of data to be signed.
/// \param dataSigned  [OUT] Signed data returned.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_sign( TCG_UID targetID, dta::tBytes & dataToSign, dta::tBytes & dataSigned )
{
   M_TCGTry()
   {
      if( dataToSign.size() > 256 )
         throw dta::Error(eGenericInvalidParameter);

      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, targetID, UID_M_SIGN );
      p = m_tokenProcessor.buildAtom( p, &dataToSign[0], (tUINT32)dataToSign.size(), true, false );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      TCG_STATUS status = m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
      if( TS_SUCCESS != status )
         throw status;

      m_tokenProcessor.getAtomData( &respSubPacketPayload[1], dataSigned );
      if( dataSigned.size() < dataToSign.size() )
         throw dta::Error(eGenericFatalError);
   }
   M_TCGCatch( true, true );
} // _sign

//=================================================================================
/// \brief Activate the given SP object from "Manufactured-Inactive" to "Manufactured".
///
/// TCG method depiction
///   SPObjectUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param target                  [IN]  UID of target SP object to be activated at "Manufactured-Inactive" state.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_activate( TCG_UID target, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _activate

//=================================================================================
/// \brief Activate the given SP object from "Manufactured-Inactive" to "Manufactured".
///
/// TCG method depiction
///   SPObjectUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param target                  [IN]  UID of target SP object to be activated at "Manufactured-Inactive" state.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_activate( TCG_UID target, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _activate

//=================================================================================
/// \brief Reactivate the in-session Locking SP.
///
/// TCG method depiction
///   ThisSPUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      Admin1PIN = bytes,
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_reactivate( TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _reactivate

//=================================================================================
/// \brief Reactivate the in-session Locking SP.
///
/// TCG method depiction
///   ThisSPUID.Reactivate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      Admin1PIN = bytes,
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_reactivate( TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _reactivate

//=================================================================================
/// \brief Revert the given object to its factory state on the TPer.
///
/// \param target  [IN]  UID of target object to be reverted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_revert( TCG_UID target )
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _revert

//=================================================================================
/// \brief Revert the currently authenticated SP (this-SP) to its factory state on the TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_revertSP()
{
   // This is a SSC specific feature, to be implemented in SSC interface.
   return TS_DTL_ERROR;
} // _revertSP

//=================================================================================
/// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
///
/// \param targetID  [IN]     Target UID, a SP object UID in the SP table.
/// \param row       [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getSP( TCG_UID targetID, IOTableSP & row )
{
   tUINT64 tmp;
   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status = _get( targetID, data );

   //
   // Retrieving the returned data and set to IOTableSP structure
   //
   if( data.size() == 0 ) // Well, this should not be a valid return, however it did happen on Seagate Ent-SSC SEDs when access is not granted.
   {
      row.setStateAll( false );
      return TS_NOT_AUTHORIZED;
   }

   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( row.ORG_isValid )
   {
      row.ORG = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ORG", 2 );
      if( p1 == p2 )
         row.ORG_isValid = false;
      else
         p2 = p1;
   } // if( row.ORG_isValid )

   if( row.EffectiveAuth_isValid )
   {
      memset( row.EffectiveAuth, 0, sizeof( row.EffectiveAuth ) );
      decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.EffectiveAuth, sizeof(row.EffectiveAuth), "EffectiveAuth", 3 );
      if( p1 == p2 )
         row.EffectiveAuth_isValid = false;
      else
         p2 = p1;
   } // if( row.EffectiveAuth_isValid )

   if( row.DateofIssue_isValid )
   {
      p1 = decodeNamedValueName( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "DateofIssue", 0x04 );
      if( NULL != p1 )
      {
         if( m_tokenProcessor.isListToken(*p1) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p1 ++ );
            if( 0 == tmp ) // empty is valid
            {
               row.DateofIssue_isValid = false;
            }
            else
            {
               if( 3 != tmp )
                  throw dta::Error(eGenericInvalidIdentifier);

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.DateofIssue_Year = (tUINT16) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.DateofIssue_Month = (tUINT8) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.DateofIssue_Day = (tUINT8) tmp;
            }

            p1 += 2; // EL, EN
            p2 = p1;
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
      {
         p1 = p2;
         row.DateofIssue_isValid = false;
      }
   } // if( row.DateofIssue_isValid )

   if( row.Bytes_isValid )
   {
      row.Bytes = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Bytes", 5 );
      if( p1 == p2 )
         row.Bytes_isValid = false;
      else
         p2 = p1;
   } // if( row.Bytes_isValid )

   if( row.LifeCycleState_isValid )
   {
      row.LifeCycleState = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "LifeCycleState", 6 );
      if( p1 == p2 )
         row.LifeCycleState_isValid = false;
      else
         p2 = p1;
   } // if( row.LifeCycleState_isValid )

   if( row.Frozen_isValid )
   {
      row.Frozen = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Frozen", 7 ) ? true : false;
      if( p1 == p2 )
         row.Frozen_isValid = false;
      else
         p2 = p1;
   } // if( row.Frozen_isValid )

   return status;
} // _getSP

//=================================================================================
/// \brief Set values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.
///
/// \param targetID  [IN]     Target UID, a SP object UID in the SP table.
/// \param row       [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setSP( TCG_UID targetID, IOTableSP & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false;            // Read-Only, cann't Set

   if( -1 != row.Name_length )
      row.Name_length = -1;               // Read-Only, cann't Set

   if( row.ORG_isValid )
      row.ORG_isValid = false;            // Read-Only, cann't Set

   if( row.EffectiveAuth_isValid )
      row.EffectiveAuth_isValid = false;  // Read-Only, cann't Set

   if( row.DateofIssue_isValid )
      row.DateofIssue_isValid = false;    // Read-Only, cann't Set

   if( row.Bytes_isValid )
      row.Bytes_isValid = false;          // Read-Only, cann't Set

   if( row.LifeCycleState_isValid )
      row.LifeCycleState_isValid = false; // Read-Only, cann't Set

   if( row.Frozen_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Frozen, "Frozen", 7 );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );
   return _set( targetID, data );
} // _setSP

//=================================================================================
/// \brief Get values of MaxRanges, MaxReEncryptions, etc, from the LockingInfo table row.
///
/// \param row      [IN/OUT] LockingInfo table row data structure IOTableLockingInfo. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getLockingInfo( IOTableLockingInfo & row )
{
   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status;

   if( isDeviceTCGCoreVersion1() )
   {
      status = _get( UID_TABLE_LOCKINGINFO, data );
   }
   else
   {
      if( isDeviceEnterpriseSSC() )
         status = _get( UID_TABLE_LOCKINGINFO, UID_LOCKINGINFO, data ); // temporarily,  until Ent CS2.0 IV consolidated, then change to the same as Opal below
      else
         status = _get( UID_LOCKINGINFO, data );
   }

   //
   // Retrieving the returned data and set to IOTableLocking structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( row.Version_isValid )
   {
      row.Version = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Version", 2 );
      if( p1 == p2 )
         row.Version_isValid = false;
      else
         p2 = p1;
   } // if( row.Version_isValid )

   if( row.EncryptSupport_isValid )
   {
      row.EncryptSupport = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "EncryptSupport", 3 );
      if( p1 == p2 )
         row.EncryptSupport_isValid = false;
      else
         p2 = p1;
   } // if( row.EncryptSupport_isValid )

  if( row.MaxRanges_isValid )
   {
      row.MaxRanges = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "MaxRanges", 4 );
      if( p1 == p2 )
         row.MaxRanges_isValid = false;
      else
         p2 = p1;
   } // if( row.MaxRanges_isValid )

   if( row.MaxReEncryptions_isValid )
   {
      row.MaxReEncryptions = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "MaxReEncryptions", 5 );
      if( p1 == p2 )
         row.MaxReEncryptions_isValid = false;
      else
         p2 = p1;
   } // if( row.MaxReEncryptions_isValid )

   if( row.KeysAvailableCfg_isValid )
   {
      row.KeysAvailableCfg = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "KeysAvailableCfg", 6 );
      if( p1 == p2 )
         row.KeysAvailableCfg_isValid = false;
   } // if( row.KeysAvailableCfgt_isValid )

   if( row.SingleUserModeRanges_isValid )
   {
      p1 = decodeNamedValueName( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "SingleUserModeRanges", 0x060000 ); // was 7 in IV
      if( NULL != p1 )
      {
         if( m_tokenProcessor.isListToken(*p1) ) // LockingObj list or empty list
         {
            row.SingleUserModeRanges.resize( m_tokenProcessor.numberOfListItems( p1 ++ ) );
            for( tUINT32 ii=0; ii<row.SingleUserModeRanges.size(); ii++ )
               p1 = m_tokenProcessor.getAtomData( p1, &row.SingleUserModeRanges[ii] );

            p1 += 2; //EL, EN
         }
         else // Locking Table UID
         {
            row.SingleUserModeRanges.resize( 1 );
            p1 = m_tokenProcessor.getAtomData( p1, &row.SingleUserModeRanges[0] );
            p1++; //EN
         }

         p2 = p1;
      }
      else
      {
         row.SingleUserModeRanges_isValid = false;
         p1 = p2;
      }
   } // if( row.SingleUserModeRanges_isValid )

   if( row.RangeStartLengthPolicy_isValid )
   {
      row.RangeStartLengthPolicy = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "RangeStartLengthPolicy", 0x060001 ); // was 8 in IV
      if( p1 == p2 )
         row.RangeStartLengthPolicy_isValid = false;
   } // if( row.RangeStartLengthPolicy_isValid )

   return status;
} // _getLockingInfo

//=================================================================================
/// \brief Get values of table columns of a range from the Locking table.
///
/// \param rangeNo  [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param row      [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getLocking( int rangeNo, IOTableLocking & row )
{
   TCG_UID targetID;
   if( rangeNo > 0 )
      targetID = (isDeviceEnterpriseSSC() ? UID_LOCKING_RANGE1_E : UID_LOCKING_RANGE1_OM) + rangeNo -1;
   else
      targetID = UID_LOCKING_RANGE0;

   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status = _get( targetID, data ); // Get all the eligible columns dependent on prious authentication

   //
   // Retrieving the returned data and set to IOTableLocking structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( -1 != row.CommonName_length )
   {
      memset( row.CommonName, 0, sizeof( row.CommonName ) );
      row.CommonName_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.CommonName, sizeof(row.CommonName) -1, "CommonName", 2 );
      if( p1 == p2 )
         row.CommonName_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.CommonName_length )

   if( row.RangeStart_isValid )
   {
      row.RangeStart = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "RangeStart", 3 );
      if( p1 == p2 )
         row.RangeStart_isValid = false;
      else
         p2 = p1;
   } // if( row.RangeStart_isValid )

   if( row.RangeLength_isValid )
   {
      row.RangeLength = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "RangeLength", 4 );
      if( p1 == p2 )
         row.RangeLength_isValid = false;
      else
         p2 = p1;
   } // if( row.RangeLength_isValid )

   if( row.ReadLockEnabled_isValid )
   {
      row.ReadLockEnabled = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ReadLockEnabled", 5 ) ? true : false;
      if( p1 == p2 )
         row.ReadLockEnabled_isValid = false;
      else
         p2 = p1;
   } // if( row.ReadLockEnabled_isValid )

   if( row.WriteLockEnabled_isValid )
   {
      row.WriteLockEnabled = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "WriteLockEnabled", 6 ) ? true : false;
      if( p1 == p2 )
         row.WriteLockEnabled_isValid = false;
      else
         p2 = p1;
   } // if( row.WriteLockEnabled_isValid )

   if( row.ReadLocked_isValid )
   {
      row.ReadLocked = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ReadLocked", 7 ) ? true : false;
      if( p1 == p2 )
         row.ReadLocked_isValid = false;
      else
         p2 = p1;
   } // if( row.ReadLocked_isValid )

   if( row.WriteLocked_isValid )
   {
      row.WriteLocked = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "WriteLocked", 8 ) ? true : false;
      if( p1 == p2 )
         row.WriteLocked_isValid = false;
      else
         p2 = p1;
   } // if( row.WriteLocked_isValid )

   if( -1 != row.LockOnReset_length )
   {
      memset( row.LockOnReset, 0, sizeof( row.LockOnReset ) );
      row.LockOnReset_length = (tUINT8) decodeNamedValue_IntgerList( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.LockOnReset, (tUINT32) (sizeof(row.LockOnReset)/sizeof(row.LockOnReset[0])), "LockOnReset", 9 );
      if( p1 == p2 )
         row.LockOnReset_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.LockOnReset_length )

   if( row.ActiveKey_isValid )
   {
      row.ActiveKey = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ActiveKey", 0x0A );
      if( p1 == p2 )
         row.ActiveKey_isValid = false;
      else
         p2 = p1;
   } // if( row.ActiveKey_isValid )

   if( row.NextKey_isValid )
   {
      row.NextKey = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "NextKey", 0x0B );
      if( p1 == p2 )
         row.NextKey_isValid = false;
      else
         p2 = p1;
   } // if( row.NextKey_isValid )

   if( row.ReEncryptState_isValid )
   {
      row.ReEncryptState = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ReEncryptState", 0x0C );
      if( p1 == p2 )
         row.ReEncryptState_isValid = false;
      else
         p2 = p1;
   } // if( row.ReEncryptState_isValid )

   if( row.ReEncryptRequest_isValid )
   {
      row.ReEncryptRequest = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ReEncryptRequest", 0x0D );
      if( p1 == p2 )
         row.ReEncryptRequest_isValid = false;
      else
         p2 = p1;
   } // if( row.ReEncryptRequest_isValid )

   if( row.AdvKeyMode_isValid )
   {
      row.AdvKeyMode = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "AdvKeyMode", 0x0E );
      if( p1 == p2 )
         row.AdvKeyMode_isValid = false;
      else
         p2 = p1;
   } // if( row.AdvKeyMode_isValid )

   if( row.VerifyMode_isValid )
   {
      row.VerifyMode = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "VerifyMode", 0x0F );
      if( p1 == p2 )
         row.VerifyMode_isValid = false;
      else
         p2 = p1;
   } // if( row.VerifyMode_isValid )

   if( -1 != row.ContOnReset_length )
   {
      memset( row.ContOnReset, 0, sizeof( row.ContOnReset ) );
      row.ContOnReset_length = (tUINT8) decodeNamedValue_IntgerList( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.ContOnReset, (tUINT32) (sizeof(row.ContOnReset)/sizeof(row.ContOnReset[0])), "ContOnReset", 0x10 );
      if( p1 == p2 )
         row.ContOnReset_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.ContOnReset_length )

   if( row.LastReEncryptLBA_isValid )
   {
      row.LastReEncryptLBA = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "LastReEncryptLBA", 0x11 );
      if( p1 == p2 )
         row.LastReEncryptLBA_isValid = false;
      else
         p2 = p1;
   } // if( row.LastReEncryptLBA_isValid )

   if( row.LastReEncStat_isValid )
   {
      row.LastReEncStat = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "LastReEncStat", 0x12 );
      if( p1 == p2 )
         row.LastReEncStat_isValid = false;
      else
         p2 = p1;
   } // if( row.LastReEncStat_isValid )

   if( -1 != row.GeneralStatus_length )
   {
      memset( row.GeneralStatus, 0, sizeof( row.GeneralStatus ) );
      row.GeneralStatus_length = (tUINT8) decodeNamedValue_IntgerList( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.GeneralStatus, (tUINT32) (sizeof(row.GeneralStatus)/sizeof(row.GeneralStatus[0])), "GeneralStatus", 0x13 );
      if( p1 == p2 )
         row.GeneralStatus_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.GeneralStatus_length )

   if( row.AllowATAUnlock_isValid )
   {
      row.AllowATAUnlock = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "AllowATAUnlock", 0x00FFFF0000 ) ? true : false;
      if( p1 == p2 )
         row.AllowATAUnlock_isValid = false;
      else
         p2 = p1;
   } // if( row.AllowATAUnlock_isValid )

   return status;
} // _getLocking

#if 0 // For reference only. This is the "slower" version of the above function implementation
TCG_STATUS CTcgCoreInterface::_getLocking( int rangeNo, IOTableLocking & row )
{
   TCG_UID targetID;
   if( rangeNo > 0 )
      targetID = (isDeviceEnterpriseSSC() ? UID_LOCKING_RANGE1_E : UID_LOCKING_RANGE1_OM) + rangeNo -1;
   else
      targetID = UID_LOCKING_RANGE0;

   tUINT8 *p;
   tUINT64 tmp;
   dta::tBytes data;
   TCG_STATUS status = _get( targetID, data ); // Get all the eligible columns dependent on prious authentication

   //
   // Retrieving the returned data and set to IOTableLocking structure
   //
   if( row.UID_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"UID", sizeof("UID")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0 );

      if( NULL != p )
         row.UID = m_tokenProcessor.getAtomData( p );
      else
         row.UID_isValid = false;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"Name", sizeof("Name")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 1 );

      if( NULL != p )
      {
         m_tokenProcessor.getAtomDataPointer( p, &p, &tmp );

         if( tmp <= sizeof( row.Name ) -1 )
         {
            memset( row.Name, 0, sizeof( row.Name ) );
            memcpy( row.Name, p, (size_t) tmp );
            row.Name_length = (tINT8) tmp;
         }
         else
         {
            // Too long data, something wrong happened
            throw dta::Error(eGenericInvalidIdentifier);
         }
      }
      else
         row.Name_length = -1;
   } // if( -1 != row.Name_length )

   if( -1 != row.CommonName_length )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"CommonName", sizeof("CommonName")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 2 );

      if( NULL != p )
      {
         m_tokenProcessor.getAtomDataPointer( p, &p, &tmp );

         if( tmp <= sizeof( row.CommonName ) -1 )
         {
            memset( row.CommonName, 0, sizeof( row.CommonName ) );
            memcpy( row.CommonName, p, (size_t) tmp );
            row.CommonName_length = (tINT8) tmp;
         }
         else
         {
            // Too long data, something wrong happened
            throw dta::Error(eGenericInvalidIdentifier);
         }
      }
      else
         row.CommonName_length = -1;
   } // if( -1 != row.CommonName_length )

   if( row.RangeStart_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"RangeStart", sizeof("RangeStart")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 3 );

      if( NULL != p )
         row.RangeStart = m_tokenProcessor.getAtomData( p );
      else
         row.RangeStart_isValid = false;
   } // if( row.RangeStart_isValid )

   if( row.RangeLength_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"RangeLength", sizeof("RangeLength")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 4 );

      if( NULL != p )
         row.RangeLength = m_tokenProcessor.getAtomData( p );
      else
         row.RangeLength_isValid = false;
   } // if( row.RangeLength_isValid )

   if( row.ReadLockEnabled_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ReadLockEnabled", sizeof("ReadLockEnabled")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 5 );

      if( NULL != p )
         row.ReadLockEnabled = ( m_tokenProcessor.getAtomData( p ) ) ? true : false;
      else
         row.ReadLockEnabled_isValid = false;
   } // if( row.ReadLockEnabled_isValid )

   if( row.WriteLockEnabled_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"WriteLockEnabled", sizeof("WriteLockEnabled")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 6 );

      if( NULL != p )
         row.WriteLockEnabled = ( m_tokenProcessor.getAtomData( p ) ) ? true : false;
      else
         row.WriteLockEnabled_isValid = false;
   } // if( row.WriteLockEnabled_isValid )

   if( row.ReadLocked_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ReadLocked", sizeof("ReadLocked")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 7 );

      if( NULL != p )
         row.ReadLocked = ( m_tokenProcessor.getAtomData( p ) ) ? true : false;
      else
         row.ReadLocked_isValid = false;
   } // if( row.ReadLocked_isValid )

   if( row.WriteLocked_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"WriteLocked", sizeof("WriteLocked")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 8 );

      if( NULL != p )
         row.WriteLocked = ( m_tokenProcessor.getAtomData( p ) ) ? true : false;
      else
         row.WriteLocked_isValid = false;
   } // if( row.WriteLocked_isValid )

   if( -1 != row.LockOnReset_length )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"LockOnReset", sizeof("LockOnReset")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 9 );

      if( NULL != p )
      {
         if( m_tokenProcessor.isListToken(*p) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p++ );
            if( tmp > sizeof( row.LockOnReset ) )
               throw dta::Error(eGenericInvalidIdentifier);

            row.LockOnReset_length = (tINT8) tmp;
            memset( row.LockOnReset, 0, sizeof( row.LockOnReset ) );

            for( int ii=0; ii<row.LockOnReset_length; ii++ )
            {
               p = m_tokenProcessor.getAtomData( p, &tmp );
               row.LockOnReset[ii] = (tUINT8) tmp;
            }
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
         row.LockOnReset_length = -1;
   } // if( -1 != row.LockOnReset_length )

   if( row.ActiveKey_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ActiveKey", sizeof("ActiveKey")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0A );

      if( NULL != p )
         row.ActiveKey = m_tokenProcessor.getAtomData( p );
      else
         row.ActiveKey_isValid = false;
   } // if( row.ActiveKey_isValid )

   if( row.NextKey_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"NextKey", sizeof("NextKey")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0B );

      if( NULL != p )
         row.NextKey = m_tokenProcessor.getAtomData( p );
      else
         row.NextKey_isValid = false;
   } // if( row.NextKey_isValid )

   if( row.ReEncryptState_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ReEncryptState", sizeof("ReEncryptState")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0C );

      if( NULL != p )
         row.ReEncryptState = (tUINT8) m_tokenProcessor.getAtomData( p );
      else
         row.ReEncryptState_isValid = false;
   } // if( row.ReEncryptState_isValid )

   if( row.ReEncryptRequest_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ReEncryptRequest", sizeof("ReEncryptRequest")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0D );

      if( NULL != p )
         row.ReEncryptRequest = (tUINT8) m_tokenProcessor.getAtomData( p );
      else
         row.ReEncryptRequest_isValid = false;
   } // if( row.ReEncryptRequest_isValid )

   if( row.AdvKeyMode_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"AdvKeyMode", sizeof("AdvKeyMode")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0E );

      if( NULL != p )
         row.AdvKeyMode = (tUINT8) m_tokenProcessor.getAtomData( p );
      else
         row.AdvKeyMode_isValid = false;
   } // if( row.AdvKeyMode_isValid )

   if( row.VerifyMode_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"VerifyMode", sizeof("VerifyMode")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x0F );

      if( NULL != p )
         row.VerifyMode = (tUINT8) m_tokenProcessor.getAtomData( p );
      else
         row.VerifyMode_isValid = false;
   } // if( row.VerifyMode_isValid )

   if( -1 != row.ContOnReset_length )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"ContOnReset", sizeof("ContOnReset")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x10 );

      if( NULL != p )
      {
         if( m_tokenProcessor.isListToken(*p) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p++ );
            if( tmp > sizeof( row.ContOnReset ) )
               throw dta::Error(eGenericInvalidIdentifier);

            row.ContOnReset_length = (tINT8) tmp;
            memset( row.ContOnReset, 0, sizeof( row.ContOnReset ) );

            for( int ii=0; ii<row.ContOnReset_length; ii++ )
            {
               p = m_tokenProcessor.getAtomData( p, &tmp );
               row.ContOnReset[ii] = (tUINT8) tmp;
            }
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
         row.ContOnReset_length = -1;
   } // if( -1 != row.ContOnReset_length )

   if( row.LastReEncryptLBA_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"LastReEncryptLBA", sizeof("LastReEncryptLBA")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x11 );

      if( NULL != p )
         row.LastReEncryptLBA = m_tokenProcessor.getAtomData( p );
      else
         row.LastReEncryptLBA_isValid = false;
   } // if( row.LastReEncryptLBA_isValid )

   if( row.LastReEncStat_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"LastReEncStat", sizeof("LastReEncStat")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x12 );

      if( NULL != p )
         row.LastReEncStat = (tUINT8) m_tokenProcessor.getAtomData( p );
      else
         row.LastReEncStat_isValid = false;
   } // if( row.LastReEncStat_isValid )

   if( -1 != row.GeneralStatus_length )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"GeneralStatus", sizeof("GeneralStatus")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x13 );

      if( NULL != p )
      {
         if( m_tokenProcessor.isListToken(*p) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p++ );
            if( tmp > sizeof( row.GeneralStatus ) )
               throw dta::Error(eGenericInvalidIdentifier);

            row.GeneralStatus_length = (tINT8) tmp;
            memset( row.GeneralStatus, 0, sizeof( row.GeneralStatus ) );

            for( int ii=0; ii<row.GeneralStatus_length; ii++ )
            {
               p = m_tokenProcessor.getAtomData( p, &tmp );
               row.GeneralStatus[ii] = (tUINT8) tmp;
            }
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
         row.GeneralStatus_length = -1;
   } // if( -1 != row.GeneralStatus_length )

   if( row.AllowATAUnlock_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"AllowATAUnlock", sizeof("AllowATAUnlock")-1 );
      else
         p = m_tokenProcessor.retrieveNamedDataFromList( data, 0x3F );

      if( NULL != p )
          row.AllowATAUnlock = m_tokenProcessor.getAtomData( p ) ? true : false;
      else
         row.AllowATAUnlock_isValid = false;
   } // if( row.AllowATAUnlock_isValid )
   
   return status;
} // _getLocking
#endif

//=================================================================================
/// \brief Set values of table columns of a range to the Locking table.
///
/// \param rangeNo  [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param row      [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setLocking( int rangeNo, IOTableLocking & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false; // Read-Only, cann't Set

   if( -1 != row.Name_length )
      row.Name_length = -1;    // Read-Only, cann't Set

   if( row.CommonName_length > 0 ) //( -1 != row.CommonName_length )
      p = encodeNamedValue_Bytes( p, row.CommonName, row.CommonName_length, "CommonName", 2 );

   if( row.RangeStart_isValid )
      p = encodeNamedValue_Integer( p, row.RangeStart, "RangeStart", 3 );

   if( row.RangeLength_isValid )
      p = encodeNamedValue_Integer( p, row.RangeLength, "RangeLength", 4 );

   if( row.ReadLockEnabled_isValid )
      p = encodeNamedValue_Integer( p, row.ReadLockEnabled, "ReadLockEnabled", 5 );

   if( row.WriteLockEnabled_isValid )
      p = encodeNamedValue_Integer( p, row.WriteLockEnabled, "WriteLockEnabled", 6 );

   if( row.ReadLocked_isValid )
      p = encodeNamedValue_Integer( p, row.ReadLocked, "ReadLocked", 7 );

   if( row.WriteLocked_isValid )
      p = encodeNamedValue_Integer( p, row.WriteLocked, "WriteLocked", 8 );

   if( row.LockOnReset_length >= 0 ) //( -1 != row.LockOnReset_length )
      p = encodeNamedValue_IntgerList( p, row.LockOnReset, row.LockOnReset_length, "LockOnReset", 9 );

   if( row.ActiveKey_isValid )
      p = encodeNamedValue_UID( p, row.ActiveKey, "ActiveKey", 0x0A );

   if( row.NextKey_isValid )
      p = encodeNamedValue_UID( p, row.NextKey, "NextKey", 0x0B );

   if( row.ReEncryptState_isValid )
      row.ReEncryptState_isValid = false; // Read-Only, cann't Set

   if( row.ReEncryptRequest_isValid )
      p = encodeNamedValue_Integer( p, row.ReEncryptRequest, "ReEncryptRequest", 0x0D );

   if( row.AdvKeyMode_isValid )
      p = encodeNamedValue_Integer( p, row.AdvKeyMode, "AdvKeyMode", 0x0E );

   if( row.VerifyMode_isValid )
      p = encodeNamedValue_Integer( p, row.VerifyMode, "VerifyMode", 0x0F );

   if( row.ContOnReset_length >= 0 ) //( -1 != row.ContOnReset_length )
      p = encodeNamedValue_IntgerList( p, row.ContOnReset, row.ContOnReset_length, "ContOnReset", 0x10 );

   if( row.LastReEncryptLBA_isValid )
      row.LastReEncryptLBA_isValid = false; // Read-Only, cann't Set

   if( row.LastReEncStat_isValid )
      row.LastReEncStat_isValid = false;    // Read-Only, cann't Set

   if( -1 != row.GeneralStatus_length )
      row.GeneralStatus_length = -1;        // Read-Only, cann't Set

   if( row.AllowATAUnlock_isValid )
      p = encodeNamedValue_Integer( p, row.AllowATAUnlock, "AllowATAUnlock", 0x3F );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );

   TCG_UID targetID;
   if( rangeNo > 0 )
      targetID = (isDeviceEnterpriseSSC() ? UID_LOCKING_RANGE1_E : UID_LOCKING_RANGE1_OM) + rangeNo -1;
   else
      targetID = UID_LOCKING_RANGE0;

   return _set( targetID, data );
} // _setLocking

//=================================================================================
/// \brief Get values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.      
///
/// \param targetID  [IN]     Target UID, a C_PIN object UID in the C_PIN table.
/// \param row       [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getC_Pin( TCG_UID targetID, IOTableC_PIN  & row )
{
   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status = _get( targetID, data );

   //
   // Retrieving the returned data and set to IOTableC_PIN structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( -1 != row.CommonName_length )
   {
      memset( row.CommonName, 0, sizeof( row.CommonName ) );
      row.CommonName_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.CommonName, sizeof(row.CommonName) -1, "CommonName", 2 );
      if( p1 == p2 )
         row.CommonName_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.CommonName_length )

   if( -1 != row.PIN_length )
   {
      memset( row.PIN, 0, sizeof( row.PIN ) );
      row.PIN_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.PIN, sizeof(row.PIN) -1, "PIN", 3 );
      if( p1 == p2 )
         row.PIN_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.PIN_length )

   if( row.CharSet_isValid )
   {
      row.CharSet = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "CharSet", 4 );
      if( p1 == p2 )
         row.CharSet_isValid = false;
      else
         p2 = p1;
   } // if( row.CharSet_isValid )

   if( row.TryLimit_isValid )
   {
      row.TryLimit = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "TryLimit", 5 );
      if( p1 == p2 )
         row.TryLimit_isValid = false;
      else
         p2 = p1;
   } // if( row.TryLimit_isValid )

   if( row.Tries_isValid )
   {
      row.Tries = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Tries", 6 );
      if( p1 == p2 )
         row.Tries_isValid = false;
      else
         p2 = p1;
   } // if( row.Tries_isValid )

   if( row.Persistence_isValid )
   {
      row.Persistence = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Persistence", 7 ) ? true : false;
      if( p1 == p2 )
         row.Persistence_isValid = false;
      else
         p2 = p1;
   } // if( row.Persistence_isValid )
      
   return status;
} // _getC_Pin

//=================================================================================
/// \brief Set values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.
///
/// \param targetID  [IN]     Target UID, a C_PIN object UID in the C_PIN table.
/// \param row       [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setC_Pin( TCG_UID targetID, IOTableC_PIN  & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false;       // Read-Only, cann't Set

   if( -1 != row.Name_length )
      row.Name_length = -1;          // Read-Only, cann't Set

   if( -1 != row.CommonName_length ) // jls 20120320 - null string is valid
      p = encodeNamedValue_Bytes( p, row.CommonName, row.CommonName_length, "CommonName", 2 );

   if( -1 != row.PIN_length )       // jls 20120320 - null string is valid
      p = encodeNamedValue_Bytes( p, row.PIN, row.PIN_length, "PIN", 3 );

   if( row.CharSet_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         row.CharSet_isValid = false;       // Read-Only, cann't Set
      else
         p = m_tokenProcessor.buildNamedValueToken( p, 4, row.CharSet, (int)sizeof(TCG_UID), true );
   }

   if( row.TryLimit_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.TryLimit, "TryLimit", 5 );

   if( row.Tries_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Tries, "Tries", 6 );

   if( row.Persistence_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Persistence, "Persistence", 7 );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );
   return _set( targetID, data );
} // _setC_Pin

//=================================================================================
/// \brief Get the value of the columns("Enabled", etc) of an authority (E.g., User1) in Authority table.
///
/// \param authority   [IN]     Target authority to get from. E.g., User1 authority.
/// \param row         [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getAuthority( TCG_UID authority, IOTableAuthority & row )
{
   tUINT8 *p1, *p2;
   tUINT64 tmp;
   dta::tBytes data;
   TCG_STATUS status = _get( authority, data ); // Get all the eligible columns dependent on prious authentication

   //
   // Retrieving the returned data and set to IOTableAuthority structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( -1 != row.CommonName_length )
   {
      memset( row.CommonName, 0, sizeof( row.CommonName ) );
      row.CommonName_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.CommonName, sizeof(row.CommonName) -1, "CommonName", 2 );
      if( p1 == p2 )
         row.CommonName_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.CommonName_length )

   if( row.IsClass_isValid )
   {
      row.IsClass = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "IsClass", 3 ) ? true : false;
      if( p1 == p2 )
         row.IsClass_isValid = false;
      else
         p2 = p1;
   } // if( row.IsClass_isValid )

   if( row.Class_isValid )
   {
      row.Class = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Class", 4 );
      if( p1 == p2 )
         row.Class_isValid = false;
      else
         p2 = p1;
   } // if( row.Class_isValid )

   if( row.Enabled_isValid )
   {
      row.Enabled = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Enabled", 5 ) ? true : false;
      if( p1 == p2 )
         row.Enabled_isValid = false;
      else
         p2 = p1;
   } // if( row.Enabled_isValid )

   if( row.Secure_isValid )
   {
      row.Secure = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Secure", 6 );
      if( p1 == p2 )
         row.Secure_isValid = false;
      else
         p2 = p1;
   } // if( row.Secure_isValid )

   if( row.HashAndSign_isValid )
   {
      row.HashAndSign = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "HashAndSign", 7 );
      if( p1 == p2 )
         row.HashAndSign_isValid = false;
      else
         p2 = p1;
   } // if( row.HashAndSign_isValid )

   if( row.PresentCertificate_isValid )
   {
      row.PresentCertificate = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "PresentCertificate", 8 ) ? true : false;
      if( p1 == p2 )
         row.PresentCertificate_isValid = false;
      else
         p2 = p1;
   } // if( row.PresentCertificate_isValid )

   if( row.Operation_isValid )
   {
      row.Operation = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Operation", 9 );
      if( p1 == p2 )
         row.Operation_isValid = false;
      else
         p2 = p1;
   } // if( row.Operation_isValid )

   if( row.Credential_isValid )
   {
      row.Credential = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Credential", 0x0A );
      if( p1 == p2 )
         row.Credential_isValid = false;
      else
         p2 = p1;
   } // if( row.Credential_isValid )

   if( row.ResponseSign_isValid )
   {
      row.ResponseSign = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ResponseSign", 0x0B );
      if( p1 == p2 )
         row.ResponseSign_isValid = false;
      else
         p2 = p1;
   } // if( row.ResponseSign_isValid )

   if( row.ResponseExch_isValid )
   {
      row.ResponseExch = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ResponseExch", 0x0C );
      if( p1 == p2 )
         row.ResponseExch_isValid = false;
      else
         p2 = p1;
   } // if( row.ResponseExch_isValid )

   if( row.ClockStart_isValid )
   {
      p1 = decodeNamedValueName( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ClockStart", 0x0D );
      if( NULL != p1 )
      {
         if( m_tokenProcessor.isListToken(*p1) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p1 ++ );
            if( 0 == tmp ) // empty is valid
            {
               row.ClockStart_isValid = false;
            }
            else
            {
               if( 3 != tmp )
                  throw dta::Error(eGenericInvalidIdentifier);

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockStart_Year = (tUINT16) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockStart_Month = (tUINT8) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockStart_Day = (tUINT8) tmp;
            }

            p1 += 2; // EL, EN
            p2 = p1;
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
      {
         p1 = p2;
         row.ClockStart_isValid = false;
      }
   } // if( row.ClockStart_isValid )

   if( row.ClockEnd_isValid )
   {
      p1 = decodeNamedValueName( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ClockEnd", 0x0E );
      if( NULL != p1 )
      {
         if( m_tokenProcessor.isListToken(*p1) )
         {
            tmp = m_tokenProcessor.numberOfListItems( p1 ++ );
            if( 0 == tmp ) // empty is valid
            {
               row.ClockEnd_isValid = false;
            }
            else
            {
               if( 3 != tmp )
                  throw dta::Error(eGenericInvalidIdentifier);

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockEnd_Year = (tUINT16) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockEnd_Month = (tUINT8) tmp;

               p1 = m_tokenProcessor.getNamedValueTokenValue( p1, tmp );
               row.ClockEnd_Day = (tUINT8) tmp;
            }

            p1 += 2; // EL, EN
            p2 = p1;
         }
         else
            throw dta::Error(eGenericInvalidIdentifier);
      }
      else
      {
         p1 = p2;
         row.ClockEnd_isValid = false;
      }
   } // if( row.ClockEnd_isValid )

   if( row.Limit_isValid )
   {
      row.Limit = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Limit", 0x0F );
      if( p1 == p2 )
         row.Limit_isValid = false;
      else
         p2 = p1;
   } // if( row.Limit_isValid )

   if( row.Uses_isValid )
   {
      row.Uses = (tUINT32) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Uses", 0x10 );
      if( p1 == p2 )
         row.Uses_isValid = false;
      else
         p2 = p1;
   } // if( row.Uses_isValid )

   if( row.Log_isValid )
   {
      row.Log = (tUINT8) decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Log", 0x11 );
      if( p1 == p2 )
         row.Log_isValid = false;
      else
         p2 = p1;
   } // if( row.Log_isValid )

   if( row.LogTo_isValid )
   {
      row.LogTo = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "LogTo", 0x12 );
      if( p1 == p2 )
         row.LogTo_isValid = false;
      else
         p2 = p1;
   } // if( row.LogTo_isValid )

   return status;
} // _getAuthority

//=================================================================================
/// \brief Set the value of the columns("Enabled", etc) of an authority (E.g., User1) in Authority table.
///
/// \param authority   [IN]     Target authority to set to. E.g., User1 authority.
/// \param row         [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setAuthority( TCG_UID authority, IOTableAuthority & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false; // Read-Only, cann't Set

   if( -1 != row.Name_length )
      row.Name_length = -1;    // Read-Only, cann't Set

   if( row.CommonName_length > 0 ) //( -1 != row.CommonName_length )
      p = encodeNamedValue_Bytes( p, row.CommonName, row.CommonName_length, "CommonName", 2 );

   if( row.IsClass_isValid )
   {
      if( isDeviceTCGCoreVersion1() )
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"IsClass", sizeof("IsClass")-1, (tUINT64) row.IsClass );
      else
         row.IsClass_isValid = false; // Read-only in CS2.0 
   }

   if( row.Class_isValid )
      p = encodeNamedValue_UID( p, row.Class, "Class", 4 );

   if( row.Enabled_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Enabled, "Enabled", 5 );

   if( row.Secure_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Secure, "Secure", 6 );

   if( row.HashAndSign_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.HashAndSign, "HashAndSign", 7 );

   if( row.PresentCertificate_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.PresentCertificate, "PresentCertificate", 8 );

   if( row.Operation_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Operation, "Operation", 9 );

   if( row.Credential_isValid )
      p = encodeNamedValue_UID( p, row.Credential, "Credential", 0x0A );

   if( row.ResponseSign_isValid )
      p = encodeNamedValue_UID( p, row.ResponseSign, "ResponseSign", 0x0B );

   if( row.ResponseExch_isValid )
      p = encodeNamedValue_UID( p, row.ResponseExch, "ResponseExch", 0x0C );

   if( row.ClockStart_isValid )
   {
      p = encodeNamedValueName( p, "ClockStart", 0x0D );

      p = m_tokenProcessor.buildStartList( p );
      if( isDeviceTCGCoreVersion1() )
      {
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Year", sizeof("Year")-1, (tUINT64) row.ClockStart_Year );
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Month", sizeof("Month")-1, (tUINT64) row.ClockStart_Month );
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Day", sizeof("Day")-1, (tUINT64) row.ClockStart_Day );
      }
      else
      {
         p = m_tokenProcessor.buildNamedValueToken( p, 0, (tUINT64) row.ClockStart_Year );
         p = m_tokenProcessor.buildNamedValueToken( p, 1, (tUINT64) row.ClockStart_Month );
         p = m_tokenProcessor.buildNamedValueToken( p, 2, (tUINT64) row.ClockStart_Day );
      }
      p = m_tokenProcessor.buildEndList( p );
      p = m_tokenProcessor.buildEndName( p );
   }

   if( row.ClockEnd_isValid )
   {
      p = encodeNamedValueName( p, "ClockEnd", 0x0E );

      p = m_tokenProcessor.buildStartList( p );
      if( isDeviceTCGCoreVersion1() )
      {
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Year", sizeof("Year")-1, (tUINT64) row.ClockEnd_Year );
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Month", sizeof("Month")-1, (tUINT64) row.ClockEnd_Month );
         p = m_tokenProcessor.buildNamedValueToken( p, (dta::tByte *)"Day", sizeof("Day")-1, (tUINT64) row.ClockEnd_Day );
      }
      else
      {
         p = m_tokenProcessor.buildNamedValueToken( p, 0, (tUINT64) row.ClockEnd_Year );
         p = m_tokenProcessor.buildNamedValueToken( p, 1, (tUINT64) row.ClockEnd_Month );
         p = m_tokenProcessor.buildNamedValueToken( p, 2, (tUINT64) row.ClockEnd_Day );
      }

      p = m_tokenProcessor.buildEndList( p );
      p = m_tokenProcessor.buildEndName( p );
   }

   if( row.Limit_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Limit, "Limit", 0x0F );

   if( row.Uses_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Uses, "Uses", 0x10 );

   if( row.Log_isValid )
      p = encodeNamedValue_Integer( p, (tUINT64) row.Log, "Log", 0x11 );

   if( row.LogTo_isValid )
      p = encodeNamedValue_UID( p, row.LogTo, "LogTo", 0x12 );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );
   return _set( authority, data );
} // _setAuthority

//=================================================================================
/// \brief Set the "BooleanExpr" column of an ACE object in the ACE table for the specified authorities.
///
/// \param ace             [IN]  Target ACE object UID. E.g., ACE_Locking_Range1_Set_RdLocked.
/// \param authorities     [IN]  Authority UIDs to set to the given ACE object.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setACE( TCG_UID ace, TCG_UIDs & authorities )
{
   dta::tBytes data( m_blockSize );
   dta::tByte *p = &data[0];

   // Pack data in the form of [ {NamedValue pairs} ] for Set()
   p = m_tokenProcessor.buildStartList( p );
   p = encodeNamedValueName( p, "BooleanExpr", 3 );
   p = m_tokenProcessor.buildStartList( p );

   // Build Boolean_Expr
   for( tUINT16 ii=0; ii < authorities.size(); ii++ )
   {
      p = m_tokenProcessor.buildNamedValueToken( p, (tUINT64) HALFUID_AUTHORITY_REF, 4, authorities[ii], sizeof(TCG_UID), true );

      if( ii > 0 )
         p = m_tokenProcessor.buildNamedValueToken( p, (tUINT64) HALFUID_BOOLEAN_ACE, 4, evOr, -1, false );
   }

   p = m_tokenProcessor.buildEndList( p );
   p = m_tokenProcessor.buildEndName( p );
   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );
   return _set( ace, data );
} // _setACE

//=================================================================================
/// \brief Get value of 'Mode' from the K_AES_128/256 table row.
///
/// \param kaes    [IN]   UID of the K_AES_128 or 256 table row to get columns from.
/// \param mode    [OUT]  The 'Mode' value to be returned (an enum, 0-23).
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getK_AES( TCG_UID kaes, tUINT8 & mode )
{
   dta::tBytes data;
   TCG_STATUS status = _get( kaes, data );

   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   tUINT8 *p = &data[1];
   mode = (tUINT8) decodeNamedValue_Integer( p, (tUINT32) data.size()-2, "Mode", 4 );

   if( p == &data[1] )
      return TS_INVALID_REFERENCE; // No data found
   else
      return status;
} // _getK_AES

//=================================================================================
/// \brief Read/Get the states of Enable/Done/MBRDoneOnReset from the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getMBRControl( IOTableMBRControl & row )
{
   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status = _get( UID_MBRCONTROL, data );

   //
   // Retrieving the returned data and set to IOTableMBRControl structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( row.Enable_isValid )
   {
      row.Enable = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Enable", 1 ) ? true : false;
      if( p1 == p2 )
         row.Enable_isValid = false;
      else
         p2 = p1;
   }

   if( row.Done_isValid )
   {
      row.Done = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "Done", 2 ) ? true : false;
      if( p1 == p2 )
         row.Done_isValid = false;
      else
         p2 = p1;
   }

   if( -1 != row.MBRDoneOnReset_length )
   {
      memset( row.MBRDoneOnReset, 0, sizeof( row.MBRDoneOnReset ) );
      row.MBRDoneOnReset_length = (tUINT8) decodeNamedValue_IntgerList( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.MBRDoneOnReset, (tUINT32) (sizeof(row.MBRDoneOnReset)/sizeof(row.MBRDoneOnReset[0])), "MBRDoneOnReset", 3 );
      if( p1 == p2 )
         row.MBRDoneOnReset_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.MBRDoneOnReset_length )

   return status;
} // _getMBRControl

//=================================================================================
/// \brief Write/Set the states of Enable/Done/MBRDoneOnReset to the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_setMBRControl( IOTableMBRControl & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false; // Read-Only, cann't Set

   if( row.Enable_isValid )
      p = encodeNamedValue_Integer( p, row.Enable, "Enable", 1 );

   if( row.Done_isValid )
      p = encodeNamedValue_Integer( p, row.Done, "Done", 2 );

   if( row.MBRDoneOnReset_length >= 0 ) //( -1 != row.MBRDoneOnReset_length )
      p = encodeNamedValue_IntgerList( p, row.MBRDoneOnReset, row.MBRDoneOnReset_length, "MBRDoneOnReset", 3 );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );

   return _set( UID_MBRCONTROL, data );
} // _setMBRControl

//=================================================================================
/// \brief Get the 'Rows' column value of a given table on the TPer's Table-Table.
///
/// \param targetTable  [IN]   Target table UID.
/// \param numRows      [OUT]  Number of rows read for the 'Rows' column.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_getNumberOfRows( TCG_UID targetTable, tUINT64 & numRows )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p;
   TCG_STATUS status;

   if( isDeviceTCGCoreVersion1() )
   {
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      status = _get( targetTable, data, "Rows", "Rows" );
#else
      status = _get( targetTable, data, (char *)"Rows", (char *)"Rows" );
#endif
      p = m_tokenProcessor.retrieveNamedDataFromList( data, (tUINT8*)"Rows", sizeof("Rows")-1 );
   }
   else
   {
      status = _get( targetTable, 7, 7, data ); // "Rows"
      p = m_tokenProcessor.retrieveNamedDataFromList( data, 7 );
   }

   if( NULL == p )
      return TS_INVALID_REFERENCE; // No data found

   numRows = m_tokenProcessor.getAtomData( p );

   return status;
} // _getNumberOfRows

//=================================================================================
/// \brief Read/Get the states of PortLocked/LockOnReset from the _PortLocking table on the TPer. (Seagate proprietary)
///
/// \param port  [IN]      Target port UID, a port object UID in the _PortLocking table.
/// \param row   [IN/OUT]  _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_get_PortLocking( TCG_UID port, IOTable_PortLocking & row )
{
   tUINT8 *p1, *p2;
   dta::tBytes data;
   TCG_STATUS status = _get( port, data ); // Get all the eligible columns dependent on prious authentication

   //
   // Retrieving the returned data and set to IOTable_PortLocking structure
   //
   if( !m_tokenProcessor.isList( data ) ) // At least []
      throw dta::Error(eGenericInvalidIdentifier);

   p1 = p2 = &data[1];

   if( row.UID_isValid )
   {
      row.UID = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "UID", 0 );
      if( p1 == p2 )
         row.UID_isValid = false;
      else
         p2 = p1;
   } // if( row.UID_isValid )

   if( -1 != row.Name_length )
   {
      memset( row.Name, 0, sizeof( row.Name ) );
      row.Name_length = (tINT8) decodeNamedValue_Bytes( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.Name, sizeof(row.Name) -1, "Name", 1 );
      if( p1 == p2 )
         row.Name_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.Name_length )

   if( -1 != row.LockOnReset_length )
   {
      memset( row.LockOnReset, 0, sizeof( row.LockOnReset ) );
      row.LockOnReset_length = (tUINT8) decodeNamedValue_IntgerList( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), row.LockOnReset, (tUINT32) (sizeof(row.LockOnReset)/sizeof(row.LockOnReset[0])), "LockOnReset", 2 );
      if( p1 == p2 )
         row.LockOnReset_length = -1;
      else
         p2 = p1;
   } // if( -1 != row.LockOnReset_length )

   if( row.PortLocked_isValid )
   {
      row.PortLocked = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "PortLocked", 3 ) ? true : false;
      if( p1 == p2 )
         row.PortLocked_isValid = false;
      else
         p2 = p1;
   } // if( row.PortLocked_isValid )

   return status;
} // _get_PortLocking

//=================================================================================
/// \brief Write/Set the states of PortLocked/LockOnReset to the _PortLocking table on the TPer. (Seagate proprietary)
///
/// \param port  [IN]      Target port UID, a port object UID in the _PortLocking table.
/// \param row   [IN/OUT]  _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgCoreInterface::_set_PortLocking( TCG_UID port, IOTable_PortLocking & row )
{
   dta::tBytes data( m_blockSize );
   tUINT8 *p = &data[0];

   p = m_tokenProcessor.buildStartList( p );

   if( row.UID_isValid )
      row.UID_isValid = false; // Read-Only, cann't Set

   if( -1 != row.Name_length )
      row.Name_length = -1;    // Read-Only, cann't Set

   if( row.LockOnReset_length >= 0 ) //( -1 != row.LockOnReset_length )
      p = encodeNamedValue_IntgerList( p, row.LockOnReset, row.LockOnReset_length, "LockOnReset", 2 );

   if( row.PortLocked_isValid )
      p = encodeNamedValue_Integer( p, row.PortLocked, "PortLocked", 3 );

   p = m_tokenProcessor.buildEndList( p );

   data.resize( p - &data[0] );

   return _set( port, data );
} // _set_PortLocking

//=================================================================================
/// \brief Initial discovery of TCG Core version and Level0 data from the TPer.
///
/// \return TCG_STATUS.
//=================================================================================
TCG_STATUS CTcgCoreInterface::probeTcgCoreSSC()
{
   m_tcgCoreSpecVersion = 2; // Try to talk in CS2.0

   M_TCGTry()
   {
      m_packetManager.setTPerSN( 0 );
      refreshLevel0DiscoveryData();
      m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );

      // Detecting Core spec version, a necessary step to decide all the subsequent method-calls
      dta::tBytes data;
      _startSession( UID_SP_ADMIN );
      _get( ( isDeviceEnterpriseSSC() ? UID_TPERINFO_E : UID_TPERINFO_OM ), data ); //_get( UID_TABLE_TPERINFO, UID_TPERINFO, data ); //Temporarily works, until Ent CS2.0 IV rectified
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( ! M_TCGResultOK() )
   {
      if( TS_SP_BUSY == M_TCGResult() )
         m_orphanSessionDetected = true;

      if( TS_INVALID_COMMAND == M_TCGResult() )
         m_tcgCoreSpecVersion = 1;

      _closeSession();
   }

   M_TCGReturn( false );
} // probeTcgCoreSSC

//=================================================================================
/// \brief Writes the command ComPacket or IF-Send byte flow to the log file.
///
/// \param protocolID  [IN]  Security Protocol ID, 00, 01, 02, and up to 06 are valid IDs for TCG.
/// \param spSpecific  [IN]  Security Protocol Specific value.
/// \param packetMode  [IN]  Is the payload in TCG ComPacket format or not (Byte-Stream format).
///
/// \pre ComPacket or IF-Send data has been prepared fully ready prior to calling this function.
///
/// \return
//=================================================================================
void CTcgCoreInterface::logSecuritySend( tUINT8 protocolID, tUINT16 spSpecific, bool packetMode )
{
   int length;
   char buffer[160];

   if( packetMode ) // for most of the protocol ID=01 (except Level 0 discovery 01/0001)
   {
      fprintf( m_logFile, "<Exchange method=\"%s\">\n", interpretExchangeName(packetMode, buffer, sizeof(buffer)) );
      length = m_packetManager.getComPacketPayloadLength();
      length += sizeof( TCG_COM_PACKET_HEADER );
   }
   else // Non-packet commands include all protocolID=0(Protocol 0 discovery with sp=0000 & Certtificate retriving with sp=0001, retrieving only), ProtocolID=2 (ComManagement exchange), and 01/0001 Level 0 discovery (retrieving only).
   {
      if( SECURITY_PROTOCOLID_COMID_MANAGEMENT == protocolID )
      {
         if( SPSPECIFIC_P02_TPER_RESET == spSpecific )
            fprintf( m_logFile, "<Transporting method=\"TCG TPerReset\">\n" ); // TPer Reset as set by the OPAL 2.0 spec
      else
            fprintf( m_logFile, "<Exchange method=\"TCG ComID Management - %s\">\n", interpretExchangeName(packetMode, buffer, sizeof(buffer)) ); // ComID management as set by the current spec
      }
      else if( protocolID <= SECURITY_PROTOCOLID_MAXTCGID )
      {
         fprintf( m_logFile, "<Exchange method=\"TCG Protocol(%0x02X, unrecognized yet)\">\n", protocolID ); // ComID management as set by the current spec
      }
      else
      {
         fprintf( m_logFile, "<Exchange method=\"Non_TCG Protocol\">\n" );
      }

      length = (int) m_commandBuffer.size();
   }

   fprintf( m_logFile, "\t<IF_Send Protocol='0x%02X' SPSpecific='0x%04X' Length='%d'>\n", protocolID, spSpecific, length );

   logTcgPayload( m_commandBuffer, length );

   fprintf( m_logFile, "\t</IF_Send>\n" );


   if( !packetMode && SECURITY_PROTOCOLID_COMID_MANAGEMENT == protocolID && SPSPECIFIC_P02_TPER_RESET == spSpecific )
      fprintf( m_logFile, "</Transporting>\n" );
} // logSecuritySend

//=================================================================================
/// \brief Writes the response ComPacket or IF-Recv byte flow to the log file.
///
/// \param protocolID  [IN]  Security Protocol ID, 00, 01, 02, and up to 06 are valid IDs for TCG.
/// \param spSpecific  [IN]  Security Protocol Specific value.
/// \param packetMode  [IN]  Is the payload in TCG ComPacket format or not (Byte-Stream format).
///
/// \pre ComPacket or IF-Recv data has been fully received prior to calling this function.
///
/// \return
//=================================================================================
void CTcgCoreInterface::logSecurityRecv( tUINT8 protocolID, tUINT16 spSpecific, bool packetMode )
{
   int length;
   if( packetMode ) // for most of the protocol ID=01 (except Level 0 discovery 01/0001)
   {
      m_packetManager.setComBuffer( m_responseBuffer, false );
      length = m_packetManager.getComPacketPayloadLength();
      length += sizeof( TCG_COM_PACKET_HEADER );
   }
   else // Non-packet commands include all protocolID=0(Protocol 0 discovery with sp=0000 & Certtificate retriving with sp=0001, retrieving only), ProtocolID=2 (ComManagement exchange), and 01/0001 Level 0 discovery (retrieving only).
   {
      if( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY == protocolID )
      {
         if( SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST == spSpecific )
            fprintf( m_logFile, "<Retrieving method=\"Protocol 0 Discovery - Security Protocol List\">\n" );
         else if( SPSPECIFIC_P00_CERTIFICATE_DATA == spSpecific )
            fprintf( m_logFile, "<Retrieving method=\"Protocol 0 Discovery - Certificate\">\n" );
         else if( SPSPECIFIC_P00_SECURITY_COMPLIANCE_INFO == spSpecific )
            fprintf( m_logFile, "<Retrieving method=\"Protocol 0 Discovery - Security Compliance\">\n" );
         else
            fprintf( m_logFile, "<Retrieving method=\"Protocol 0 Discovery - Unrecognized Request\">\n" );
      }
      else if( SECURITY_PROTOCOLID_COMPACKET_IO == protocolID )
      {
         if( SPSPECIFIC_P01_LEVEL0_DISCOVERY == spSpecific )
            fprintf( m_logFile, "<Retrieving method=\"TCG Level 0 Discovery\">\n" );
         else
            fprintf( m_logFile, "<Retrieving method=\"TCG, Invalid Request\">\n" );
      }
      else if( SECURITY_PROTOCOLID_COMID_MANAGEMENT == protocolID )
      {
         if( SPSPECIFIC_P02_GET_COM_ID == spSpecific )
         {
            fprintf( m_logFile, "<Retrieving method=\"ComID Management - GetComID\">\n" );
         }
         else
         {
            // Do nothing for the rest. Other TCG ComID Management runs in pair of IF_Send/Recv. XML tag already added.
         }
      }
      else
      {
         // Do nothing. XML tag should have already been added in IF-Send logging.
      }

      length = (int) m_responseBuffer.size();
   }

#if defined(_WIN32) // nvn20110719 - remove gcc warning
   fprintf( m_logFile, "\t<IF_Recv Protocol='0x%02X' SPSpecific='0x%04X' Length='%d' MethodExecTimeMs='%u'>\n", protocolID, spSpecific, length, m_methodExecTimeMilliSecond );
#else
   fprintf( m_logFile, "\t<IF_Recv Protocol='0x%02X' SPSpecific='0x%04X' Length='%d' MethodExecTimeMs='%u'>\n", protocolID, spSpecific, length, (uint)m_methodExecTimeMilliSecond );
#endif

   logTcgPayload( m_responseBuffer, length );

   fprintf( m_logFile, "\t</IF_Recv>\n" );

   if( packetMode )
   {
      fprintf( m_logFile, "</Exchange>\n" );
   }
   else
   {
      if( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY == protocolID || SECURITY_PROTOCOLID_COMPACKET_IO == protocolID || (SECURITY_PROTOCOLID_COMID_MANAGEMENT == protocolID && SPSPECIFIC_P02_GET_COM_ID == spSpecific) )
      {
         fprintf( m_logFile, "</Retrieving>\n" );
      }
      else // future expension, including (0x02 == protocolID)
      {
         fprintf( m_logFile, "</Exchange>\n" );
      }
   }
} // logSecurityRecv

//=================================================================================
/// \brief Log TCG Payload data in the given buffer to the log file.
///
/// \return the address of the interpreted names.
//=================================================================================
void CTcgCoreInterface::logTcgPayload( dta::tBytes & buffer, int bytesToShow, bool logASCII )
{
   if( bytesToShow > (int)buffer.size() )
      bytesToShow = (int) buffer.size();

   int lines = ( bytesToShow + 15 ) / 16;

   fprintf( m_logFile, "\t<![CDATA[\t\n" ); // XML unparsed data begins

   for( int ii=0; ii < lines; ii++ )
   {
       fprintf( m_logFile, "\t\t%04X:  ", ii*16 );
       for( int jj=0; jj<4; jj++ )
       {
          for( int kk=0; kk<4; kk++ )
          {
             int p = ii*16 + jj*4 + kk;
             if( p < bytesToShow )
                fprintf( m_logFile, "%02X", buffer[ p ] );
             else
                fprintf( m_logFile, "  " );
          }

          fprintf( m_logFile, " " );
       }

       if( !logASCII )
       {
          fprintf( m_logFile, "\n" );
          continue;
       }

       fprintf( m_logFile, "\t " );

       for( int jj=0; jj<16; jj++ )
       {
          int p = ii*16 + jj;
          if( p < bytesToShow )
          {
             if( isprint(buffer[p]) && buffer[p] != '\t' && buffer[p] != '\b' && buffer[p] != '\n' && buffer[p] != '\r' && buffer[p] != '<' && buffer[p] != '>' )
                fprintf( m_logFile, "%C", buffer[p] );
             else
                fprintf( m_logFile, "#" );
          }
          else
          {
             fprintf( m_logFile, "  " );
          }
       }

       fprintf( m_logFile, "\n" );
   }

   fprintf( m_logFile, "\t]]>\n" ); // XML unparsed data ends
} // logTcgPayload

//=================================================================================
/// \brief Interpret the Invoking UID and Method UID set in the commandBuffer.
///
/// \param packetMode  [IN]    Is the payload in TCG ComPacket format or not (Byte-Stream format).
/// \param pBuffer     [OUT]   Caller provided buffer to store the symbolic names of the UIDs.
/// \param length      [IN]    Length of the buffer, usually 160 bytes required.
///
/// \pre ComPacket or IF-Send data has been prepared fully ready prior to calling this function.
///
/// \return the address of the interpreted names.
//=================================================================================
char *CTcgCoreInterface::interpretExchangeName( bool packetMode, char *pBuffer, int length )
{
   memset( pBuffer, 0, length );
#if !defined(_WIN32) // nvn20110719
   std::ostringstream strStream;
#endif
   if( packetMode )
   {
      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer, false );

      if( m_tokenProcessor.isCallToken( *p ) )
      {
         tUINT64 target, method;
         char name1[80], name2[80];
         p = m_tokenProcessor.getShortAtomData( ++p, &target );
         p = m_tokenProcessor.getShortAtomData( p, &method );
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, length, "%s.%s", mapUIDToName( target, name1, sizeof(name1) ), mapUIDToName(method, name2, sizeof(name2) ) );
#else
         strStream << mapUIDToName( target, name1, sizeof(name1) ) << "." << mapUIDToName(method, name2, sizeof(name2) ) ;
#endif

         if( UID_SESSION_MANAGER == target && UID_M_START_SESSION == method )
         {
            p++; // F0
            p = m_tokenProcessor.skipSimpleToken( p ); // HSN
            tUINT64 sp = m_tokenProcessor.getShortAtomData( p );
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer + strlen(pBuffer), length - strlen(pBuffer), " (%s)", mapUIDToName( sp, name1, sizeof(name1) ) );
#else
            strStream << " (" << mapUIDToName( sp, name1, sizeof(name1) ) << ")";
#endif
         }
      }
      else if( m_tokenProcessor.isEOS( *p ) )
      {
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, length, "%s", "CloseSession" );
#else
         strStream << "CloseSession";
#endif
      }
      else if( m_tokenProcessor.isStartTransactionToken( *p ) )
      {
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, length, "%s", "StartTransaction" );
#else
         strStream << "StartTransaction";
#endif
      }
      else if( m_tokenProcessor.isEndTransactionToken( *p ) )
      {
         if( m_tokenProcessor.getEndTransactionStatus(p) )
         {
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer, length, "%s", "EndTransaction(Abort)" );
#else
            strStream << "EndTransaction(Abort)";
#endif
         }
         else
         {
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer, length, "%s", "EndTransaction(Commit)" );
#else
            strStream << "EndTransaction(Commit)";
#endif
         }
      }
      else
      {
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, length, "Unrecognized method-call token(%02X)", *p );
#else
         strStream << "Unrecognized method-call token(" << *p << ")";
#endif
      }
   }
   else
   {
      tUINT32 requestCode = m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[4])) );
      switch( requestCode )
      {
         case VERIFY_COMID_REQ_CODE:
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer, length, "VerifyComdID(0x%08X)", m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) );
#else
            strStream << "VerifyComdID(" << m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) << ")";
#endif
            break;

         case PROTOCOL_STACK_RESET_REQ_CODE:
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer, length, "ResetStack(0x%08X)", m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) );
#else
            strStream << "ResetStack(" << m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) << ")";
#endif
            break;

         default:
#if defined(_WIN32) // nvn20110719
            sprintf_s( pBuffer, length, "Unrecognized Code 0x%08X (0x%08X)", requestCode, m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) );
#else
            strStream << "Unrecognized Code " << requestCode <<" (" << m_swapper.NetToHost( *((tUINT32*)(&m_commandBuffer[0])) ) << ")";
#endif
      }
   }

#if !defined(_WIN32) // nvn20110719
   if ((uint)length >= (strStream.str()).length())
   {
      memcpy( pBuffer, &(strStream.str())[0], (strStream.str()).length() );
   }
   else
   {
      memcpy( pBuffer, &(strStream.str())[0], length );
   }
#endif

   return pBuffer;
} // interpretExchangeName

//=================================================================================
/// \brief Translate a UID value to a symbolic name.
///
/// \param uid        [IN]   Given UID to be translated to its symbolic name.
/// \param pBuffer    [OUT]  Caller provided buffer to store the symbolic name of the UID.
/// \param maxLength  [IN]   Maximum length of the buffer, usually 80 bytes required.
///
/// \return the address of the interpreted invoking or Method UID's name.
//=================================================================================
char *CTcgCoreInterface::mapUIDToName( TCG_UID uid, char *pBuffer, int maxLength )
{
#if !defined(_WIN32) // nvn20110719
   std::ostringstream strStream;
#endif

   typedef struct _TCG_UID_SYMBOLICNAME_PAIR
   {
      tUINT64 uid;
      #if defined(_WIN32) // nvn20110701
      char *symbolicName;
      #else
      const char *symbolicName;
      #endif
   } TCG_UID_SYMBOLICNAME_PAIR, *PTCG_UID_SYMBOLICNAME_PAIR;

   static TCG_UID_SYMBOLICNAME_PAIR uidList[] =
   {
      // SP UIDs & Special UIDs
      { UID_SP_ADMIN,                           "AdminSP_UID"                           },
      { UID_SP_LOCKING_E,                       "LockingSP_UID"                         },
      { UID_SP_LOCKING_OM,                      "LockingSP_UID"                         },
      { UID_THIS_SP,                            "ThisSP"                                },
      { UID_SESSION_MANAGER,                    "SMUID"                                 },

      // Table UIDs
      { UID_TABLE_TABLE,                        "Table_Table_UID"                       },
      { UID_TABLE_SPINFO,                       "SPInfo_Table_UID"                      },
      { UID_TABLE_SPTEMPLATES,                  "SPTemplates_Table_UID"                 },
      { UID_TABLE_COLUMN,                       "Column_Table_UID"                      },
      { UID_TABLE_TYPE,                         "Type_Table_UID"                        },
      { UID_TABLE_METHODID,                     "MethodID_Table_UID"                    },
      { UID_TABLE_METHOD,                       "Method_Table_UID"                      },  //*Called "Method" table in Core1.0
      { UID_TABLE_ACCESSCONTROL,                "AccessControl_Table_UID"               },  //*Core 2.0
      { UID_TABLE_ACE,                          "ACE_Table_UID"                         },
      { UID_TABLE_AUTHORITY,                    "Authority_Table_UID"                   },
      { UID_TABLE_CERTIFICATES,                 "Certificates_Table_UID"                },
      { UID_TABLE_C_PIN,                        "C_PIN_Table_UID"                       },
      { UID_TABLE_C_RSA_1024,                   "C_RSA_1024_Table_UID"                  },
      { UID_TABLE_C_RSA_2048,                   "C_RSA_2048_Table_UID"                  },
      { UID_TABLE_C_AES_128,                    "C_AES_128_Table_UID"                   },
      { UID_TABLE_C_AES_256,                    "C_AES_256_Table_UID"                   },
      { UID_TABLE_C_EC_160,                     "C_EC_160_Table_UID"                    },
      { UID_TABLE_C_EC_192,                     "C_EC_192_Table_UID"                    },
      { UID_TABLE_C_EC_224,                     "C_EC_224_Table_UID"                    },
      { UID_TABLE_C_EC_256,                     "C_EC_256_Table_UID"                    },
      { UID_TABLE_C_EC_384,                     "C_EC_384_Table_UID"                    },
      { UID_TABLE_C_EC_521,                     "C_EC_521_Table_UID"                    },
      { UID_TABLE_C_EC_163,                     "C_EC_163_Table_UID"                    },
      { UID_TABLE_C_EC_233,                     "C_EC_233_Table_UID"                    },
      { UID_TABLE_C_EC_283,                     "C_EC_283_Table_UID"                    },
      { UID_TABLE_C_HMAC_160,                   "C_HMAC_160_Table_UID"                  },
      { UID_TABLE_C_HMAC_256,                   "C_HMAC_256_Table_UID"                  },
      { UID_TABLE_C_HMAC_384,                   "C_HMAC_384_Table_UID"                  },
      { UID_TABLE_C_HMAC_512,                   "C_HMAC_512_Table_UID"                  },
      { UID_TABLE_SECRET_PROTECT,               "SecretProtect_Table_UID"               },
      { UID_TABLE_TPERINFO,                     "TPerInfo_Table_UID"                    },
      { UID_TABLE_PROPERTIES,                   "Properties_Table_UID"                  },  // defined in Core1.0, obsolete in Core2.0
      { UID_TABLE_CRYPTO_SUITE,                 "CryptoSuite_Table_UID"                 },
      { UID_TABLE_TEMPLATE,                     "Template_Table_UID"                    },
      { UID_TABLE_SP,                           "SP_Table_UID"                          },
      { UID_TABLE_CLOCKTIME,                    "ClockTime_Table_UID"                   },
      { UID_TABLE_H_SHA_1,                      "H_SHA_1_Table_UID"                     },
      { UID_TABLE_H_SHA_256,                    "H_SHA_256_Table_UID"                   },
      { UID_TABLE_H_SHA_384,                    "H_SHA_384_Table_UID"                   },
      { UID_TABLE_H_SHA_512,                    "H_SHA_512_Table_UID"                   },
      { UID_TABLE_LOG,                          "Log_Table_UID"                         },
      { UID_TABLE_LOGLIST,                      "LogList_Table_UID"                     },
      { UID_TABLE_LOCKINGINFO,                  "LockingInfo_Table_UID"                 },
      { UID_TABLE_LOCKING,                      "Locking_Table_UID"                     },
      { UID_TABLE_MBRCONTROL,                   "MBRControl_Table_UID"                  },
      { UID_TABLE_MBR,                          "MBR_Table_UID"                         },
      { UID_TABLE_K_AES_128,                    "K_AES_128_Table_UID"                   },
      { UID_TABLE_K_AES_256,                    "K_AES_256_Table_UID"                   },
      { UID_TABLE_DATASTORE1_EM,                "DataStore1_Table_UID"                  },  //*+defined in Ent-SSC & Marble-SSC (DataStoreB-MB)
      { UID_TABLE_DATASTORE1_OM,                "DataStore1_Table_UID"                  },  //*+defined in Opal-SSC & Marble-SSC (DataStoreA), Additional_DataStore_Tables.
      { UID_TABLE_RESTRICTEDCMDS,               "RestrictedCommands_Table_UID"          },  // defined in Opal-SSC & Marble-SSC (O)
      { UID_TABLE_SECURITY_OPERATING_MODE,      "_SecurityOperatingMode_Table_UID"      },  // Seagate proprietary, defined in "TcgFdeProductRequirements"

      // TableTable Row UIDs
      { UID_TABLETABLE_TABLE,                   "TableTable_Table_UID"                  },
      { UID_TABLETABLE_SPINFO,                  "TableTable_SPInfo_UID"                 },
      { UID_TABLETABLE_SPTEMPLATES,             "TableTable_SPTemplates_UID"            },
      { UID_TABLETABLE_COLUMN,                  "TableTable_Column_UID"                 },
      { UID_TABLETABLE_TYPE,                    "TableTable_Type_UID"                   },
      { UID_TABLETABLE_METHODID,                "TableTable_MethodID_UID"               },
      { UID_TABLETABLE_ACCESSCONTROL,           "TableTable_AccessControl_UID"          },
      { UID_TABLETABLE_ACE,                     "TableTable_ACE_UID"                    },
      { UID_TABLETABLE_AUTHORITY,               "TableTable_Authority_UID"              },
      { UID_TABLETABLE_CERTIFICATES,            "TableTable_Certificates_UID"           },
      { UID_TABLETABLE_C_PIN,                   "TableTable_C_PIN_UID"                  },
      { UID_TABLETABLE_C_RSA_1024,              "TableTable_C_RSA_1024_UID"             },
      { UID_TABLETABLE_C_RSA_2048,              "TableTable_C_RSA_2048_UID"             },
      { UID_TABLETABLE_C_AES_128,               "TableTable_C_AES_128_UID"              },
      { UID_TABLETABLE_C_AES_256,               "TableTable_C_AES_256_UID"              },
      { UID_TABLETABLE_C_EC_160,                "TableTable_C_EC_160_UID"               },
      { UID_TABLETABLE_C_EC_192,                "TableTable_C_EC_192_UID"               },
      { UID_TABLETABLE_C_EC_224,                "TableTable_C_EC_224_UID"               },
      { UID_TABLETABLE_C_EC_256,                "TableTable_C_EC_256_UID"               },
      { UID_TABLETABLE_C_EC_384,                "TableTable_C_EC_384_UID"               },
      { UID_TABLETABLE_C_EC_521,                "TableTable_C_EC_521_UID"               },
      { UID_TABLETABLE_C_EC_163,                "TableTable_C_EC_163_UID"               },
      { UID_TABLETABLE_C_EC_233,                "TableTable_C_EC_233_UID"               },
      { UID_TABLETABLE_C_EC_283,                "TableTable_C_EC_283_UID"               },
      { UID_TABLETABLE_C_HMAC_160,              "TableTable_C_HMAC_160_UID"             },
      { UID_TABLETABLE_C_HMAC_256,              "TableTable_C_HMAC_256_UID"             },
      { UID_TABLETABLE_C_HMAC_384,              "TableTable_C_HMAC_384_UID"             },
      { UID_TABLETABLE_C_HMAC_512,              "TableTable_C_HMAC_512_UID"             },
      { UID_TABLETABLE_SECRET_PROTECT,          "TableTable_Secret_Protect_UID"         },
      { UID_TABLETABLE_TPERINFO,                "TableTable_TPerInfo_UID"               },
      { UID_TABLETABLE_PROPERTIES,              "TableTable_Properties_UID"             },  // defined in Core1.0, obsolete in Core2.0
      { UID_TABLETABLE_CRYPTO_SUITE,            "TableTable_Crypto_Suite_UID"           },
      { UID_TABLETABLE_TEMPLATE,                "TableTable_Template_UID"               },
      { UID_TABLETABLE_SP,                      "TableTable_SP_UID"                     },
      { UID_TABLETABLE_CLOCKTIME,               "TableTable_ClockTime_UID"              },
      { UID_TABLETABLE_H_SHA_1,                 "TableTable_H_SHA_1_UID"                },
      { UID_TABLETABLE_H_SHA_256,               "TableTable_H_SHA_256_UID"              },
      { UID_TABLETABLE_H_SHA_384,               "TableTable_H_SHA_384_UID"              },
      { UID_TABLETABLE_H_SHA_512,               "TableTable_H_SHA_512_UID"              },
      { UID_TABLETABLE_LOG,                     "TableTable_Log_UID"                    },
      { UID_TABLETABLE_LOGLIST,                 "TableTable_LogList_UID"                },
      { UID_TABLETABLE_LOCKINGINFO,             "TableTable_LockingInfo_UID"            },
      { UID_TABLETABLE_LOCKING,                 "TableTable_Locking_UID"                },
      { UID_TABLETABLE_MBRCONTROL,              "TableTable_MBRControl_UID"             },
      { UID_TABLETABLE_MBR,                     "TableTable_MBR_UID"                    },
      { UID_TABLETABLE_K_AES_128,               "TableTable_K_AES_128_UID"              },
      { UID_TABLETABLE_K_AES_256,               "TableTable_K_AES_256_UID"              },
      { UID_TABLETABLE_DATASTORE1_EM,           "TableTable_DataStore1_UID"             },  //*+defined in Ent-SSC & Marble-SSC (DataStoreB)
      { UID_TABLETABLE_DATASTORE1_OM,           "TableTable_DataStore1_UID"             },  //*+defined in Opal-SSC & Marble-SSC (DataStoreA), Additional_DataStore_Tables.
      { UID_TABLETABLE_RESTRICTEDCMDS,          "TableTable_RestrictedCommands_UID"     },  // defined in Opal-SSC & Marble-SSC (TT2)
      { UID_TABLETABLE_SECURITY_OPERATING_MODE, "TableTable__SecurityOperatingMode_UID" },  // Seagate proprietary, defined in "TcgFdeProductRequirements"

      // Session Mgr Method UIDs
      { UID_M_PROPERTIES,                       "Properties"                            },
      { UID_M_START_SESSION,                    "StartSession"                          },
      { UID_M_SYNC_SESSION,                     "SyncSession"                           },
      { UID_M_START_TRUSTED_SESSION,            "StartTrustedSession"                   },
      { UID_M_SYNC_TRUSTED_SESSION,             "SyncTrustedSession"                    },
      { UID_M_CLOSE_SESSION,                    "CloseSession"                          },

      // Method UIDs
      { UID_M_DELETE_SP,                        "DeleteSP"                              },
      { UID_M_CREATE_TABLE,                     "CreateTable"                           },
      { UID_M_DELETE,                           "Delete"                                },
      { UID_M_CREATE_ROW,                       "CreateRow"                             },
      { UID_M_DELETE_ROW,                       "DeleteRow"                             },
      { UID_M_GET1,                             "Get"                                   },  //*defined in Core1.0, obsolete in Core2.0
      { UID_M_SET1,                             "Set"                                   },  //*defined in Core1.0, obsolete in Core2.0
      { UID_M_NEXT,                             "Next"                                  },
      { UID_M_GET_FREESPACE,                    "GetFreeSpace"                          },
      { UID_M_GET_FREEROWS,                     "GetFreeRows"                           },
      { UID_M_DELETE_METHOD,                    "DeleteMethod"                          },
      { UID_M_AUTHENTICATE1,                    "Authenticate"                          },  //*defined in Core1.0, obsolete in Core2.0
      { UID_M_GET_ACL,                          "GetACL"                                },
      { UID_M_ADD_ACE,                          "AddACE"                                },
      { UID_M_REMOVE_ACE,                       "RemoveACE"                             },
      { UID_M_GEN_KEY,                          "GenKey"                                },
      { UID_M_REVERTSP,                         "RevertSP"                              },  // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
      { UID_M_GET_PACKAGE2,                     "GetPackage"                            },  //*defined in Core2.0, to replace Core1.0
      { UID_M_SET_PACKAGE2,                     "SetPackage"                            },  //*defined in Core2.0, to replace Core1.0
      { UID_M_GET2,                             "Get"                                   },  //*defined in Core2.0, to replace Core1.0
      { UID_M_SET2,                             "Set"                                   },  //*defined in Core2.0, to replace Core1.0
      { UID_M_AUTHENTICATE2,                    "Authenticate"                          },  //*defined in Core2.0, to replace Core1.0
      { UID_M_ISSUE_SP,                         "IssueSP"                               },
      { UID_M_REVERT,                           "Revert"                                },  // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
      { UID_M_ACTIVATE,                         "Activate"                              },  // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
      { UID_M_GET_CLOCK,                        "GetClock"                              },
      { UID_M_RESET_CLOCK,                      "ResetClock"                            },
      { UID_M_SET_CLOCKHIGH,                    "SetClockHigh"                          },
      { UID_M_SET_LAGHIGH,                      "SetLagHigh"                            },
      { UID_M_SET_CLOCKLOW,                     "SetClockLow"                           },
      { UID_M_SET_LAGLOW,                       "SetLagLow"                             },
      { UID_M_INCREMENT_COUNTER,                "IncrementCounter"                      },
      { UID_M_RANDOM,                           "Random"                                },
      { UID_M_SALT,                             "Salt"                                  },
      { UID_M_DECRYPT_INIT,                     "DecryptInit"                           },
      { UID_M_DECRYPT,                          "Decrypt"                               },
      { UID_M_DECRYPT_FINALIZE,                 "DecryptFinalize"                       },
      { UID_M_ENCRYPT_INIT,                     "EncryptInit"                           },
      { UID_M_ENCRYPT,                          "Encrypt"                               },
      { UID_M_ENCRYPT_FINALIZE,                 "EncryptFinalize"                       },
      { UID_M_HMAC_INIT,                        "HMACInit"                              },
      { UID_M_HAMC,                             "HMAC"                                  },
      { UID_M_HAMC_FINALIZE,                    "HMACFinalize"                          },
      { UID_M_HASH_INIT,                        "HASHInit"                              },
      { UID_M_HASH,                             "HASH"                                  },
      { UID_M_HASH_FINALIZE,                    "HASHFinalize"                          },
      { UID_M_SIGN,                             "Sign"                                  },
      { UID_M_VERIFY,                           "Verify"                                },
      { UID_M_XOR,                              "XOR"                                   },
      { UID_M_ADD_LOG,                          "AddLog"                                },
      { UID_M_CREATE_LOG,                       "CreateLog"                             },
      { UID_M_CLEAR_LOG,                        "ClearLog"                              },
      { UID_M_FLUSH_LOG,                        "FlushLog"                              },
      { UID_M_GET_PACKAGE1,                     "GetPackage"                            },  //*defined in Core1.0, obsolete in Core2.0
      { UID_M_REACTIVATE,                       "Reactivate"                            },  //*defined in Opal-SSC Fixed ACL (Core2.0)
      { UID_M_SET_PACKAGE1,                     "SetPackage"                            },  //*defined in Core1.0, obsolete in Core2.0
      { UID_M_ERASE,                            "Erase"                                 },  // defined in Ent-SSC & Marble-SSC(MB), marked as "reserved for SSC" in Core2.0

      // Authority UIDs
      { UID_AUT_ANYBODY,                        "Anybody_Authority_UID"                 },
      { UID_AUT_ADMINS,                         "Admins_Authority_UID"                  },
      { UID_AUT_ADMIN1,                         "Admin1_Authority_UID"                  },  //+defined in Opal-SSC & Marble-SSC
      { UID_AUT_USERS,                          "Users_Authority_UID"                   },  // defined in Opal-SSC & Marble-SSC
      { UID_AUT_USER1,                          "User1_Authority_UID"                   },  //+defined in Opal-SSC & Marble-SSC
      { UID_AUT_MAKERS,                         "Makers_Authority_UID"                  },
      { UID_AUT_MAKERSYMK,                      "MakerSymK_Authority_UID"               },
      { UID_AUT_MAKERPUK,                       "MakerPuK_Authority_UID"                },
      { UID_AUT_SID,                            "SID_Authority_UID"                     },
      { UID_AUT_TPER_SIGN,                      "TPerSign_Authority_UID"                },
      { UID_AUT_TPER_EXCH,                      "TPerExch_Authority_UID"                },
      { UID_AUT_ADMIN_EXCH,                     "AdminExch_Authority_UID"               },
      { UID_AUT_ISSUERS,                        "Issuers_Authority_UID"                 },
      { UID_AUT_EDITORS,                        "Editors_Authority_UID"                 },
      { UID_AUT_DELETERS,                       "Deleters_Authority_UID"                },
      { UID_AUT_SERVERS,                        "Servers_Authority_UID"                 },
      { UID_AUT_RESERVE0,                       "Reserve0_Authority_UID"                },
      { UID_AUT_RESERVE1,                       "Reserve1_Authority_UID"                },
      { UID_AUT_RESERVE2,                       "Reserve2_Authority_UID"                },
      { UID_AUT_RESERVE3,                       "Reserve3_Authority_UID"                },
      { UID_AUT_BANDMASTER0,                    "BandMaster0_Authority_UID"             },  //+defined in Ent-SSC & Marble-SSC (MB)
      { UID_AUT_ERASEMASTER,                    "EraseMaster_Authority_UID"             },  // defined in Ent-SSC & Marble-SSC (MB)
      { UID_AUT_MSID,                           "MSID_Authority_UID"                    },
      { UID_AUT_PSID,                           "PSID_Authority_UID"                    },  // (Seagate properprietory)
      { UID_AUT_BANDMASTERS,                    "BandMasters_Authority_UID"             },  // defined in Marble-SSC (MB)

      // Single Row Table Row UIDs
      { UID_SPINFO,                             "SPInfo_Row_UID"                        },
      { UID_TPERINFO_E,                         "TPerInfo_Row_UID"                      },
      { UID_TPERINFO_OM,                        "TPerInfo_Row_UID"                      },
      { UID_LOCKINGINFO,                        "LockingInfo_Row_UID"                   },
      { UID_MBRCONTROL,                         "MBRControl_Row_UID"                    },

      // Multiple Row Table Row UIDs
      { UID_LOCKING_RANGE0,                     "Locking_GlobalRange_UID"               },
      { UID_LOCKING_RANGE1_E,                   "Locking_Range1_UID"                    },  //*+Ent-SSC
      { UID_LOCKING_RANGE1_OM,                  "Locking_Range1_UID"                    },  //*+Opal-SSC & Marble-SSC
      { UID_K_AES_128_RANGE0,                   "K_AES_128_GlobalRange_Key_UID"         },
      { UID_K_AES_128_RANGE1_E,                 "K_AES_128_Range1_Key_UID"              },  //*+Ent-SSC
      { UID_K_AES_128_RANGE1_OM,                "K_AES_128_Range1_Key_UID"              },  //*+Opal-SSC & Marble-SSC
      { UID_K_AES_256_RANGE0,                   "K_AES_256_GlobalRange_Key_UID"         },
      { UID_K_AES_256_RANGE1_E,                 "K_AES_256_Range1_Key_UID"              },  //*+Ent-SSC
      { UID_K_AES_256_RANGE1_OM,                "K_AES_256_Range1_Key_UID"              },  //*+Opal-SSC & Marble-SSC

      // PIN UIDs
      { UID_C_PIN_SID,                          "C_PIN_SID_UID"                         },
      { UID_C_PIN_MSID,                         "C_PIN_MSID_UID"                        },
      { UID_C_PIN_PSID,                         "C_PIN_PSID_UID"                        },  // (Seagate proprietary)
      { UID_C_PIN_BANDMASTER0,                  "C_PIN_BandMaster0_UID"                 },  //+defined in Ent-SSC & Marble-SSC (MB)
      { UID_C_PIN_ERASEMASTER,                  "C_PIN_EraseMaster_UID"                 },  // defined in Ent-SSC & Marble-SSC (MB)
      { UID_C_PIN_ADMIN1,                       "C_PIN_Admin1_UID"                      },  //+defined in Opal-SSC & Marble-SSC (MA)
      { UID_C_PIN_USER1,                        "C_PIN_User1_UID"                       },  //+defined in Opal-SSC & Marble-SSC (MA)

      // ACE UIDs
      { UID_ACE_LOCKING_RANGE0_GET_RANGESTARTTOACTIVEKEY,  "ACE_Locking_GlobalRange_Get_RangeStartToActiveKey_UID" },
      { UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY,  "ACE_Locking_Range1_Get_RangeStartToActiveKey_UID"      }, //+
      { UID_ACE_LOCKING_RANGE0_SET_RDLOCKED,               "ACE_Locking_GlobalRange_Set_RdLocked_UID"              },
      { UID_ACE_LOCKING_RANGE1_SET_RDLOCKED,               "ACE_Locking_Range1_Set_RdLocked_UID"                   }, //+
      { UID_ACE_LOCKING_RANGE0_SET_WRLOCKED,               "ACE_Locking_GlobalRange_Set_WrLocked_UID"              },
      { UID_ACE_LOCKING_RANGE1_SET_WRLOCKED,               "ACE_Locking_Range1_Set_WrLocked_UID"                   }, //+
      { UID_ACE_MBRCONTROL_ADMINS_SET,                     "ACE_MBRControl_Admins_Set_UID"                         },
      { UID_ACE_MBRCONTROL_SET_DONE,                       "ACE_MBRControl_Set_Done_UID"                           },
      { UID_ACE_DATASTORE1_GET_ALL,                        "ACE_DataStore1_Get_All_UID"                            }, //+ *2
      { UID_ACE_DATASTORE1_SET_ALL,                        "ACE_DataStore1_Set_All_UID"                            }, //+ *2

      // Half-UIDs
      { HALFUID_AUTHORITY_REF,                  "HalfUID_Authority_ObjectRef"           },
      { HALFUID_BOOLEAN_ACE,                    "HalfUID_Boolean_ACE"                   },

      // Seagate proprietary UIDs
      { UID__PORTLOCKING_FWDOWNLOAD,            "_PortLocking_FWDownload_UID"           }
   };

   memset( pBuffer, 0, maxLength );

   int totalUIDs = sizeof( uidList ) / sizeof( uidList[0] );
   int ii;

   for( ii=0; ii < totalUIDs; ii++ )
   {
      if( uidList[ii].uid != uid )
         continue;

      if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
         break;

      // Need to handle re-definition of 'name' of the same UID values in different revs of the Core specs
      if( UID_TABLE_ACCESSCONTROL == uid || UID_M_REACTIVATE == uid )
      {
         if( !isDeviceTCGCoreVersion1() )
            ii++; // the first found match is for Core1.0, according to the order of the list items
      }

      break; 
   }

   if( ii < totalUIDs )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "%s", uidList[ii].symbolicName );
#else
      strStream << uidList[ii].symbolicName;
      if ((uint)maxLength >= (strStream.str()).length())
      {
         memcpy(pBuffer, &(strStream.str())[0], (strStream.str()).length());
      }
      else
      {
         memcpy(pBuffer, &(strStream.str())[0], maxLength);
      }
#endif
      return pBuffer;
   }

   // Check if it belongs to the 'indexed' UIDs
   if( uid >= UID_TABLE_DATASTORE1_EM && uid < (UID_TABLE_DATASTORE1_EM + (((tUINT64)MAX_NUMBER_OF_DATASTORETABLES) << 32)) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "DataStore%d_Table_UID", ((uid - UID_TABLE_DATASTORE1_EM) >> 32) +1 );
#else
      strStream << "DataStore" << ((uid - UID_TABLE_DATASTORE1_EM) >> 32) +1 << "_Table_UID";
#endif
   }
   else if( uid >= UID_TABLE_DATASTORE1_OM && uid < (UID_TABLE_DATASTORE1_OM + (((tUINT64)MAX_NUMBER_OF_DATASTORETABLES) << 32)) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "DataStore%d_Table_UID", ((uid - UID_TABLE_DATASTORE1_OM) >> 32) +1 );
#else
      strStream << "DataStore" << ((uid - UID_TABLE_DATASTORE1_OM) >> 32) +1 << "_Table_UID";
#endif
   }
   else if( uid >= UID_TABLETABLE_DATASTORE1_EM && uid < (UID_TABLETABLE_DATASTORE1_EM + MAX_NUMBER_OF_DATASTORETABLES) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "TableTable_DataStore%d_UID", uid - UID_TABLETABLE_DATASTORE1_EM +1 );
#else
      strStream << "TableTable_DataStore" << uid - UID_TABLETABLE_DATASTORE1_EM +1 << "_UID";
#endif
   }
   else if( uid >= UID_TABLETABLE_DATASTORE1_OM && uid < (UID_TABLETABLE_DATASTORE1_OM + MAX_NUMBER_OF_DATASTORETABLES) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "TableTable_DataStore%d_UID", uid - UID_TABLETABLE_DATASTORE1_OM +1 );
#else
      strStream << "TableTable_DataStore" << uid - UID_TABLETABLE_DATASTORE1_OM +1 << "_UID";
#endif
   }
   else if( uid >= UID_AUT_ADMIN1 && uid < (UID_AUT_ADMIN1 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "Admin%d_Authority_UID", uid - UID_AUT_ADMIN1 +1 );
#else
      strStream << "Admin" << uid - UID_AUT_ADMIN1 +1 << "_Authority_UID";
#endif
   }
   else if( uid >= UID_AUT_USER1 && uid < (UID_AUT_USER1 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "User%d_Authority_UID", uid - UID_AUT_USER1 +1 );
#else
      strStream << "User" << uid - UID_AUT_USER1 +1 << "_Authority_UID";
#endif
   }
   else if( uid >= UID_AUT_BANDMASTER0 && uid < (UID_AUT_BANDMASTER0 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "BandMaster%d_Authority_UID", uid - UID_AUT_BANDMASTER0 );
#else
      strStream << "BandMaster" << uid - UID_AUT_BANDMASTER0 << "_Authority_UID";
#endif
   }
   else if( uid >= UID_LOCKING_RANGE1_E && uid < (UID_LOCKING_RANGE1_E + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "Locking_Range%d_UID", uid - UID_LOCKING_RANGE1_E +1 );
#else
      strStream << "Locking_Range" << uid - UID_LOCKING_RANGE1_E +1 << "_UID";
#endif
   }
   else if( uid >= UID_LOCKING_RANGE1_OM && uid < (UID_LOCKING_RANGE1_OM + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "Locking_Range%d_UID", uid - UID_LOCKING_RANGE1_OM +1 );
#else
      strStream << "Locking_Range" << uid - UID_LOCKING_RANGE1_OM +1 << "_UID";
#endif
   }
   else if( uid >= UID_K_AES_128_RANGE1_E && uid < (UID_K_AES_128_RANGE1_E + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "K_AES_128_Range%d_Key_UID", uid - UID_K_AES_128_RANGE1_E +1 );
#else
      strStream << "K_AES_128_Range" << uid - UID_K_AES_128_RANGE1_E +1 << "_Key_UID";
#endif
   }
   else if( uid >= UID_K_AES_128_RANGE1_OM && uid < (UID_K_AES_128_RANGE1_OM + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "K_AES_128_Range%d_Key_UID", uid - UID_K_AES_128_RANGE1_OM +1 );
#else
      strStream << "K_AES_128_Range" << uid - UID_K_AES_128_RANGE1_OM +1 << "_Key_UID";
#endif
   }
   else if( uid >= UID_K_AES_256_RANGE1_E && uid < (UID_K_AES_256_RANGE1_E + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "K_AES_256_Range%d_Key_UID", uid - UID_K_AES_256_RANGE1_E +1 );
#else
      strStream << "K_AES_256_Range" << uid - UID_K_AES_256_RANGE1_E +1 << "_Key_UID";
#endif
   }
   else if( uid >= UID_K_AES_256_RANGE1_OM && uid < (UID_K_AES_256_RANGE1_OM + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "K_AES_256_Range%d_Key_UID", uid - UID_K_AES_256_RANGE1_OM +1 );
#else
      strStream << "K_AES_256_Range" << uid - UID_K_AES_256_RANGE1_OM +1 << "_Key_UID";
#endif
   }
   else if( uid >= UID_C_PIN_BANDMASTER0 && uid < (UID_C_PIN_BANDMASTER0 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "C_PIN_BandMaster%d_UID", uid - UID_C_PIN_BANDMASTER0 );
#else
      strStream << "C_PIN_BandMaster" << uid - UID_C_PIN_BANDMASTER0 << "_UID";
#endif
   }
   else if( uid >= UID_C_PIN_ADMIN1 && uid < (UID_C_PIN_ADMIN1 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "C_PIN_Admin%d_UID", uid - UID_C_PIN_ADMIN1 +1 );
#else
      strStream << "C_PIN_Admin" << uid - UID_C_PIN_ADMIN1 +1 << "_UID";
#endif
   }
   else if( uid >= UID_C_PIN_USER1 && uid < (UID_C_PIN_USER1 + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "C_PIN_User%d_UID", uid - UID_C_PIN_USER1 +1 );
#else
      strStream << "C_PIN_User" << uid - UID_C_PIN_USER1 +1 << "_UID";
#endif
   }
   else if( uid >= UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY && uid < (UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "ACE_Locking_Range%d_Get_RangeStartToActiveKey_UID", uid - UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY +1 );
#else
      strStream << "ACE_Locking_Range" << uid - UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY +1 << "_Get_RangeStartToActiveKey_UID";
#endif
   }
   else if( uid >= UID_ACE_LOCKING_RANGE1_SET_RDLOCKED && uid < (UID_ACE_LOCKING_RANGE1_SET_RDLOCKED + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "ACE_Locking_Range%d_Set_RdLocked_UID", uid - UID_ACE_LOCKING_RANGE1_SET_RDLOCKED +1 );
#else
      strStream << "ACE_Locking_Range" << uid - UID_ACE_LOCKING_RANGE1_SET_RDLOCKED +1 << "_Set_RdLocked_UID";
#endif
   }
   else if( uid >= UID_ACE_LOCKING_RANGE1_SET_WRLOCKED && uid < (UID_ACE_LOCKING_RANGE1_SET_WRLOCKED + MAX_NUMBER_OF_BANDS) )
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "ACE_Locking_Range%d_Set_WrLocked_UID", uid - UID_ACE_LOCKING_RANGE1_SET_WRLOCKED +1 );
#else
      strStream << "ACE_Locking_Range" << uid - UID_ACE_LOCKING_RANGE1_SET_WRLOCKED +1 << "_Set_WrLocked_UID";
#endif
   }
   else if( uid >= UID_ACE_DATASTORE1_GET_ALL && uid < (UID_ACE_DATASTORE1_SET_ALL + (MAX_NUMBER_OF_DATASTORETABLES - 1) *2 ) )
   {
      if( (uid - UID_ACE_DATASTORE1_GET_ALL) % 2 )
      {
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, maxLength, "ACE_DataStore%d_Set_All_UID", (uid - UID_ACE_DATASTORE1_SET_ALL)/2 +1 );
#else
         strStream << "ACE_DataStore" << ((uid - UID_ACE_DATASTORE1_SET_ALL)/2) +1 << "_Set_All_UID";
#endif
      }
      else
      {
#if defined(_WIN32) // nvn20110719
         sprintf_s( pBuffer, maxLength, "ACE_DataStore%d_Get_All_UID", (uid - UID_ACE_DATASTORE1_GET_ALL)/2 +1 );
#else
         strStream << "ACE_DataStore" << ((uid - UID_ACE_DATASTORE1_GET_ALL)/2) +1 << "_Set_All_UID";
#endif
      }
   }
   else
   {
#if defined(_WIN32) // nvn20110719
      sprintf_s( pBuffer, maxLength, "UID(%016I64X)", uid );
#else
      strStream << "UID(" << uid << ")";
#endif
   }

#if !defined(_WIN32) // nvn20110719
   if ((uint)maxLength >= (strStream.str()).length())
   {
      memcpy( pBuffer, &(strStream.str())[0], (strStream.str()).length() );
   }
   else
   {
      memcpy( pBuffer, &(strStream.str())[0], maxLength );
   }
#endif

   return pBuffer;
} // mapUIDToName

//=================================================================================
/// \brief Translate a ASCII string of an authority or pin name to its UID.
///
/// \param name  [in]   The name of an authority or pin to be translated.
/// \param isPin [in]   True for pin mapping or false for authority mapping.
///
/// \return UID value for the matched authority or pin name.
//=================================================================================
TCG_UID CTcgCoreInterface::mapAuthorityOrPinNameToUID( char *name, bool isPin )
{
   TCG_UID uid = UID_NULL;
   int seqNo = 0;

   if( NULL == name )
      return uid;

   if( _strnicmp( name, "SID", sizeof("SID")-1 ) == 0 )
   {
      uid = ( isPin ? UID_C_PIN_SID : UID_AUT_SID );
   }
   else if( _strnicmp( name, "MSID", sizeof("MSID")-1 ) == 0 )
   {
      uid = ( isPin ? UID_C_PIN_MSID : UID_AUT_MSID );
   }
   else if( _strnicmp( name, "PSID", sizeof("PSID")-1 ) == 0 )
   {
      uid = ( isPin ? UID_C_PIN_PSID : UID_AUT_PSID );
   }
   else if( _strnicmp( name, "EraseMaster", sizeof("EraseMaster")-1 ) == 0 )
   {
      uid = ( isPin ? UID_C_PIN_ERASEMASTER : UID_AUT_ERASEMASTER );
   }
   else if( _strnicmp( name, "BandMaster", sizeof("BandMaster")-1 ) == 0 )
   {
      seqNo = atoi( name + sizeof("BandMaster") -1 );
	  uid = ( isPin ? UID_C_PIN_BANDMASTER0 : UID_AUT_BANDMASTER0 ) + seqNo; // e.g., "BandMaster0"
   }
   else if( _strnicmp( name, "Admin", sizeof("Admin")-1 ) == 0 )
   {
      seqNo = atoi( name + sizeof("Admin") -1 );
	  uid = ( isPin ? UID_C_PIN_ADMIN1 : UID_AUT_ADMIN1 ) + seqNo -1; // e.g., "Admin1"
   }
   else if( _strnicmp( name, "User", sizeof("User")-1 ) == 0 )
   {
      seqNo = atoi( name + sizeof("User") -1 );
	  uid = ( isPin ? UID_C_PIN_USER1 : UID_AUT_USER1 ) + seqNo -1; // e.g., "User1"
   }
   else if( _strnicmp( name, "Anybody", sizeof("Anybody")-1 ) == 0 )
   {
      uid = ( isPin ? UID_NULL : UID_AUT_ANYBODY );
   }
   else if( _strnicmp( name, "Makers", sizeof("Makers")-1 ) == 0 )
   {
      uid = ( isPin ? UID_NULL : UID_AUT_MAKERS );
   }

   return uid;
} // mapAuthorityOrPinNameToUID

//=================================================================================
/// \brief Returns a string description for a TCG status byte.
///
/// \param status [in]   Status byte to be translated.
///
/// \return String description of given status byte.
//=================================================================================
_tstring CTcgCoreInterface::tcgStatusToString( const TCG_STATUS status )
{
   switch ( status )
   {
      case TS_SUCCESS:
         return TXT("TCG__SUCCESS");

      case TS_NOT_AUTHORIZED:
         return TXT("TCG__NOT_AUTHORIZED");

      case TS_SP_READ_ONLY:
         return TXT("TCG__SP_READ_ONLY");

      case TS_SP_BUSY:
         return TXT("TCG__SP_BUSY");

      case TS_SP_FAILED:
         return TXT("TCG__SP_FAILED");

      case TS_SP_DISABLED:
         return TXT("TCG__SP_DISABLED");

      case TS_SP_FROZEN:
         return TXT("TCG__SP_FROZEN");

      case TS_NO_SESSION_AVAILABLE:
         return TXT("TCG__NO_SESSION_AVAILABLE");

      case TS_INDEX_CONFLICT:
         return TXT("TCG__INDEX_CONFLICT");

      case TS_INSUFFICIENT_SPACE:
         return TXT("TCG__INSUFFICIENT_SPACE");

      case TS_INSUFFICIENT_ROWS:
         return TXT("TCG__INSUFFICIENT_ROWS");

      case TS_INVALID_COMMAND:
         return TXT("TCG__INVALID_COMMAND");

      case TS_INVALID_PARAMETER:
         return TXT("TCG__INVALID_PARAMETER");

      case TS_INVALID_REFERENCE:
         return TXT("TCG__INVALID_REFERENCE");

      case TS_INVALID_SECMSG_PROPERTIES:
         return TXT("TCG__INVALID_SECMSG_PROPERTIES");

      case TS_TPER_MALFUNCTION:
         return TXT("TCG__TPER_MALFUNCTION");

      case TS_TRANSACTION_FAILURE:
         return TXT("TCG__TRANSACTION_FAILURE");

      case TS_RESPONSE_OVERFLOW:
         return TXT("TCG__RESPONSE_OVERFLOW");

      case TS_AUTHORITY_LOCKED_OUT:
         return TXT("TCG__AUTHORITY_LOCKED_OUT");

      case TS_FAIL:
         return TXT("TCG__FAIL");

      case TS_DTL_ERROR:
         return TXT("TCG__DTL_ERROR");

      default:
         return TXT("TCG__Unknown_status");

   } // switch
} // tcgStatusToString

//=================================================================================
/// \brief Returns a string description for a DTL/TCG error code.
///
/// \param status [in]  Status code to be translated.
///
/// \return String description of given status code.
//=================================================================================
_tstring CTcgCoreInterface::dtlErrorToString( const dta::DTA_ERROR status )
{
   if( 0 == status.Error )
      return TXT("SUCCESS");

   // Only 'eDtaCategoryGeneric' and 'eDtaCategoryProtocol' are what we really care about.
   switch( status.Info.Category )
   {
      case eDtaCategoryGeneric:
         switch( status.Info.Detail )
         {
            case eGenericWarning:
               return TXT("DTL__GENERIC_WARNING(eg. Failed authentication or empty Data Return)");

            case eGenericFatalError:
               return TXT("DTL__GENERIC_FATAL");

            case eGenericTimeoutError:
               return TXT("DTL__GENERIC_TIMEOUT");

            case eGenericDeviceUnavailable:
               return TXT("DTL__GENERIC_DEVICE_UNAVAILABLE");

            case eGenericInvalidParameter:
               return TXT("DTL__GENERIC_INVALID_PARAMETER");

            case eGenericNotImplemented:
               return TXT("DTL__GENERIC_NOT_IMPLEMENTED");

            case eGenericInvalidIdentifier:
               return TXT("DTL__GENERIC_INVALID_ID");

            case eGenericAttributeReadOnly:
               return TXT("DTL__GENERIC_READONLY");

            case eGenericMemoryError:
               return TXT("DTL__GENERIC_MEMORY");
 
            default:
               return TXT("DTL__GENERIC_ERROR");
         }

      case eDtaCategoryProtocol:
         return tcgStatusToString( (TCG_STATUS) status.Info.Detail );

      case eDtaCategoryOS:
      case eDtaCategoryDirect:
      case eDtaCategoryClient:
      case eDtaCategoryService:
      default:
         return TXT("DTL__ERROR");
   }
} // dtlErrorToString

//=================================================================================
/// \brief Returns the number of bytes of maximium user data blocks per a Get/Set.
///
/// \return Number of bytes of the maximium user data blocks per a Get/Set.
//=================================================================================
tUINT32 CTcgCoreInterface::getMaxUserDataLength()
{
   if( m_packetManager.getMaxComPacketSize() )
      return ((m_packetManager.getMaxComPacketSize() - 512) / 512 ) * 512;

   else if( m_packetManager.getMaxPacketSize() )
      return ((m_packetManager.getMaxPacketSize() + 20 - 512) / 512 ) * 512;

   return 512;
} // getMaxUserDataLength

//=================================================================================
/// \brief Attempt to set and use ATA DMA security commands for ATA devices if supported.
///
/// \return none.
//=================================================================================
void CTcgCoreInterface::attemptUsingDmaIF4ATA()
{
   _tstring attrValue;
   m_session->GetAttribute( TXT("Transport" ), attrValue );
   if( attrValue == TXT("ATA") )
   {
      ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
      if ( pATA )
      {
         try
         {
#if defined(_WIN32) // nvntry - skip try DMA operation for non windows OS

            // Current Megadolon drives have a bug in DMA operation and will hang. The drive    - jls 20120801
            // itself won't respond to other commands after this hang, so don't do it.          - jls 20120801
            // HACK HACK HACK - for testing, disable the following command!!
            pATA->SetTrustedOpcodes( ata::evTrustedSendDMA, ata::evTrustedReceiveDMA );
#endif
            securityIFRecv( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY, SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST );
            //m_responseBuffer.resize( m_blockSize * 1 );
            //m_session->SecurityDataFromDevice( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY, SWAPWORD(SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST), m_responseBuffer );
         }
         catch( const dta::DTA_ERROR& )
         {
            pATA->SetTrustedOpcodes( ata::evTrustedSend, ata::evTrustedReceive );
         }
      }
   }
} // attemptUsingDmaIF4ATA

//=================================================================================
/// \brief Encode an unsigned interger list NamedValue token stream for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [OUT] Caller provided destination buffer to keep the built NamedValue token.
/// \param pData              [IN]  Pointer to a type of unsigned interger upto 8-bytes in size to be encoded size-fit. 
/// \param numDataItems       [IN]  Number of the items of the integer data for the list.
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
///
/// \return Pointer to the buffer location following this token.
//=================================================================================
template <typename T>
tUINT8 * CTcgCoreInterface::encodeNamedValue_IntgerList( tUINT8 * pTokenStreamBuffer, T * pData, tUINT32 numDataItems, const char *nameCS1, tUINT64 nameCS2 )
{
   if( isDeviceTCGCoreVersion1() && NULL == nameCS1 ) // Non-empty name must be submitted to build CS1.0 token
      return pTokenStreamBuffer;

   pTokenStreamBuffer = encodeNamedValueName( pTokenStreamBuffer, nameCS1, nameCS2 );

   pTokenStreamBuffer = m_tokenProcessor.buildStartList( pTokenStreamBuffer );
   for( tUINT32 ii=0; ii<numDataItems; ii++ )
      pTokenStreamBuffer = m_tokenProcessor.buildIntAtom( pTokenStreamBuffer, (tUINT64) pData[ii] );
   
   pTokenStreamBuffer = m_tokenProcessor.buildEndList( pTokenStreamBuffer );
   pTokenStreamBuffer = m_tokenProcessor.buildEndName( pTokenStreamBuffer );

   return pTokenStreamBuffer;
} // encodeNamedValue_IntgerList

//=================================================================================
/// \brief Encode an unsigned interger NamedValue token stream for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [OUT] Caller provided destination buffer to keep the built NamedValue token.
/// \param data               [IN]  Unsigned interger upto 8-bytes in size to be encoded size-fit. 
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
///
/// \return Pointer to the buffer location following this token.
//=================================================================================
tUINT8 * CTcgCoreInterface::encodeNamedValue_Integer( tUINT8 * pTokenStreamBuffer, tUINT64 data, const char *nameCS1, tUINT64 nameCS2 )
{
   if( isDeviceTCGCoreVersion1() && NULL != nameCS1 )
      return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, (tUINT8 *)nameCS1, (tUINT32)strlen(nameCS1), data, -1, false );

   if( !isDeviceTCGCoreVersion1() )
      return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, nameCS2, data, -1, false );

   return pTokenStreamBuffer;
} // encodeNamedValue_Integer

//=================================================================================
/// \brief Encode an UID or HalfUID NamedValue token stream for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [OUT] Caller provided destination buffer to keep the built NamedValue token.
/// \param data               [IN]  UID or HalfUID value to be encoded. 
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
/// \param halfUID            [IN]  Boolean set true to encode HalfUID
///
/// \return Pointer to the buffer location following this token.
//=================================================================================
tUINT8 * CTcgCoreInterface::encodeNamedValue_UID( tUINT8 * pTokenStreamBuffer, TCG_UID data, const char *nameCS1, tUINT64 nameCS2, bool halfUID )
{
   if( isDeviceTCGCoreVersion1() && NULL != nameCS1 )
	   return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, (tUINT8 *)nameCS1, (tUINT32)strlen(nameCS1), data, (halfUID ? 4 : 8), true );

   if( !isDeviceTCGCoreVersion1() )
      return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, nameCS2, data, (halfUID ? 4 : 8), true );

   return pTokenStreamBuffer;
} // encodeNamedValue_UID

//=================================================================================
/// \brief Encode a Byte-flow NamedValue token stream for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [OUT] Caller provided destination buffer to keep the built NamedValue token.
/// \param pData              [IN]  Pointer to a byte-array to be encoded. 
/// \param length             [IN]  Size of byte-array
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
///
/// \return Pointer to the buffer location following this token.
//=================================================================================
tUINT8 * CTcgCoreInterface::encodeNamedValue_Bytes( tUINT8 * pTokenStreamBuffer, tUINT8 * pData, tUINT32 length, const char *nameCS1, tUINT64 nameCS2 )
{
   if( isDeviceTCGCoreVersion1() && NULL != nameCS1 )
	   return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, (tUINT8 *)nameCS1, (tUINT32)strlen(nameCS1), pData, length, false );

   if( !isDeviceTCGCoreVersion1() )
      return m_tokenProcessor.buildNamedValueToken( pTokenStreamBuffer, nameCS2, pData, length, false );

   return pTokenStreamBuffer;
} // encodeNamedValue_Bytes

//=================================================================================
/// \brief Encode the 'Name' part of a NamedValue token for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [OUT] Caller provided destination buffer to keep the built NamedValue token's Name part.
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
///
/// \return Pointer to the buffer location following this token part for building its Data part subsequently.
//=================================================================================
tUINT8 * CTcgCoreInterface::encodeNamedValueName( tUINT8 * pTokenStreamBuffer, const char *nameCS1, tUINT64 nameCS2 )
{
   if( isDeviceTCGCoreVersion1() && NULL != nameCS1 )
   {
      pTokenStreamBuffer = m_tokenProcessor.buildStartName( pTokenStreamBuffer );
      pTokenStreamBuffer = m_tokenProcessor.buildNamedValueTokenName( pTokenStreamBuffer, (tUINT8 *)nameCS1, (tUINT32)strlen(nameCS1) );
   }

   if( !isDeviceTCGCoreVersion1() )
   {
      pTokenStreamBuffer = m_tokenProcessor.buildStartName( pTokenStreamBuffer );
      pTokenStreamBuffer = m_tokenProcessor.buildNamedValueTokenName( pTokenStreamBuffer, nameCS2 );
   }

   return pTokenStreamBuffer;
} // encodeNamedValueName

//=================================================================================
/// \brief Decode and return an integer list of data of a NamedValue token for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [IN/OUT] Caller provided destination buffer holding the NamedValue token upon entry, and pointing to the next token stream location after this upon return if found, and 'pTokenStreamBuffer' remains unchanged if not found.
/// \param bufferLength       [IN]     Length of the token stream buffer.
/// \param pData              [OUT]    Buffer to receive the type of integers retrieved.
/// \param capacityDataItems  [IN]     Capacity, number of data items of the 'pData' buffer for receiving data.
/// \param nameCS1            [IN]     Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]     Interger of the name for CS2.0.
///
/// \return Actuall size of data received.
//=================================================================================
template <typename T>
tUINT32 CTcgCoreInterface::decodeNamedValue_IntgerList( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, T * pData, tUINT32 capacityDataItems, const char *nameCS1, tUINT64 nameCS2 )
{
   tUINT32 numItems = 0;
   tUINT8 * p = decodeNamedValueName( pTokenStreamBuffer, bufferLength, nameCS1, nameCS2 );
   if( NULL != p )
   {
      if( m_tokenProcessor.isListToken(*p) )
      {
         numItems = m_tokenProcessor.numberOfListItems( p++ );

         if( numItems > capacityDataItems )
            throw dta::Error(eGenericInvalidIdentifier);

         tUINT64 tmp;
         for( tUINT32 ii=0; ii<numItems; ii++ )
         {
            p = m_tokenProcessor.getAtomData( p, &tmp );
            pData[ii] = (T) tmp;
         }

         pTokenStreamBuffer = p + 2; //EL, EN
      }
      else
         throw dta::Error(eGenericInvalidIdentifier);
   }

   return numItems;
} // decodeNamedValue_IntgerList

//=================================================================================
/// \brief Decode and return an unsigned interger NamedValue token data for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [IN/OUT] Caller provided destination buffer holding the NamedValue token upon entry, and pointing to the next token stream location after this upon return if found, and 'pTokenStreamBuffer' remains unchanged if not found.
/// \param bufferLength       [IN]     Length of the token stream buffer.
/// \param nameCS1            [IN]     Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]     Interger of the name for CS2.0.
///
/// \return An unsigned integer value of the NameValue token, 
///  the buffer location following this token is returned in 'pTokenStreamBuffer'. 
//=================================================================================
tUINT64 CTcgCoreInterface::decodeNamedValue_Integer( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, const char *nameCS1, tUINT64 nameCS2 )
{
   tUINT64 data = 0;
   tUINT8 * p = decodeNamedValueName( pTokenStreamBuffer, bufferLength, nameCS1, nameCS2 );

   if( NULL != p )
   {
      p = m_tokenProcessor.getAtomData( p, &data );
      pTokenStreamBuffer = ++p; // EN
   }

   return data;
} // decodeNamedValue_Integer

//=================================================================================
/// \brief Decode and return a byte flow of data of a NamedValue token for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [IN/OUT] Caller provided destination buffer holding the NamedValue token upon entry, and pointing to the next token stream location after this upon return if found, and 'pTokenStreamBuffer' remains unchanged if not found.
/// \param bufferLength       [IN]     Length of the token stream buffer.
/// \param pData              [OUT]    Buffer to receive the bytes retrieved.
/// \param dataLength         [IN]     Capacity size of the 'pData' buffer for receiving data.
/// \param nameCS1            [IN]     Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]     Interger of the name for CS2.0.
///
/// \return Actuall size of data received.
//=================================================================================
tUINT32 CTcgCoreInterface::decodeNamedValue_Bytes( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, tUINT8 * pData, tUINT32 dataLength, const char *nameCS1, tUINT64 nameCS2 )
{
   tUINT64 len = 0;
   tUINT8 * p = decodeNamedValueName( pTokenStreamBuffer, bufferLength, nameCS1, nameCS2 );

   if( NULL != p )
   {
      m_tokenProcessor.getAtomDataPointer( p, &p, &len );

      if( len <= dataLength )
      {
         memcpy( pData, p, (size_t) len );
         pTokenStreamBuffer = p + len + 1; // EN
         return (tINT32) len;
      }
      else
      {
         // Too long data, something wrong happened
         throw dta::Error(eGenericInvalidIdentifier);
      }
   }
   
   return (tINT32) len;
} // decodeNamedValue_Bytes

//=================================================================================
/// \brief Decode and return the location of the value part of a NamedValue token specified by its name for the current CoreSpec 1.0 or 2.0.
///
/// \param pTokenStreamBuffer [IN]  Caller provided destination buffer holding the NamedValue token upon entry.
/// \param bufferLength       [IN]  Length of the token stream buffer.
/// \param nameCS1            [IN]  Zero teminated ASCII string of the name for CS1.0.
/// \param nameCS2            [IN]  Interger of the name for CS2.0.
///
/// \return A pointer of location of the value part of the NameValue token. NULL if not found.
//=================================================================================
tUINT8 * CTcgCoreInterface::decodeNamedValueName( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, const char *nameCS1, tUINT64 nameCS2 )
{
   tUINT8 * p = pTokenStreamBuffer;

   if( isDeviceTCGCoreVersion1() && NULL != nameCS1 )
      p = m_tokenProcessor.retrieveNamedDataFromStream( p, bufferLength, (tUINT8 *)nameCS1, (tUINT32)strlen(nameCS1) );
   else if( !isDeviceTCGCoreVersion1() )
      p = m_tokenProcessor.retrieveNamedDataFromStream( p, bufferLength, nameCS2 );
   else
      p = NULL;

   return p;
} // decodeNamedValueName

#ifdef __TCGSILO
//=================================================================================
void CTcgCoreInterface::searchForSilo()
{
   // Null out the current ACT and TCG Silo variables
   m_ACT = NULL;
   m_TCGSilo = NULL;
   m_hasSilo = false;
   
   try
   {
      tUINT16 numberIDs;
      dta::tBytes IDs;
      getSupportedProtocolIDs( numberIDs, IDs );

      // Now parse the list of protocols.
      for (unsigned int i = 0; i < numberIDs; i++)
      {
         if (IDs[i] == eSPIEEE1667)
         {
            m_ACT = new dti::CIEEE1667Interface(m_session);
            
            // See if it has a TCG Silo
            if (m_ACT->getSiloIndex(eSiloTCG) != 0xFF)
            {
               m_TCGSilo = new dti::CTCGSilo(m_ACT);
               m_hasSilo = true;
            }
            break;
         } // if
      } // for

      if( useSilo() )
         refreshLevel0DiscoveryData();
   } // try
   catch(...)
   {
      // If we get an error, no worries, it just doesn't support 1667 silo
   }
} // searchForSilo
#endif

//=================================================================================
unsigned int CTcgCoreInterface::getPollSleepTime() const
{
   return m_sleepTime;
}

//=================================================================================
unsigned int CTcgCoreInterface::setPollSleepTime(const unsigned int t) 
{
   const unsigned int oldSleepTime = m_sleepTime;

   if((t >= MIN_SLEEP_TIME) && (t <= MAX_SLEEP_TIME)) {
      m_sleepTime = t;
   }

   return oldSleepTime;
}

