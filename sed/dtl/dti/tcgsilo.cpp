/*! \file tcgsilo.cpp
    \brief Basic implementations of IEEE-1667 TCG Silo functions.

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
#include "tcgsilo.hpp"
#include "TCG/PacketManager.hpp"
#include <time.h>
using namespace dti;

//=======================================================================================
// CTCGSilo
//=======================================================================================
CTCGSilo::CTCGSilo(CIEEE1667Interface* device)
                              : CSiloBase(eSiloTCG, device), m_ComID(0), m_MaxPOutSize(0)
{

} // CTCGSilo


//=======================================================================================
// getSiloCapabilites
//=======================================================================================
IEEE1667_STATUS CTCGSilo::getSiloCapabilites(dta::tBytes &level0DiscoveryData, tUINT16 *pComID, tUINT32 *pMaxPOutSize)
{
   M_SiloTry()
   {
      // Create the buffers
      dta::tBytes recvPayload(512);
      dta::tBytes sendPayload;

      // Set up the buffer
      CIEEE1667Interface::add1667CommandHeader(sendPayload);

      // Now send it out
      m_device->sendCommand(m_siloIndex, eTCGGetSiloCapabilities, sendPayload, recvPayload);
      if( recvPayload.size() < sizeof(GSCResponsePayloadHdr) )
         throw dta::Error(dta::eGenericInvalidParameter);

      // Parse and return the response
      GSCResponsePayloadHdr* gscResponsePayload = (GSCResponsePayloadHdr*)&recvPayload[0];
      m_ComID = m_swapper.NetToHost(gscResponsePayload->ComID);
      m_MaxPOutSize = m_swapper.NetToHost(gscResponsePayload->maximum_P_OUT_TransferSize);
      if( NULL != pComID )
         *pComID = m_ComID;
      if( NULL != pMaxPOutSize )
         *pMaxPOutSize = m_MaxPOutSize;

      if( m_swapper.NetToHost(gscResponsePayload->tcgLevel0DiscoveryDataLength) + sizeof(GSCResponsePayloadHdr) > recvPayload.size() )
         throw dta::Error(dta::eGenericInvalidParameter);

      level0DiscoveryData.resize(m_swapper.NetToHost(gscResponsePayload->tcgLevel0DiscoveryDataLength));
      memcpy(&level0DiscoveryData[0], ((tUINT8*)gscResponsePayload) + sizeof(GSCResponsePayloadHdr), level0DiscoveryData.size());
   }
   M_SiloCatch()
} // getSiloCapabilites

//=======================================================================================
// transfer
//=======================================================================================
IEEE1667_STATUS CTCGSilo::transfer(const dta::tBytes &tcgComPacketPOut, dta::tBytes &tcgComPacketPIn)
{
   M_SiloTry()
   {
      if( tcgComPacketPOut.size() < sizeof(TCG_COM_PACKET_HEADER) )
         throw dta::Error(dta::eGenericInvalidParameter);

      // Create the buffers
      dta::tBytes recvPayload( tcgComPacketPIn.size() );
      dta::tBytes sendPayload( tcgComPacketPOut.size() + sizeof(TransferCommandPayloadHdr) );

      // Set up the buffer
      TransferCommandPayloadHdr* transferCommandPayload = (TransferCommandPayloadHdr*)&sendPayload[0];

      transferCommandPayload->header.payloadContentLength = m_swapper.HostToNet(tUINT32(sendPayload.size()));
      memset( &transferCommandPayload->header.reserved[0], 0, sizeof(transferCommandPayload->header.reserved) );

      memset( &transferCommandPayload->reserved[0], 0, sizeof(transferCommandPayload->reserved) );

      transferCommandPayload->tcgComPacketLength = m_swapper.HostToNet(tUINT32(tcgComPacketPOut.size()));

      TCG_COM_PACKET_HEADER* pTCGComPacketHeader = (TCG_COM_PACKET_HEADER*)(&sendPayload[0] + sizeof(TransferCommandPayloadHdr));
      memcpy( pTCGComPacketHeader, &tcgComPacketPOut[0], tcgComPacketPOut.size() );

      // Make sure using the Silo's ComID, regardless of whatever value passed from original TCG ComPacket
      if( 0 != m_ComID )
         pTCGComPacketHeader->extendedComID = m_swapper.HostToNet( (((tUINT32) m_ComID) << 16) & 0xFFFF0000 );


      // Now send it out, adhering to the P22 R14 spec
      m_device->sendCommand(m_siloIndex, eTCGTransfer, sendPayload, recvPayload);
      if( recvPayload.size() < sizeof(TransferResponsePayloadHdr) )
         throw dta::Error(dta::eGenericInvalidParameter);

      TransferResponsePayloadHdr* pTransferResponsePayload = (TransferResponsePayloadHdr*)&recvPayload[0];
      if( sizeof(TransferResponsePayloadHdr) + m_swapper.NetToHost(pTransferResponsePayload->tcgComPacketLength) > recvPayload.size() )
         throw dta::Error(dta::eGenericInvalidParameter);

      tcgComPacketPIn.resize( recvPayload.size() - sizeof(TransferResponsePayloadHdr) );
      if( tcgComPacketPIn.size() > 0 )
         memcpy( &tcgComPacketPIn[0], (tUINT8*) &recvPayload[0] + sizeof(TransferResponsePayloadHdr), tcgComPacketPIn.size() );

   } // try
   M_SiloCatch()
} // transfer

//=======================================================================================
// getXferResults
//=======================================================================================
IEEE1667_STATUS CTCGSilo::getXferResults(dta::tBytes &tcgComPacket)
{
   M_SiloTry()
   {
      // Create the buffers
      dta::tBytes recvPayload( tcgComPacket.size() );
      dta::tBytes sendPayload;

      // Set up the buffer
      CIEEE1667Interface::add1667CommandHeader(sendPayload);

      // Now send it out
      m_device->sendCommand(m_siloIndex, eTCGGetTransferResults, sendPayload, recvPayload);
      if( recvPayload.size() < sizeof(GetXferResultsResponsePayloadHdr) )
         throw dta::Error(dta::eGenericInvalidParameter);

      GetXferResultsResponsePayloadHdr* pTransferResponsePayload = (GetXferResultsResponsePayloadHdr*)&recvPayload[0];
      if( sizeof(GetXferResultsResponsePayloadHdr) + m_swapper.NetToHost(pTransferResponsePayload->tcgComPacketLength) > recvPayload.size() )
         throw dta::Error(dta::eGenericInvalidParameter);

      tcgComPacket.resize( recvPayload.size() - sizeof(GetXferResultsResponsePayloadHdr) );
      if( tcgComPacket.size() > 0 )
         memcpy( &tcgComPacket[0], (tUINT8*) &recvPayload[0] + sizeof(GetXferResultsResponsePayloadHdr), tcgComPacket.size() );

   } // try
   M_SiloCatch()

} // getXferResults

//=======================================================================================
// reset
//=======================================================================================
IEEE1667_STATUS CTCGSilo::reset()
{
   M_SiloTry()
   {
      // Create the buffers
      dta::tBytes recvPayload(sizeof(ResetResponsePayload));
      dta::tBytes sendPayload;

      // Set up the buffer
      CIEEE1667Interface::add1667CommandHeader(sendPayload);

      // Now send it out
      m_device->sendCommand(m_siloIndex, eTCGReset, sendPayload, recvPayload);
   }
   M_SiloCatch()
} // reset

//=======================================================================================
// executeTCGComPacketCmd
//=======================================================================================
IEEE1667_STATUS CTCGSilo::executeTCGComPacketCmd(const dta::tBytes &tcgComPacketPOut, dta::tBytes &tcgComPacketPIn, const tUINT32 timeout, const tUINT32 pollingInterval)
{
   M_SiloTry()
   {
      tUINT32 startTime = clock(); // Start the timer
      transfer( tcgComPacketPOut, tcgComPacketPIn );

      while( true )
      {
         TCG_COM_PACKET_HEADER* pComPacketHeader = (TCG_COM_PACKET_HEADER*) &tcgComPacketPIn[0];

         if( m_swapper.NetToHost( pComPacketHeader->outstandingData ) == 0 )
         {
            break; // data ready/completes
         }
         else if( m_swapper.NetToHost( pComPacketHeader->outstandingData ) == 1 ) // device is still processing
         {
            if( clock() - startTime < (tUINT32)(timeout/1000.0 * CLOCKS_PER_SEC) )
               sleep( CLOCKS_PER_SEC * pollingInterval / 1000 );
            else
               throw dta::Error(dta::eGenericTimeoutError);
         }
         else // Not big enough receiving buffer??
         {
            if( 0 == m_swapper.NetToHost( pComPacketHeader->length ) && m_swapper.NetToHost( pComPacketHeader->outstandingData ) == m_swapper.NetToHost( pComPacketHeader->minTransfer ) )
            {
               tcgComPacketPIn.resize( m_swapper.NetToHost( pComPacketHeader->outstandingData ) );
               memset( &tcgComPacketPIn[0], 0, tcgComPacketPIn.size() );
            }
            else
            {
               throw dta::Error(dta::eGenericInvalidIdentifier);
            }
         }

         getXferResults( tcgComPacketPIn );
      } // while
   } // try
   M_SiloCatch()
} // executeTCGComPacketCmd


//=======================================================================================
// sleep
//=======================================================================================
void CTCGSilo::sleep( clock_t wait )
{
   clock_t current = clock();
   clock_t goal = current + wait;

   while( -1 != current && current < goal )
      current = clock();

} // sleep
