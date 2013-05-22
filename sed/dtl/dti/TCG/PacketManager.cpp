/*! \file PacketManager.cpp
    \brief Class definition for handling TCG Packets.

    This file contains the class definition for TCG ComPacket/Packet/SubPacket structures.
    It is a C++ specific interface.
    
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

//=================================
// Include files
//=================================
#include "PacketManager.hpp"
#include <dtlcrypto.h>

using namespace dta;
using namespace dti;

//=================================================================================
/// \brief Setup the ComBuffern to a caller's In/Out buffer, and set headers and their pointers.
///
/// \param comBuffer   [IN]  A reference to the caller's ComPacketBuffer.
/// \param dataEmpty   [IN]  A flag indicating the initialization request for the beginning header-sections,
///                          true to initialize headers(for a command packet), and false no (for response).
///
/// \pre Caller provides a large enough fixed sized storage for the buffer, and
///  m_extendedComID, m_TPerSN, and m_HostSN, m_seqNumber are all set.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the location of the first SubPacket payload following ComPacket/Packet/SubPacket headers.
//=================================================================================
dta::tByte* CTcgPacketManager::setComBuffer( dta::tBytes & comBuffer, bool dataEmpty )
{
   if( dataEmpty && ( comBuffer.size() < MIN_SEND_RECV_LEN ) )
   {
      throw dta::Error(eGenericMemoryError); //TXT( "ComPacket buffer is too small" );
   }

   if( dataEmpty )
      memset( &comBuffer[0], 0, comBuffer.size() );

   m_pComPacketHeader = (PTCG_COM_PACKET_HEADER) &comBuffer[0];
   m_pPacketHeader = (PTCG_PACKET_HEADER) ((dta::tByte*) m_pComPacketHeader + sizeof(TCG_COM_PACKET_HEADER));
   m_pSubPacketHeader = (PTCG_SUB_PACKET_HEADER) ((dta::tByte*) m_pPacketHeader + sizeof(TCG_PACKET_HEADER));

   if( dataEmpty ) // for Command, set the initial headers (first ComPktHdr/PktHdr/SubPktHdr).
   {
      //memset( &comBuffer[0], 0, comBuffer.size() ); // optional, for padding zeroes

      m_pComPacketHeader->reserved = 0;
      m_pComPacketHeader->extendedComID = m_swapper.HostToNet( m_extendedComID );
      m_pComPacketHeader->outstandingData = 0;
      m_pComPacketHeader->minTransfer = 0;
      m_pComPacketHeader->length = 0;

      m_pPacketHeader->TPerSN = m_swapper.HostToNet( m_TPerSN );
      m_pPacketHeader->HostSN = m_swapper.HostToNet( m_HostSN );
      m_pPacketHeader->seqNumber = m_swapper.HostToNet( m_seqNumber );
      m_pPacketHeader->reserved = 0;
      m_pPacketHeader->ackType = 0;
      m_pPacketHeader->acknowledgement = 0;
      m_pPacketHeader->length = 0;

      m_pSubPacketHeader->reserved1 = 0;
      m_pSubPacketHeader->reserved2 = 0;
      m_pSubPacketHeader->kind = 0;
      m_pSubPacketHeader->length = 0;
   }

   return (dta::tByte*) m_pSubPacketHeader + sizeof(TCG_SUB_PACKET_HEADER);

} // setComBuffer

//=================================================================================
/// \brief Calculate the length for the current SubPacket/Packet/ComPacket, and update them in headers.
///  Encryption is required for secure messaging if turned on. 
///
///  This function is mainly used immediately after the last SubPacket payload fill-up to complete the 
///  preparation of the entire ComPacket.
///
/// \param pEndData       [IN]  A pointer to the buffer location following the current/last Subpacket payload.
/// \param subPacketKind  [IN]  SubPacket kind.
///
/// \pre Caller provides storage, the initial header sections set except payload lengths.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 Length of the entire built ComPacket.
//=================================================================================
tUINT32 CTcgPacketManager::sealComPacket( dta::tByte* pEndData, tUINT16 subPacketKind )
{
   // Calculate and close the current SubPacket section
   m_pSubPacketHeader->kind = m_swapper.HostToNet( subPacketKind );
   m_pSubPacketHeader->length = m_swapper.HostToNet( (tUINT32)(pEndData - getSubPacketPayloadAddress() ) );

   // Calculate and close the current Packet section
   setCurrentPacketPayloadLength( getPacketPayloadLength() + getAlignedSubPacketSize() ); // appending the current Subpacket to the group of current Packet

   // Process secure-messaging if applicable
   if( m_secureMessaging )
   {
      // TBD
   }

   // Calculate and close the entire ComPacket section by appending the current Packet
   setCurrentComPacketPayloadLength( getComPacketPayloadLength() + sizeof(TCG_PACKET_HEADER) + getPacketPayloadLength() );

   return sizeof(TCG_COM_PACKET_HEADER) + getComPacketPayloadLength();

} // sealComPacket

//=================================================================================
/// \brief Add a SubPacket header to the buffer at the specified location for filling-up of payload afterwords.
///
/// \param pBuffer        [IN]  A pointer to the caller's ComPacketBuffer.
/// \param subPacketKind  [IN]  SubPacket kind.
///
/// \pre It's used for appending subsequent sub-packets after the first one.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the starting location of SubPacket payload for filling-up.
//=================================================================================
dta::tByte* CTcgPacketManager::newSubPacket( dta::tByte* pBuffer, tUINT16 subPacketKind )
{
   m_pSubPacketHeader = (PTCG_SUB_PACKET_HEADER) pBuffer;
   m_pSubPacketHeader->reserved1 = 0;
   m_pSubPacketHeader->reserved2 = 0;
   m_pSubPacketHeader->kind = m_swapper.HostToNet( subPacketKind );
   m_pSubPacketHeader->length = 0;

   return getSubPacketPayloadAddress();

} // newSubPacket

//=================================================================================
/// \brief Calculate the length of the SubPacket payload, and update its header.
///
/// \param pEndData   [IN]  A pointer to the caller's ComPacketBuffer.
///
/// \pre
///
/// \post condition   m_pSubPacketHeader is changed to the next empty location for a new SubPacket to fill in.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to next location to start another SubPacket.
//=================================================================================
dta::tByte* CTcgPacketManager::endSubPacket( dta::tByte* pEndData )
{
   m_pSubPacketHeader->length = m_swapper.HostToNet( (tUINT32)(pEndData - getSubPacketPayloadAddress() ) );
   m_pSubPacketHeader = (PTCG_SUB_PACKET_HEADER) ((dta::tByte*)m_pSubPacketHeader + getAlignedSubPacketSize());
   return (dta::tByte*) m_pSubPacketHeader;

} // endSubPacket

//=================================================================================
/// \brief Add a Packet/SubPacket headers to the buffer at the specified location for filling-up of payload afterwords.
///
/// \param pBuffer         [IN]  A pointer to the caller's ComPacketBuffer.
/// \param seqNumber       [IN]  Sequence Number within this Session.
/// \param ackType         [IN]  Acknowledge type.
/// \param acknowledgement [IN]  Acknowledgement.
/// \param subPacketKind   [IN]  SubPacket kind.
///
/// \pre It's used for appending subsequent packets after the first one.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the starting location of SubPacket payload for filling-up.
//=================================================================================
dta::tByte* CTcgPacketManager::newPacket( dta::tByte* pBuffer, tUINT32 seqNumber, tUINT16 ackType, tUINT32 acknowledgement, tUINT16 subPacketKind )
{
   m_pPacketHeader = (PTCG_PACKET_HEADER) pBuffer;
   m_pSubPacketHeader = (PTCG_SUB_PACKET_HEADER) ((dta::tByte*) m_pPacketHeader + sizeof(TCG_PACKET_HEADER));

   m_pPacketHeader->TPerSN = m_swapper.HostToNet( m_TPerSN );
   m_pPacketHeader->HostSN = m_swapper.HostToNet( m_HostSN );
   m_pPacketHeader->seqNumber = m_swapper.HostToNet( seqNumber );
   m_pPacketHeader->reserved = 0;
   m_pPacketHeader->ackType = m_swapper.HostToNet( ackType );
   m_pPacketHeader->acknowledgement = m_swapper.HostToNet( acknowledgement );
   m_pPacketHeader->length = 0;

   return newSubPacket( (dta::tByte*) m_pPacketHeader + sizeof(TCG_PACKET_HEADER), subPacketKind );

} // newPacket

//=================================================================================
/// \brief Calculate the length of the SubPacket/Packet payload, and update headers.
///
/// \param pEndData   [IN]  A pointer to the caller's ComPacketBuffer.
///
/// \pre
///
/// \post condition   m_pSubPacketHeader is changed to the next empty location.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to next location to start another SubPacket.
//=================================================================================
dta::tByte* CTcgPacketManager::endPacket( dta::tByte* pEndData )
{
   // appending the current Subpacket to the group of current Packet
   setCurrentPacketPayloadLength( getPacketPayloadLength() + getAlignedSubPacketSize() );
   dta::tByte* p = endSubPacket( pEndData ); // m_pSubPacketHeader changed to the next empty location!

   // Encryption if secure messaging is turned on, for this packet payload
   if( m_secureMessaging )
   {
      // TBD
   }

   return p;

} // endPacket

//=================================================================================
/// \brief Calculate the aligned size of the current sub-packet according to the payload alignment spec (4-byte).
///
/// \pre Subpacket has been prepared ready (m_pSubPacketHeader set properly) in the ComBuffer.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 The length of the aligned Sub-packet including header.
//=================================================================================
tUINT32 CTcgPacketManager::getAlignedSubPacketSize() const
{
   return sizeof(TCG_SUB_PACKET_HEADER)
       + ( getSubPacketPayloadLength() + m_padding -1 ) / m_padding * m_padding;

} // getAlignedSubPacketSize

//=================================================================================
/// \brief Creates the cryptogram for a TCG secure Packet payload.
///
/// \param data          [IN]  Input payload for encodeding and encrypting.
/// \param securePayload [OUT] Output secure payload.
///
/// \pre
///
/// \post condition
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 Length of the built secure packet payload.
//=================================================================================
tUINT32 CTcgPacketManager::createSecurePayload( const dta::tBytes & data, dta::tBytes & securePayload )
{
   //TBD
   return (tUINT32) securePayload.size();

} // createSecurePayload

//=================================================================================
/// \brief Constructs a TCG ComPacket with the given SubPacket kind & payload (tokens).
///
/// \param comBuffer        [OUT] ComPacket to be built.
/// \param subPacketPayload [IN]  SubPacket payload data.
/// \param subPacketKind    [IN]  SubPacket kind.
///
/// \return tUINT32 Length of the entire built ComPacket.
//=================================================================================
tUINT32 CTcgPacketManager::buildComPacket( dta::tBytes & comBuffer, dta::tBytes & subPacketPayload, tUINT16 subPacketKind )
{
   tUINT32 bufferSize = (tUINT32)(sizeof(TCG_COM_PACKET_HEADER) + sizeof(TCG_PACKET_HEADER) + sizeof(TCG_SUB_PACKET_HEADER))
                        + (tUINT32) subPacketPayload.size();

   bufferSize = (bufferSize + m_blockSize - 1) / m_blockSize * m_blockSize;
   if( 0 != m_maxComPacketSize && bufferSize > m_maxComPacketSize )
      throw dta::Error(eGenericMemoryError);

   comBuffer.resize( bufferSize );   memset( &comBuffer[0], 0, comBuffer.size() );
   dta::tByte* p = setComBuffer( comBuffer );
   memcpy( p, &subPacketPayload[0], subPacketPayload.size() );
   p += subPacketPayload.size();

   return sealComPacket( p, subPacketKind );
   

/* // reference for handling secure messaging
   dta::tBytes securePacketPayload;
   if( m_secureMessaging )
   {
      securePacketPayload.resize( m_packetHeader.length );
      fillSubPacketHeader( &securePacketPayload[0] );
      memcpy( &securePacketPayload[sizeof(TCG_SUB_PACKET_HEADER)], &subPacketPayload[0], subPacketPayload.size() );
      securePacketPayload = createSecurePayload( securePacketPayload );

      m_packetHeader.length = (tUINT32) securePacketPayload.size();
      m_packetHeader.length = ((m_packetHeader.length + m_padding - 1)/m_padding )* m_padding;
      m_comPacketHeader.length = sizeof(TCG_PACKET_HEADER) + m_packetHeader.length;

      bufferSize = sizeof(TCG_COM_PACKET_HEADER) + m_comPacketHeader.length;
      bufferSize = (bufferSize + m_blockSize - 1) / m_blockSize * m_blockSize;
      comPacket.resize( bufferSize );
      memset( &comPacket[0], 0, comPacket.size() );
   }

   // Fill ComPkt Header, Pkt Header, and SubPket Header
   dta::tByte *p = &comPacket[0];
   fillComPacketHeader( p ); p += sizeof(TCG_COM_PACKET_HEADER);
   fillPacketHeader( p );    p += sizeof(TCG_PACKET_HEADER);
   if( m_secureMessaging )
   {
      memcpy( p, &securePacketPayload[0], securePacketPayload.size() );
   }
   else
   {
      fillSubPacketHeader( p ); p += sizeof(TCG_SUB_PACKET_HEADER);
      memcpy( p, &subPacketPayload[0], subPacketPayload.size() );
   }

   return comPacket;
*/
} // buildComPacket

//=================================================================================
TCG_STATUS CTcgPacketManager::parseComPacket( dta::tBytes &comPacket, dta::tBytes &subPacketPayload, tUINT8 expectedToken, TCG_UID expectedTargetID, TCG_UID expectedMethodID )
{
   TCG_STATUS status = TS_SUCCESS;
   dta::tByte* p = (dta::tByte*) &comPacket[0];
   p += sizeof(TCG_COM_PACKET_HEADER) + sizeof(TCG_PACKET_HEADER);

   setComBuffer( comPacket, false );

   if( m_secureMessaging )
   {
      dta::tBytes securePacketPayload;
      securePacketPayload.resize( getPacketPayloadLength() );
      memcpy( &securePacketPayload[0], p, securePacketPayload.size());
      status = secureResponse( securePacketPayload );

      p = &securePacketPayload[0];

      subPacketPayload.resize( m_swapper.NetToHost( ((TCG_SUB_PACKET_HEADER*)p)->length ) );
   }
   else
   {
      subPacketPayload.resize( getSubPacketPayloadLength() );
   }

   if( subPacketPayload.size() == 0 )
      throw dta::Error(eGenericInvalidIdentifier);

   memcpy( &subPacketPayload[0], p+sizeof(TCG_SUB_PACKET_HEADER), subPacketPayload.size() );

   // Performs some check-up
   if( subPacketPayload[0] != expectedToken )
      throw dta::Error(eGenericInvalidIdentifier);

   if( TOKEN_TYPE_END_OF_SESSION == expectedToken ) // no more data for EOS
      return status;

   if( TOKEN_TYPE_START_TRANSACTION == expectedToken || TOKEN_TYPE_END_TRANSACTION == expectedToken ) // following is the only status byte
      return subPacketPayload[1];

   if( TOKEN_TYPE_CALL == expectedToken )
   {
      if( m_swapper.NetToHost( *((tUINT64*)(&subPacketPayload[2])) ) != expectedTargetID )
         throw dta::Error(eGenericInvalidIdentifier);

      if( m_swapper.NetToHost( *((tUINT64*)(&subPacketPayload[11])) ) != expectedMethodID )
         throw dta::Error(eGenericInvalidIdentifier);
   }

   // Check the last section of the return (Status)
   if( TOKEN_TYPE_END_OF_DATA != subPacketPayload[getSubPacketPayloadLength() -6] )
      throw dta::Error(eGenericInvalidIdentifier);

   if( TOKEN_TYPE_START_LIST != subPacketPayload[getSubPacketPayloadLength() -5] )
      throw dta::Error(eGenericInvalidIdentifier);

   if( TOKEN_TYPE_END_LIST != subPacketPayload[getSubPacketPayloadLength() -1] )
      throw dta::Error(eGenericInvalidIdentifier);

   status = subPacketPayload[getSubPacketPayloadLength() -4];

   if( TS_SUCCESS != status )
      throw (TCG_STATUS) status;

   return status;

} // parseComPacket

//=================================================================================
TCG_STATUS CTcgPacketManager::secureResponse( dta::tBytes & packet )
{
   // TBD
   return 0;

} // secureResponse

//=================================================================================
/// \brief Encryptes or decryptes a cryptogram.
///
/// \param encryptedData  [in,out]  Vector of encrypted bytes.
/// \param unecryptedData [in,out]  Vector of unencrypted bytes.
/// \param encrypt        [in]      Boolean value determining encryt/decrypt
/// \param useIV          [in]      Boolean value determining use of initialzation vector.
///
/// \return Number of bytes processed
//=================================================================================
tINT32 CTcgPacketManager::packetCrypt(std::vector<tUINT8> &encryptedData,
                               std::vector<tUINT8> &unecryptedData,
                               const bool encrypt,
                               const bool useIV)
{
   // Determine which key to use based on direction
   tUINT8* key = encrypt ? &m_hostToDriveKey[0] : &m_driveToHostKey[0];

   // Set the local algorithm
   tUINT8 algo = encrypt ? m_commandAlgo : m_responseAlgo;

   // Set up some attributes for each algorithm
   bool ecb;
   tUINT16 bitSize   = 0;
   tUINT8  blockSize = 0;
   switch (algo)
   {
      case CALGO_DES_ECB:
         ecb = true;
         blockSize = DES_BLOCK_SIZE;
         break;
      case CALGO_DES_CBC:
         ecb = false;
         blockSize = DES_BLOCK_SIZE;
         break;
      case CALGO_3DES_ECB:
         ecb = true;
         blockSize = TRIPLE_DES_BLOCK_SIZE;
         break;
      case CALGO_3DES_CBC:
         ecb = false;
         blockSize = TRIPLE_DES_BLOCK_SIZE;
         break;
      case CALGO_AES_ECB_128:
         bitSize = 128;
         ecb = true;
         blockSize = AES_BLOCK_SIZE;
         break;
      case CALGO_AES_CBC_128:
         bitSize = 128;
         ecb = false;
         blockSize = AES_BLOCK_SIZE;
         break;
      case CALGO_AES_ECB_192:
         bitSize = 192;
         ecb = true;
         blockSize = AES_BLOCK_SIZE;
         break;
      case CALGO_AES_CBC_192:
         bitSize = 192;
         ecb = false;
         blockSize = AES_BLOCK_SIZE;
         break;
      case CALGO_AES_ECB_256:
         bitSize = 256;
         ecb = true;
         blockSize = AES_BLOCK_SIZE;
         break;
      case CALGO_AES_CBC_256:
         bitSize = 256;
         ecb = false;
         blockSize = AES_BLOCK_SIZE;
         break;
      default:
         bitSize = 0;
         ecb = false;
         blockSize = 0;
   } // switch

   // If we're encrypting, make sure we're block aligned
   if (encrypt && ((encryptedData.size() % blockSize) != 0))
   {
      encryptedData.resize(encryptedData.size() + blockSize - (encryptedData.size() % blockSize));
   }

   // Set the Initialization vector, if needed
   tUINT8* iv     = useIV ? &m_challengeIV[0] : NULL;
   tUINT32 ivSize = useIV ? (tUINT32)m_challengeIV.size() : 0;

   // Now encrypt/decrypt
   switch (algo)
   {
         case CALGO_3DES_ECB:
         case CALGO_3DES_CBC:
#if defined(_WIN32) // TODO: // nvn20110728 - linux crypto
            return DTLCRYPTO::crypt3Des(key,
                                       (tUINT8*)&encryptedData[0],
                                       (tINT32)encryptedData.size(),
                                       (tUINT8*)&unecryptedData[0],
                                       (tINT32)unecryptedData.size(),
                                       encrypt,
                                       ecb,
                                       iv,
                                       ivSize);
#endif
         case CALGO_AES_ECB_128:
         case CALGO_AES_CBC_128:
         case CALGO_AES_ECB_192:
         case CALGO_AES_CBC_192:
         case CALGO_AES_ECB_256:
         case CALGO_AES_CBC_256:
#if defined(_WIN32) // TODO: // nvn20110728 - linux crypto
            return DTLCRYPTO::cryptAes(key,
                                       (tUINT8*)&encryptedData[0],
                                       (tINT32)encryptedData.size(),
                                       (tUINT8*)&unecryptedData[0],
                                       (tINT32)unecryptedData.size(),
                                       encrypt,
                                       ecb,
                                       bitSize,
                                       iv,
                                       ivSize);
#endif
         default:
            return 0;
   } // switch

} // packetCrypt
