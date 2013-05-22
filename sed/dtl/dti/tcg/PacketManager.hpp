/*! \file PacketManager.hpp
    \brief Class declaration for TCG Packets.

    This file contains the class structures for ComPacket/Packet/SubPacket.
    It is a C++ specific interface. For a 'C' interface, include 
    PacketManager.h instead of this file.
    
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

#ifndef PACKETMANAGER_DOT_HPP
#define PACKETMANAGER_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include PacketManager.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include <math.h>
#include <dta/dta.hpp>
#include "../byteorder.hpp"
#include "TCGValues.h"

namespace dti
{
   //=================================
   // defines
   //=================================

   //=================================
   // structures and type definitions
   //=================================

#pragma pack(push, 2)

   //
   /// Com Packet Header
   //
   typedef struct _TCG_COM_PACKET_HEADER
   {
      tUINT32 reserved;           /// must be all zeros

      tUINT32 extendedComID;      /// ComID of this comPacket

      tUINT32 outstandingData;    /// For TPer->Host, number of bytes readily available 
                                  /// (including Compacket/Packet/Subpacket overheads) in TPer yet 
                                  /// to be transfered to host with this ComID after this ComPacket.
                                  /// Max value (0xFFFFFFFF) may mean this actual value, or more.
                                  /// If TPer is not ready for the remaining data, it is 0x00000001.
                                  ///
                                  /// For Host->TPer, set to all zeros.

      tUINT32 minTransfer;        /// For TPer->Host, minimum number of bytes Host must request with 
                                  /// this ComID, including Compacket/Packet/Subpacket overheads.
                                  /// Set to zero if TPer has no more data, or no such min requirement for host.
                                  /// For Host->TPer, set to all zeros.

      tUINT32 length;             /// number of bytes of the payload (one or more packets) that follows
                                  /// in this ComPacket. Should be 4-byte aligned, multiple of 4-bytes.

   } TCG_COM_PACKET_HEADER, *PTCG_COM_PACKET_HEADER;

   //
   /// Packet Header
   //
   typedef struct _TCG_PACKET_HEADER
   {
      tUINT32 TPerSN;             /// TPer Session Number/ID
                                  ///                        + => as "Session" in the TCG spec
      tUINT32 HostSN;             /// Host Session Number/ID

      tUINT32 seqNumber;          /// packet number tracked within this sessionID, 1 to 2^32 -1.
                                  /// (Not supported yet in Hurricane, set to 0)

      tUINT16 reserved;           /// set to zeros

      tUINT16 ackType;            /// 0x0001 if ACK, 0x0002 NAK, 0x0000 if neither.
                                  /// (Not supported yet in Hurricane, set to 0)

      tUINT32 acknowledgement;    /// seqNo of last packet  received if ackType = 0x0001,
                                  /// seqNo of the packet requested for re-transmission if ackType = 0x0002,
                                  /// all zeros if ackType = 0.
                                  /// (Not supported yet in Hurricane, set to 0)

      tUINT32 length;             /// number of bytes of payload (subpackets or secure messaging data)
                                  /// that follows in this packet, 4-byte aligned.

   } TCG_PACKET_HEADER, *PTCG_PACKET_HEADER;

   //
   /// Sub Packet Header
   //
   typedef struct _TCG_SUB_PACKET_HEADER
   {
      tUINT32 reserved1;          /// set to all zeros
      tUINT16 reserved2;          /// set to all zeros

      tUINT16 kind;               /// type of sub-packet, 
                                  /// 0x0000 indicates a data subpacket, 
                                  /// 0x8001 credit subpacket (length=4).

      tUINT32 length;             /// number of bytes of payload (tokens and/or a partial token) in
                                  /// this subpacket (excluding 4-byte aligned padding for the payload),
                                  /// padding of 4- (length mode 4) bytes may follow after this field.

   } TCG_SUB_PACKET_HEADER, *PTCG_SUB_PACKET_HEADER;

#pragma pack(pop)


   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Class that defines TCG Packet Manager handling ComPacket/Packet/SubPacket.
   ///
   /// CTcgComPacket is a class that implements the TCG Packets
   //====================================================================================
   class CTcgPacketManager
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgPacketManager.
      ///
      /// \param extComID Extended ComID for ComPacket that will be built for.
      /// \param blockSize Block size for ComPacket that will be built with.
      ///
      /// \return
      //=================================================================================
      CTcgPacketManager( tUINT32 extComID=EXT_COM_ID1, tUINT16 blockSize=512 ) : 
         m_blockSize(blockSize), m_maxComPacketSize(0), m_maxPacketSize(0), m_sessionTimeout(0),
         m_extendedComID(extComID), m_TPerSN(0), m_HostSN(0), m_seqNumber(0), m_secureMessaging(false) {}

      // Packet & subpacket construction/build-up
      dta::tByte* setComBuffer( dta::tBytes &comBuffer, bool dataEmpty=true );
      tUINT32 sealComPacket( dta::tByte* pEndData, tUINT16 subPacketKind=DATA_SUB_PKT );
      dta::tByte* getSubPacketPayloadAddress() { return (dta::tByte*) m_pSubPacketHeader + sizeof(TCG_SUB_PACKET_HEADER); }

      dta::tByte* newSubPacket( dta::tByte* pBuffer, tUINT16 subPacketKind=DATA_SUB_PKT );
      dta::tByte* endSubPacket( dta::tByte* pEndData );

      dta::tByte* newPacket( dta::tByte* pBuffer, tUINT32 seqNumber=0, tUINT16 ackType=0, tUINT32 acknowledgement=0, tUINT16 subPacketKind=DATA_SUB_PKT );
      dta::tByte* endPacket( dta::tByte* pEndData ); // including ending the current subpacket

      //=================================================================================
      /// \brief Constructs a TCG ComPacket with the given SubPacket kind & payload (tokens).
      ///
      /// \param comBuffer        [OUT] ComPacket to be built.
      /// \param subPacketPayload [IN]  SubPacket payload data.
      /// \param subPacketKind    [IN]  SubPacket kind.
      ///
      /// \return tUINT32 Length of the entire built ComPacket.
      //=================================================================================
      tUINT32 buildComPacket( dta::tBytes & comBuffer, dta::tBytes & subPacketPayload, tUINT16 subPacketKind =DATA_SUB_PKT );

      //=================================================================================
      /// \brief Extracts the status and sub-packet playload from a response ComPacket.
      ///
      /// \param comPacket [In] Response ComPacket.
      /// \param subPacketPayload [Out] SubPacketPayload(tokens) extracted from response ComPacket.
      /// \param expectedToken [In] 
      /// \param expectedTargetID [In] 
      /// \param expectedMethodID [In] 
      ///
      /// \return TCG_STATUS output of reponse status
      //=================================================================================
      TCG_STATUS parseComPacket( dta::tBytes &comPacket, dta::tBytes &subPacketPayload, tUINT8 expectedToken=TOKEN_TYPE_START_LIST, TCG_UID expectedTargetID=0, TCG_UID expectedMethodID=0 );

      //
      // Get/Set class member variables
      //

      //=================================================================================
      /// \brief Sets the value of m_blockSize.
      ///
      /// \param blockSize Block size for device Packet's will be built for.
      ///
      /// \return 
      //=================================================================================
      void setBlockSize( tUINT16 blockSize ) { m_blockSize = blockSize; }

      //=================================================================================
      /// \brief Returns the block size
      ///
      /// \return Block size
      //=================================================================================
      tUINT16 blockSize() const { return m_blockSize; }

      //=================================================================================
      /// \brief Sets the value of extendedComID for ComPacketHeader.
      ///
      /// \param extComID [IN]  extended ComID for ComPackets to be built for.
      ///
      /// \return 
      //=================================================================================
      void setExtendedComID( tUINT32 extComID ) { m_extendedComID = extComID; }

      //=================================================================================
      /// \brief Gets the value of extendedComID of ComPacketHeader.
      ///
      /// \return tUINT32 the currently used ComID value
      //=================================================================================
      tUINT32 getExtendedComID() const { return m_extendedComID; }

      //=================================================================================
      /// \brief Sets the value of TPerSN for PacketHeader.
      ///
      /// \param tperSN [IN]  TPerSN for Packets to be built for.
      ///
      /// \return 
      //=================================================================================
      void setTPerSN( tUINT32 tperSN ) { m_TPerSN = tperSN; }

      //=================================================================================
      /// \brief Gets the value of TPerSN of PacketHeader.
      ///
      /// \return tUINT32 the currently used TPerSN value
      //=================================================================================
      tUINT32 getTPerSN() const { return m_TPerSN; }

      //=================================================================================
      /// \brief Sets the value of HostSN for PacketHeader.
      ///
      /// \param hostSN [IN]  HostSN for Packets to be built for.
      ///
      /// \return 
      //=================================================================================
      void setHostSN( tUINT32 hostSN ) { m_HostSN = hostSN; }

      //=================================================================================
      /// \brief Gets the value of HostSN of PacketHeader.
      ///
      /// \return tUINT32 the currently used HostSN value
      //=================================================================================
      tUINT32 getHostSN() const { return m_HostSN; }

      void setMaxComPacketSize( tUINT32 maxComPacketSize ) { m_maxComPacketSize = maxComPacketSize; }
      tUINT32 getMaxComPacketSize() const { return m_maxComPacketSize; }

      void setMaxPacketSize( tUINT32 maxPacketSize ) { m_maxPacketSize = maxPacketSize; }
      tUINT32 getMaxPacketSize() const { return m_maxPacketSize; }

      void setSessionTimeout( tUINT32 sessionTimeout ) { m_sessionTimeout = sessionTimeout; }
      tUINT32 getSessionTimeout() const { return m_sessionTimeout; }

      void setSeqNumber( tUINT32 seqNumber ) { m_seqNumber = seqNumber; }
      tUINT32 getSeqNumber() const { return m_seqNumber; }

      //
      // Retrieve header variables
      //

      //=================================================================================
      /// \brief Gets the value of oustanding ComID data of ComPacketHeader.
      ///
      /// \return tUINT32 the current oustanding Com data
      //=================================================================================
      tUINT32 getOustandingData() const
      {
          return m_swapper.NetToHost( m_pComPacketHeader->outstandingData );
      }

      //=================================================================================
      /// \brief Gets the value of minTransfer of ComPacketHeader.
      ///
      /// \return tUINT32 the current minTransfer of ComPacket
      //=================================================================================
      tUINT32 getMinTransfer() const
      {
          return m_swapper.NetToHost( m_pComPacketHeader->minTransfer );
      }

      //=================================================================================
      /// \brief Gets the length of ComPacket payload in ComPacketHeader.
      ///
      /// \return tUINT32 the current minTransfer of ComPacket
      //=================================================================================
      tUINT32 getComPacketPayloadLength() const
      {
          return m_swapper.NetToHost( m_pComPacketHeader->length );
      }

      //=================================================================================
      /// \brief Gets the length of Packet payload in PacketHeader.
      ///
      /// \return tUINT32 the length of Packet payload
      //=================================================================================
      tUINT32 getPacketPayloadLength() const
      {
          return m_swapper.NetToHost( m_pPacketHeader->length );
      }

      //=================================================================================
      /// \brief Gets the value of kind of SubPacketHeader.
      ///
      /// \return tUINT16 the currently used kind value
      //=================================================================================
      tUINT16 getSubPacketKind() const
      {
          return m_swapper.NetToHost( m_pSubPacketHeader->kind );
      }

      //=================================================================================
      /// \brief Gets the length of SubPacket payload in SubPacketHeader.
      ///
      /// \return tUINT32 the length of SubPacket payload
      //=================================================================================
      tUINT32 getSubPacketPayloadLength() const
      {
          return m_swapper.NetToHost( m_pSubPacketHeader->length );
      }

      //=================================================================================
      /// \brief Returns the Challenge initialization vector
      ///
      /// \return Challenge initialization vector
      //=================================================================================
      dta::tBytes challengeIV() const
      {
         return m_challengeIV;
      }

      //=================================================================================
      /// \brief Sets the challenge initialization vector
      ///
      /// \param challengeIV New challenge initialization vector
      //=================================================================================
      void setChallengeIV(const dta::tBytes challengeIV)
      {
         m_challengeIV = challengeIV;
      }

      //=================================================================================
      /// \brief Returns the Host-to-Drive key
      ///
      /// \return Host-to-Drive key
      //=================================================================================
      dta::tBytes hostToDriveKey() const
      {
         return m_hostToDriveKey;
      }

      //=================================================================================
      /// \brief Sets the Host-to-Drive key.
      ///
      /// \param key New Host-to-Drive key.
      //=================================================================================
      void setHostToDriveKey(const dta::tBytes key)
      {
         m_hostToDriveKey = key;
      }

      //=================================================================================
      /// \brief Returns the Drive-to-Host key
      ///
      /// \return Drive-to-Host key
      //=================================================================================
      dta::tBytes driveToHostKey() const
      {
         return m_driveToHostKey;
      }

      //=================================================================================
      /// \brief Sets the Drive-to-Host key.
      ///
      /// \param key New Drive-to-Host key
      //=================================================================================
      void setDriveToHostKey(const dta::tBytes key)
      {
         m_driveToHostKey = key;
      }

      //=================================================================================
      /// \brief Returns the DL hash key
      ///
      /// \return DL hash key
      //=================================================================================
      dta::tBytes dlHashKey() const
      {
         return m_dlHashKey;
      }

      //=================================================================================
      /// \brief Sets the DL hash key
      ///
      /// \param key New DL hash key
      //=================================================================================
      void setDLHashKey(const dta::tBytes key)
      {
         m_dlHashKey = key;
      }

      //=================================================================================
      /// \brief Returns the command encryption algorithm
      ///
      /// \return Command encryption algorithm
      //=================================================================================
      tUINT8 commandEncryptionAlgorithm() const
      {
         return m_commandAlgo;
      }

      //=================================================================================
      /// \brief Sets the command encryption algorithm
      ///
      /// \param algorithm New command encryption algorithm
      //=================================================================================
      void setCommandEncryptionAlgorithm(const tUINT8 algorithm)
      {
         m_commandAlgo = algorithm;
      }

      //=================================================================================
      /// \brief Returns the response encryption algorithm
      ///
      /// \return Response encryption algorithm
      //=================================================================================
      tUINT8 responseEncryptionAlgorithm() const
      {
         return m_responseAlgo;
      }

      //=================================================================================
      /// \brief Sets the response encryption algorithm
      ///
      /// \param algorithm New response encryption algorithm
      //=================================================================================
      void setResponseEncryptionAlgorithm(const tUINT8 algorithm)
      {
         m_responseAlgo = algorithm;
      }

      //=================================================================================
      /// \brief Returns boolean for secure messaing.
      ///
      /// \return Boolean secure messaging.
      //=================================================================================
      bool secureMessaging() const
      {
         return m_useCRT;
      }

      //=================================================================================
      /// \brief Sets the boolean for secure messaging.
      ///
      /// \param secureMessaging New value for secureMessaging.
      //=================================================================================
      void setSecureMessaging(const bool secureMessaging)
      {
         m_secureMessaging = secureMessaging;
      }

      //=================================================================================
      /// \brief Returns boolean for using CRT's.
      ///
      /// \return Boolean use CRT.
      //=================================================================================
      bool useCRT() const
      {
         return m_useCRT;
      }

      //=================================================================================
      /// \brief Sets the boolean for using CRT's.
      ///
      /// \param useCRT New value for using CRT.
      //=================================================================================
      void setUseCRT(const bool useCRT)
      {
         m_useCRT = useCRT;
      }

      //=================================================================================
      /// \brief Returns boolean for using get challenge plus one for iv.
      ///
      /// \return Boolean use get challenge plus one for iv.
      //=================================================================================
      bool useChallengeIV() const
      {
         return m_useChallengeIV;
      }

      //=================================================================================
      /// \brief Sets the boolean for get challenge plus one for iv.
      ///
      /// \param useChallengeIV New boolean value for using challenge plus one for iv.
      //=================================================================================
      void setUseChallengeIV(const bool useChallengeIV)
      {
         m_useChallengeIV = useChallengeIV;
      }

   protected:

      void setCurrentSubPacketPayloadLength( tUINT32 length ) { m_pSubPacketHeader->length = m_swapper.HostToNet(length); }
      void setCurrentPacketPayloadLength( tUINT32 length ) { m_pPacketHeader->length = m_swapper.HostToNet(length); }
      void setCurrentComPacketPayloadLength( tUINT32 length ) { m_pComPacketHeader->length = m_swapper.HostToNet(length); }
      tUINT32 getAlignedSubPacketSize() const;

      //=================================================================================
      /// \brief Creates the cryptogram for a TCG secure Packet payload.
      ///
      /// \param data          [IN]  Input payload for encodeding and encrypting.
      /// \param securePayload [OUT] Output secure payload.
      ///
      /// \return tUINT32 Length of the built secure packet payload.
      //=================================================================================
      tUINT32 createSecurePayload( const dta::tBytes & data, dta::tBytes & securePayload );

      //=================================================================================
      /// \brief Decodes a secure response to an unencrypted Packet payload.
      ///
      /// \param packet [in,out] Reponse Packet that needs decoding and decrypting.
      ///
      /// \return TCG_STATUS Status from response packet.
      //=================================================================================
      TCG_STATUS secureResponse( dta::tBytes & packet );

      //=================================================================================
      /// \brief Encryptes or decryptes a cryptogram.
      ///
      /// \param encryptedData [in,out]   Vector of encrypted bytes.
      /// \param unecryptedData [in,out]  Vector of unencrypted bytes.
      /// \param encrypt [in]             Boolean value determining encryt/decrypt
      /// \param useIV [in]               Boolean value determining use of initialzation vector.
      ///
      /// \return Number of bytes processed
      //=================================================================================
      tINT32 packetCrypt(std::vector<tUINT8> &encryptedData, std::vector<tUINT8> &unecryptedData,
                        const bool encrypt, const bool useIV);

   protected:
      // ComPacket/Packet/SubPacket variables
      tUINT16 m_blockSize;                       /// Block size.
      tUINT32 m_maxComPacketSize;                /// Max ComPacket size (header + payload)
      tUINT32 m_maxPacketSize;                   /// Max Packet size (header + payload)
      tUINT32 m_sessionTimeout;                  /// Timeout value for the current session
      tUINT32 m_extendedComID;                   /// ComID of this comPacket
      tUINT32 m_TPerSN;                          /// TPer Session Number/ID
      tUINT32 m_HostSN;                          /// Host Session Number/ID
      tUINT32 m_seqNumber;                       /// packet number tracked within this sessionID, 1 to 2^32 -1.
      TCG_COM_PACKET_HEADER *m_pComPacketHeader; /// Pointer to the current ComBuffer's ComPacket header.
      TCG_PACKET_HEADER     *m_pPacketHeader;    /// Pointer to the current ComBuffer's present Packet header.
      TCG_SUB_PACKET_HEADER *m_pSubPacketHeader; /// Pointer to the current ComBuffer's present SubPacket header.

      // Secure messaging variables
      dta::tBytes m_challengeIV;                 /// Initialization Vector.
      dta::tBytes m_hostToDriveKey;              /// Key for encrypted command packet payloads.
      dta::tBytes m_driveToHostKey;              /// Key for decrypting response packet payloads.
      dta::tBytes m_dlHashKey;                   /// Key for calculating the SHA1 hash.
      tUINT8 m_commandAlgo;                      /// Command packet payload encryption algorithm.
      tUINT8 m_responseAlgo;                     /// Response packet payload encryption algorithm.
      bool m_secureMessaging;                    /// Bool for enabling/disabling secure messaging.
      bool m_useCRT;                             /// Bool use Command Reference Templates.
      bool m_useChallengeIV;                     /// Bool use last get challenge plus one for iv.

      // utilities
      CByteOrder m_swapper;                      /// Used for converting from system to big endian.

   private:
      static const tUINT32 m_padding = 4;        /// Alignment/padding for payload of SubPacket
   }; // class CTcgPacketManager

} // namespace dti


#endif // PACKETMANAGER_DOT_HPP