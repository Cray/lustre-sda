/*! \file tcgsilo.hpp
    \brief Basic API definition for IEEE-1667 TCG Silo.

    This file details the interface classes and functions for writing
    client code that uses the TCG security protocol via DTA to access
    Self-Encrypting devices.  It is a C++ specific interface.
    
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

#ifndef TCGSILO_DOT_HPP
#define TCGSILO_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include passwordsilo.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "ieee1667i.hpp"

namespace dti
{
   //=================================
   // enumerations
   //=================================
   /// TCG Silo Functions
   typedef enum
   {
      eTCGGetSiloCapabilities = 0x01,
      eTCGTransfer            = 0x02,
      eTCGReset               = 0x03,
      eTCGGetTransferResults  = 0x04
   } eTCGSiloFunctions;

   //=================================
   // structures
   //=================================
#pragma pack(push, 1)
   /// Get Silo Capabilities Command payload structure
   typedef struct tGSCCommandPayload
   {
      CommonPayloadHeader header;   /// Byte 0-7
   } GSCCommandPayload;

   /// Get Silo Capabilities Reponse payload structure
   typedef struct tGSCResponsePayloadHdr
   {
      ResponsePayloadHeader header;          /// Byte 0-7
      tUINT32 availablePayloadLength;        /// Byte 8-11
      tUINT16 ComID;                         /// Byte 12-13
      tUINT8  reserved1[2];                  /// Byte 14-15
      tUINT32 maximum_P_OUT_TransferSize;    /// Byte 16-19
      tUINT8  reserved2[8];                  /// Byte 20-27
      tUINT32 tcgLevel0DiscoveryDataLength;  /// Byte 28-31
      //tUINT8[]  tcgLevel0DiscoveryData;    /// Byte 32+
   } GSCResponsePayloadHdr;


   /// Transfer Command Payload structure
   typedef struct tTransferCommandPayloadHdr
   {
      CommonPayloadHeader header;   /// Byte 0-7
      tUINT8 reserved[20];          /// Byte 8-27
      tUINT32 tcgComPacketLength;   /// Byte 28-31
      //tUINT8[]  tcgComPacket;     /// Byte 32+
   } TransferCommandPayloadHdr;

   /// Transfer Response payload structure
   typedef struct tTransferResponsePayloadHdr
   {
      ResponsePayloadHeader header;   /// Byte 0-7
      tUINT32 availablePayloadLength; /// Byte 8-11
      tUINT8 reserved[16];            /// Byte 12-27
      tUINT32 tcgComPacketLength;     /// Byte 28-31
      //tUINT8[]  tcgComPacket;       /// Byte 32+
   } TransferResponsePayloadHdr;


   /// Get Transfer Results command Payload structure
   typedef struct tGetXferResultsCommandPayload
   {
      CommonPayloadHeader header;   /// Byte 0-7
   } GetXferResultsCommandPayload;

   /// Get Transfer Results response payload structure, similiar to that of Transfer cmd
   typedef struct tGetXferResultsResponsePayloadHdr
   {
      ResponsePayloadHeader header;   /// Byte 0-7
      tUINT32 availablePayloadLength; /// Byte 8-11
      tUINT8 reserved[16];            /// Byte 12-27
      tUINT32 tcgComPacketLength;     /// Byte 28-31
      //tUINT8[]  tcgComPacket;       /// Byte 32+
   } GetXferResultsResponsePayloadHdr;


   /// Reset Command payload structure
   typedef struct tResetCommandPayload
   {
      CommonPayloadHeader header;   /// Byte 0-7
   } ResetCommandPayload;

   /// Reset Response payload structure
   typedef struct tResetResponsePayload
   {
      ResponsePayloadHeader header; /// Byte 0-7
   } ResetResponsePayload;
#pragma pack(pop)

   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implements protocol.
   ///
   /// CTCGSilo is a derived class from CSiloBase which provides the
   /// implementation IEEE 1667 Password Silo Specification.
   //====================================================================================
   class CTCGSilo : public CSiloBase
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTCGSilo.
      ///
      /// The constructor takes a CDriveTrustSession as it class member.
      ///
      /// \param device [in] CIEEE1667Interface object which has been initialized
      ///                        and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTCGSilo(dti::CIEEE1667Interface* device);

      //=================================================================================
      /// \brief Constructor for CTCGSilo.
      ///
      /// The constructor takes a CDriveTrustSession as it class member. Also creates a
	   /// log file.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized
      ///                        and connected to a DriveTrust device.
      /// \param logFileName [in] Name of file to log commands.
      ///
      //=================================================================================
      CTCGSilo(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      //
      // START OF TCG SILO COMMANDS
      //
      //=================================================================================

      //=================================================================================
      /// \brief Get Silo Capabilites
      ///
      /// \param  level0DiscoveryData [out]
      /// \param  pComID              [out]
      /// \param  pMaxPOutSize        [out]
      ///
      /// \return SC_SUCCESS status if successful, false otherwise.
      //=================================================================================
      IEEE1667_STATUS getSiloCapabilites(dta::tBytes &level0DiscoveryData, 
                                         tUINT16 *pComID =NULL, tUINT32 *pMaxPOutSize =NULL );

      //=================================================================================
      /// \brief Transfer
      ///
      /// \param  tcgComPacketPOut [in]   TCG ComPacket data to transfer to the device.
      /// \param  tcgComPacketPIn  [out]  TCG ComPacket data received from the device.
      ///
      /// \return SC_SUCCESS status if successful, false otherwise.
      //=================================================================================
      IEEE1667_STATUS transfer(const dta::tBytes &tcgComPacketPOut, dta::tBytes &tcgComPacketPIn);

      //=================================================================================
      /// \brief getXferResults
      ///
      /// \param  tcgComPacket  [out]  TCG ComPacket data retrieved/received from the device.
      ///
      /// \return SC_SUCCESS status if successful, false otherwise.
      //=================================================================================
      IEEE1667_STATUS getXferResults(dta::tBytes &tcgComPacket);

      //=================================================================================
      /// \brief Reset
      ///
      /// \return SC_SUCCESS status if successful, false otherwise.
      //=================================================================================
      IEEE1667_STATUS reset();


      //=================================================================================
      /// \brief executeTCGComPacketCmd
      ///
      /// \param  tcgComPacketPOut [in]   TCG ComPacket data to transfer to the device.
      /// \param  tcgComPacketPIn  [out]  TCG ComPacket data received from the device.
      /// \param  timeout          [in]   Number of milliseconds for the command to complete
      /// \param  pollingInterval  [in]   Number of milliseconds for the interval of result polling
      ///
      /// \return SC_SUCCESS status if successful, false otherwise.
      //=================================================================================
      IEEE1667_STATUS executeTCGComPacketCmd(const dta::tBytes &tcgComPacketPOut, dta::tBytes &tcgComPacketPIn,
                               const tUINT32 timeout=15000, const tUINT32 pollingInterval=3);


      //=================================================================================
      //
      // END OF TCG SILO COMMANDS
      //
      //=================================================================================
   protected:
      void sleep( clock_t wait );

   public:
      /// TCG Silo Status values
      typedef enum
      {
         SC_NO_ERROR             = 0x00,
         SC_ERROR_GENERIC_ERROR  = 0x80,
      } TCGSiloStatus;

   private:
      CByteOrder m_swapper;   /// Used for converting from system to big endian.
      tUINT16 m_ComID;
      tUINT32 m_MaxPOutSize;
   }; // class CTCGSilo
} // namespace dti

#endif // TCGSILO_DOT_HPP