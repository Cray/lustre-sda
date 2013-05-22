/*! \file ieee1667values.h
    \brief Basic definition for common IEEE 1667 values.

    This file defines IEEE-1667 values.

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

    Copyright © 2008.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.

*/

#ifndef IEEE1667VALUES_DOT_H
#define IEEE1667VALUES_DOT_H

//=================================
// defines
//=================================

/// Defintions used for probing the device
#define IEEE1667_MAJOR_VERSION      0x01  /// IEEE 1667 Major Version number
#define IEEE1667_MINOR_VERSION      0x01  /// IEEE 1667 Minor Version number
#define IEEE1667_PROBE_SILO_MAJOR   0x01  /// IEEE 1667 Probe Silo Major Version number
#define IEEE1667_PROBE_SILO_MINOR   0x01  /// IEEE 1667 Probe Silo Minor Version number
#define IEEE1667_PROBE_SILO_INDEX   0x00  /// IEEE 1667 Probe Silo Index

//=================================
// typedefs
//=================================
typedef tUINT8 IEEE1667_STATUS;  /// Typedef for IEEE 1667 status code

//=================================
// enums
//=================================
/// 1667 Status values
enum IEEE1667Status
{
   SC_SUCCESS                             = 0x00,
   SC_DEFAULT_BEHAVIOR                    = 0x01,
   SC_FAILURE                             = 0x80,
   SC_UNSUPPORTED_HOST_1667VERSION        = 0x81,
   SC_INVALID_PARAMETER_COMBINATION       = 0xF7, // Swapped with F8 by MSFT 1.29.09
   SC_INVALID_PARAMETER_LENGTH            = 0xF8, // Swapped with F7 by MSFT 1.29.09
   SC_INCONSISTENT_PAYLOAD_CONTENT_LENGTH = 0xF9,
   SC_INCOMPLETE_COMMAND                  = 0xFA,
   SC_INVALID_SILO                        = 0xFB,
   SC_INVALID_PARAMETER                   = 0xFC,
   SC_SEQUENCE_REJECTION                  = 0xFD,
   SC_NO_PROBE                            = 0xFE,
   SC_RESERVED_FUNCITON                   = 0xFF,

   // Seagate Unique
   SC_DTL_ERROR                           = 0xF0,  /// This gives an error code for failure within the DTL layer.
};

//=================================
// structs
//=================================
#pragma pack(push, 2)

   /// Common header for send payloads
   typedef struct tCommonPayloadHeader
   {
      tUINT32 payloadContentLength; /// Byte 0-3
      tUINT8  reserved[4];          /// Byte 4-7
   } CommonPayloadHeader;

   /// Common header for response payloads
   typedef struct tResponsePayloadHeader
   {
      tUINT32 payloadContentLength;    /// Byte 0-3
      tUINT8  reserved[3];             /// Byte 4-6
      tUINT8  statusCode;              /// Byte 7
   } ResponsePayloadHeader;

#pragma pack(pop)

/// Silo IDs
typedef enum
{
   eSiloProbe    = 0x00000100,   /// Probe Silo
   eSiloCert     = 0x00000101,   /// Certificate Silo
   eSiloPassword = 0x00000102,   /// Password Silo
   eSiloTCG      = 0x00000104,   /// TCG Silo
   eSiloTCGDev   = 0x00001234,   /// TCG Silo for Development
} eSiloIDs;

//=================================================================================
/// \brief Returns a string description of a silo type id.
///
/// \param siloTypeID[in] Silo Type ID
///
/// \return String description of given Silo Type ID.
//=================================================================================
static _tstring siloTypeIDToString(const tUINT32 stid)
{
   switch (stid)
   {
      case eSiloProbe:
         return TXT("Probe Silo");
      case eSiloCert:
         return TXT("Certificate Silo");
      case eSiloPassword:
         return TXT("Password Silo");
      case eSiloTCG:
         return TXT("TCG Silo");
      default:
         return TXT("Unknown Silo Type");
   } // switch
};

#endif // IEEE1667VALUES_DOT_H