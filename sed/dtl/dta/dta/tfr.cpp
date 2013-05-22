/*! \file tfr.cpp
    \brief Implementation of CTfr

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

//=================================
// Include files
//=================================
#include "tfr.hpp"
#include "splitjoin.hpp"

using namespace ata;

#define Split dta::Split
#define Join  dta::Join
//=================================
// macro/constant definitions
//=================================

/// Define the SMART command code, since it's used frequently.
#define SMART 0xB0

/// Default parameters for ATA_COMMAND_INFO with obsolete command codes.
#define ACI_OBSOLETE( opcode )                                   \
{ opcode, evObsolete, evObsolete, evNoProtocol, evNoAddressMode, \
  evNoDirection, evValidNone, TXT("OPCODE_") TXT(#opcode) }

/// Default parameters for ATA_COMMAND_INFO with reserved command codes.
#define ACI_RESERVED( opcode )                                   \
{ opcode, evReserved, evReserved, evNoProtocol, evNoAddressMode, \
  evNoDirection, evValidNone, TXT("OPCODE_") TXT(#opcode) }

/// Default parameters for ATA_COMMAND_INFO with retired command codes.
#define ACI_RETIRED( opcode )                                    \
{ opcode, evRetired, evRetired, evNoProtocol, evNoAddressMode,   \
  evNoDirection, evValidNone, TXT("OPCODE_") TXT(#opcode) }

/// Default parameters for ATA_COMMAND_INFO with vendor-specific command codes.
#define ACI_VENDOR( opcode )                                                 \
{ opcode, evVendorSpecific, evVendorSpecific, evNoProtocol, evNoAddressMode, \
  evNoDirection, evValidGeneralFeatureSet | evValidPacketFeatureSet,         \
  TXT("VENDOR_") TXT(#opcode) }

/// Default parameters for ATA_COMMAND_INFO with a 28-bit non-data command.
#define ACI_NONDATA( opcode, general, packet, command )          \
{ opcode, general, packet, evNonData, ev28Bit, evNoDirection,      \
  evValidAll, TXT(command) }

#define ACI_NONDATA48( opcode, general, packet, command )        \
{ opcode, general, packet, evNonData, ev48Bit, evNoDirection,      \
  evValidAll, TXT(command) }

#define ACI_PIO28IN( opcode, general, packet, command )          \
{ opcode, general, packet, evPIO, ev28Bit, evDataIn,               \
  evValidAll, TXT(command) }

#define ACI_PIO48IN( opcode, general, packet, command )          \
{ opcode, general, packet, evPIO, ev48Bit, evDataIn,               \
  evValidAll, TXT(command) }

#define ACI_DMA28IN( opcode, general, packet, command )          \
{ opcode, general, packet, evDMA, ev28Bit, evDataIn,               \
  evValidAll, TXT(command) }

#define ACI_DMA48IN( opcode, general, packet, command )          \
{ opcode, general, packet, evDMA, ev48Bit, evDataIn,               \
  evValidAll, TXT(command) }

#define ACI_DMQ28IN( opcode, general, packet, command )          \
{ opcode, general, packet, evDMAQ, ev28Bit, evDataIn,              \
  evValidAll, TXT(command) }

#define ACI_DMQ48IN( opcode, general, packet, command )          \
{ opcode, general, packet, evDMAQ, ev48Bit, evDataIn,              \
  evValidAll, TXT(command) }

#define ACI_PIO28OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evPIO, ev28Bit, evDataOut,              \
  evValidAll, TXT(command) }

#define ACI_PIO48OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evPIO, ev48Bit, evDataOut,              \
  evValidAll, TXT(command) }

#define ACI_DMA28OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evDMA, ev28Bit, evDataOut,              \
  evValidAll, TXT(command) }

#define ACI_DMA48OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evDMA, ev48Bit, evDataOut,              \
  evValidAll, TXT(command) }

#define ACI_DMQ28OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evDMAQ, ev28Bit, evDataOut,             \
  evValidAll, TXT(command) }

#define ACI_DMQ48OUT( opcode, general, packet, command )         \
{ opcode, general, packet, evDMAQ, ev48Bit, evDataOut,             \
  evValidAll, TXT(command) }

/// An enumeration of feature set settings.
enum etFeatureSet
{
   evNoFeatureSet    = ' ',   //!< Feature set unspecified
   evPacket          = 'P',   //!< Feature is in the packet feature set
   evMandatory       = 'M',   //!< Feature is mandatory
   evOptional        = 'O',   //!< Feature is optional
   evProhibited      = 'N',   //!< Feature use is prohibited
   evVendorSpecific  = 'V',   //!< Feature has vendor specific implementation
   evRetired         = 'E',   //!< Feature is retired
   evObsolete        = 'B',   //!< Feature is obsolete
   evReserved        = 'R',   //!< Feature is reserved
   evCFASpecial      = 'F'    //!< Feature is vendor specific if CFA not supported
};

/// A bitmap listing of valid fields in an ATA_COMMAND_INFO.
enum etValidCIFields
{
   evValidNone              = 0x00, //!< no fields are valid
   evValidGeneralFeatureSet = 0x01, //!< generalFeatureSet field is valid
   evValidPacketFeatureSet  = 0x02, //!< packetFeatureSet field is valid
   evValidProtocol          = 0x04, //!< protocol field is valid
   evValidAddressMode       = 0x08, //!< addressMode field is valid
   evValidDataDirection     = 0x10, //!< direction field is valid
   evValidAll               = 0x1F  //!< all fields are valid
};

//=================================
// typedefs and structures
//=================================

/// Information about ATA commands based on command codes.  This
/// definition was largely pulled from the ATA-8 specification.
typedef struct _ATA_COMMAND_INFO
{
   tUINT8          opCode;             //!< Command code
   etFeatureSet    generalFeatureSet;  //!< General feature set
   etFeatureSet    packetFeatureSet;   //!< PACKET feature set
   etProtocol      protocol;           //!< Protocol
   etAddressMode   addressMode;        //!< Argument
   etDataDirection direction;          //!< Direction of data transfer
   int             valid;              //!< Valid fields in this structure
   const TCHAR*    command;            //!< Text command description
} ATA_COMMAND_INFO;


/// A table of known ATA command information, indexed by command
/// code.  This table was generated from the appendices of ATA-8.
static const ATA_COMMAND_INFO aci8[] = {
   //
   // Command codes 0x00 to 0x0F
   //
   ACI_NONDATA( 0x00, evOptional, evMandatory, "NOP" ),
   ACI_RESERVED( 0x01 ), ACI_RESERVED( 0x02 ),
   ACI_NONDATA(  0x03, evOptional, evProhibited, "CFA REQUEST EXTENDED ERROR" ),
   ACI_RESERVED( 0x04 ), ACI_RESERVED( 0x05 ),
   ACI_RESERVED( 0x06 ), ACI_RESERVED( 0x07 ),
   { 0x08, evProhibited, evMandatory, evReset, ev28Bit,
     evNoDirection, evValidAll, TXT("DEVICE RESET") },
   ACI_RESERVED( 0x09 ), ACI_RESERVED( 0x0A ), ACI_RESERVED( 0x0B ), 
   ACI_RESERVED( 0x0C ), ACI_RESERVED( 0x0D ), ACI_RESERVED( 0x0E ),
   ACI_RESERVED( 0x0F ), 
   //
   // Command codes 0x10 to 0x1F
   //
   ACI_OBSOLETE( 0x10 ), ACI_RETIRED ( 0x11 ), 
   ACI_RETIRED ( 0x12 ), ACI_RETIRED ( 0x13 ), ACI_RETIRED ( 0x14 ),
   ACI_RETIRED ( 0x15 ), ACI_RETIRED ( 0x16 ), ACI_RETIRED ( 0x17 ), 
   ACI_RETIRED ( 0x18 ), ACI_RETIRED ( 0x19 ), ACI_RETIRED ( 0x1A ),
   ACI_RETIRED ( 0x1B ), ACI_RETIRED ( 0x1C ), ACI_RETIRED ( 0x1D ), 
   ACI_RETIRED ( 0x1E ), ACI_RETIRED ( 0x1F ),
   //
   // Command codes 0x20 to 0x2F
   //
   ACI_PIO28IN ( 0x20, evMandatory, evMandatory, "READ SECTOR(S)" ),
   ACI_OBSOLETE( 0x21 ), ACI_OBSOLETE( 0x22 ), ACI_OBSOLETE( 0x23 ),
   ACI_PIO48IN ( 0x24, evOptional, evProhibited, "READ SECTOR(S) EXT" ),
   ACI_DMA48IN ( 0x25, evOptional, evProhibited, "READ DMA EXT" ),
   ACI_DMQ48IN ( 0x26, evOptional, evProhibited, "READ DMA QUEUED EXT" ),
   ACI_NONDATA48(0x27, evOptional, evProhibited, "READ NATIVE MAX ADDRESS EXT" ),
   ACI_RESERVED( 0x28 ),
   ACI_PIO48IN ( 0x29, evOptional, evProhibited, "READ MULTIPLE EXT" ),
   ACI_DMA48IN ( 0x2A, evOptional, evProhibited, "READ STREAM DMA EXT" ),
   ACI_PIO48IN ( 0x2B, evOptional, evProhibited, "READ STREAM EXT" ),
   ACI_RESERVED( 0x2C ), ACI_RESERVED( 0x2D ), ACI_RESERVED( 0x2E ),
   ACI_PIO48IN ( 0x2F, evOptional, evOptional, "READ LOG EXT" ),
   //
   // Command codes 0x30 to 0x3F
   //
   ACI_PIO28OUT( 0x30, evMandatory, evProhibited, "WRITE SECTOR(S)" ),
   ACI_OBSOLETE( 0x31 ), ACI_OBSOLETE( 0x32 ), ACI_OBSOLETE( 0x33 ),
   ACI_PIO48OUT( 0x34, evOptional, evProhibited, "WRITE SECTOR(S) EXT" ),
   ACI_DMA48OUT( 0x35, evOptional, evProhibited, "WRITE DMA EXT" ),
   ACI_DMA48OUT( 0x36, evOptional, evProhibited, "WRITE DMA QUEUED EXT" ),
   ACI_NONDATA48(0x37, evOptional, evProhibited, "SET MAX ADDRESS EXT" ),
   ACI_PIO28OUT( 0x38, evOptional, evProhibited, "CFA WRITE SECTORS WITHOUT ERASE" ),
   ACI_PIO48OUT( 0x39, evOptional, evProhibited, "WRITE MULTIPLE EXT" ),
   ACI_DMA48OUT( 0x3A, evOptional, evProhibited, "WRITE STREAM DMA EXT" ),
   ACI_PIO48OUT( 0x3B, evOptional, evProhibited, "WRITE STREAM EXT" ),
   ACI_RESERVED( 0x3C ), 
   ACI_DMA48OUT( 0x3D, evOptional, evProhibited, "WRITE DMA FUA EXT" ), 
   ACI_DMQ48OUT( 0x3E, evOptional, evProhibited, "WRITE DMA FUA EXT" ), 
   ACI_PIO48OUT( 0x3F, evOptional, evOptional, "WRITE LOG EXT" ),
   //
   // Command codes 0x40 to 0x4F
   //
   ACI_NONDATA ( 0x40, evMandatory, evProhibited, "READ VERIFY SECTOR(S)" ),
   ACI_OBSOLETE( 0x41 ), 
   ACI_NONDATA48(0x42, evOptional, evProhibited, "READ VERIFY SECTOR(S) EXT" ),
   ACI_RESERVED( 0x43 ), ACI_RESERVED( 0x44 ),
   ACI_NONDATA48(0x45, evOptional, evProhibited, "WRITE UNCORRECTABLE EXT" ),
   ACI_RESERVED( 0x46 ),
   ACI_DMA48IN ( 0x47, evOptional, evOptional, "READ LOG DMA EXT" ),
   ACI_RESERVED( 0x48 ), ACI_RESERVED( 0x49 ), ACI_RESERVED( 0x4A ),
   ACI_RESERVED( 0x4B ), ACI_RESERVED( 0x4C ), ACI_RESERVED( 0x4D ),
   ACI_RESERVED( 0x4E ), ACI_RESERVED( 0x4F ),
   //
   // Command codes 0x50 to 0x5F
   //
   ACI_RESERVED( 0x50 ),
   ACI_NONDATA48(0x51, evOptional, evOptional, "CONFIGURE STREAM" ),
   ACI_RESERVED( 0x52 ), ACI_RESERVED( 0x53 ), ACI_RESERVED( 0x54 ),
   ACI_RESERVED( 0x55 ), ACI_RESERVED( 0x56 ),
   ACI_DMA48OUT( 0x57, evOptional, evOptional, "WRITE LOG DMA EXT" ),
   ACI_RESERVED( 0x58 ), ACI_RESERVED( 0x59 ), ACI_RESERVED( 0x5A ),
   ACI_NONDATA ( 0x5B, evOptional, evProhibited, "TRUSTED NON-DATA" ),
   ACI_PIO28IN ( 0x5C, evOptional, evProhibited, "TRUSTED RECEIVE" ),
   ACI_DMA28IN ( 0x5D, evOptional, evProhibited, "TRUSTED RECEIVE DMA" ),
   ACI_PIO28OUT( 0x5E, evOptional, evProhibited, "TRUSTED SEND" ),
   ACI_DMA28OUT( 0x5F, evOptional, evProhibited, "TRUSTED SEND DMA" ),
   //
   // Command codes 0x60 to 0x6F
   //
   ACI_DMQ48IN ( 0x60, evOptional, evProhibited, "READ FPDMA QUEUED" ),
   ACI_DMQ48OUT( 0x61, evOptional, evProhibited, "WRITE FPDMA QUEUED" ),
   ACI_RESERVED( 0x62 ), ACI_RESERVED( 0x63 ), ACI_RESERVED( 0x64 ),
   ACI_RESERVED( 0x65 ), ACI_RESERVED( 0x66 ), ACI_RESERVED( 0x67 ), 
   ACI_RESERVED( 0x68 ), ACI_RESERVED( 0x69 ), ACI_RESERVED( 0x6A ),
   ACI_RESERVED( 0x6B ), ACI_RESERVED( 0x6C ), ACI_RESERVED( 0x6D ), 
   ACI_RESERVED( 0x6E ), ACI_RESERVED( 0x6F ), 
   //
   // Command codes 0x70 to 0x7F
   //
   ACI_OBSOLETE( 0x70 ), ACI_RETIRED ( 0x71 ), 
   ACI_RETIRED ( 0x72 ), ACI_RETIRED ( 0x73 ), ACI_RETIRED ( 0x74 ),
   ACI_RETIRED ( 0x75 ), ACI_RETIRED ( 0x76 ), ACI_RETIRED ( 0x77 ), 
   ACI_RETIRED ( 0x78 ), ACI_RETIRED ( 0x79 ), ACI_RETIRED ( 0x7A ),
   ACI_RETIRED ( 0x7B ), ACI_RETIRED ( 0x7C ), ACI_RETIRED ( 0x7D ), 
   ACI_RETIRED ( 0x7E ), ACI_RETIRED ( 0x7F ),
   //
   // Command codes 0x80 to 0x8F
   //
   ACI_VENDOR  ( 0x80 ), ACI_VENDOR  ( 0x81 ), ACI_VENDOR  ( 0x82 ),
   ACI_VENDOR  ( 0x83 ), ACI_VENDOR  ( 0x84 ), ACI_VENDOR  ( 0x85 ),
   ACI_VENDOR  ( 0x86 ),
   ACI_PIO28IN ( 0x87, evOptional, evProhibited, "CFA TRANSLATE SECTOR" ),
   ACI_VENDOR  ( 0x88 ), ACI_VENDOR  ( 0x89 ), ACI_VENDOR  ( 0x8A ),
   ACI_VENDOR  ( 0x8B ), ACI_VENDOR  ( 0x8C ), ACI_VENDOR  ( 0x8D ),
   ACI_VENDOR  ( 0x8E ), ACI_VENDOR  ( 0x8F ),
   //
   // Command codes 0x90 to 0x9F
   //
   { 0x90, evMandatory, evMandatory, evDiagnostic, ev28Bit,
     evNoDirection, evValidAll, TXT("EXECUTE DEVICE DIAGNOSTIC") },
   ACI_RESERVED( 0x91 ),
   ACI_PIO28OUT( 0x92, evOptional, evProhibited, "DOWNLOAD MICROCODE" ),
   ACI_RESERVED( 0x93 ),
   ACI_RETIRED ( 0x94 ), ACI_RETIRED ( 0x95 ), ACI_RETIRED ( 0x96 ), 
   ACI_RETIRED ( 0x97 ), ACI_RETIRED ( 0x98 ), ACI_RETIRED ( 0x99 ),
   ACI_VENDOR  ( 0x9A ),
   ACI_RESERVED( 0x9B ), ACI_RESERVED( 0x9C ), ACI_RESERVED( 0x9D ),
   ACI_RESERVED( 0x9E ), ACI_RESERVED( 0x9F ),
   //
   // Command codes 0xA0 to 0xAF
   //
   { 0xA0, evProhibited, evMandatory, evNoProtocol, 
     evNoAddressMode, evNoDirection, 
     evValidGeneralFeatureSet | evValidPacketFeatureSet, TXT("PACKET") },
   ACI_PIO28IN ( 0xA1, evProhibited, evMandatory, "IDENTIFY PACKET DEVICE" ),
   { 0xA2, evOptional, evOptional, evNoProtocol, evNoAddressMode,
     evNoDirection, evValidNone, TXT("SERVICE") },
   ACI_RESERVED( 0xA3 ), ACI_RESERVED( 0xA4 ), ACI_RESERVED( 0xA5 ),
   ACI_RESERVED( 0xA6 ), ACI_RESERVED( 0xA7 ), ACI_RESERVED( 0xA8 ),
   ACI_RESERVED( 0xA9 ), ACI_RESERVED( 0xAA ), ACI_RESERVED( 0xAB ),
   ACI_RESERVED( 0xAC ), ACI_RESERVED( 0xAD ), ACI_RESERVED( 0xAE ),
   ACI_RESERVED( 0xAF ), 
   //
   // Command codes SMART to 0xBF
   //
   { SMART, evOptional, evProhibited, evNoProtocol, 
     evNoAddressMode, evNoDirection, 
     evValidGeneralFeatureSet | evValidPacketFeatureSet, TXT("SMART") },
   ACI_NONDATA ( 0xB1, evOptional, evOptional, "Device Configuration Overlay" ),
   ACI_RESERVED( 0xB2 ), ACI_RESERVED( 0xB3 ), 
   ACI_NONDATA48( 0xB4, evOptional, evOptional, "Sanitize Device"),
   ACI_RESERVED( 0xB5 ),
   { 0xB6, evOptional, evProhibited, evNoProtocol, 
     ev48Bit, evNoDirection, evValidGeneralFeatureSet | 
     evValidPacketFeatureSet | evValidDataDirection | evValidAddressMode, TXT("SMART") },
   ACI_RESERVED( 0xB7 ), ACI_RESERVED( 0xB8 ), ACI_RESERVED( 0xB9 ), 
   ACI_RESERVED( 0xBA ), ACI_RESERVED( 0xBB ), ACI_RESERVED( 0xBC ), 
   ACI_RESERVED( 0xBD ), ACI_RESERVED( 0xBE ), ACI_RESERVED( 0xBF ), 
   //
   // Command codes 0xC0 to 0xCF
   //
   ACI_NONDATA ( 0xC0, evCFASpecial, evProhibited, "CFA ERASE SECTORS" ),
   ACI_VENDOR  ( 0xC1 ), ACI_VENDOR  ( 0xC2 ), ACI_VENDOR  ( 0xC3 ),
   ACI_PIO28IN ( 0xC4, evMandatory, evProhibited, "READ MULTIPLE" ),
   ACI_PIO28OUT( 0xC5, evMandatory, evProhibited, "WRITE MULTIPLE" ),
   ACI_NONDATA ( 0xC6, evMandatory, evProhibited, "SET MULTIPLE MODE" ),
   ACI_DMQ28IN ( 0xC7, evOptional,  evProhibited, "READ DMA QUEUED" ),
   ACI_DMA28IN ( 0xC7, evMandatory, evProhibited, "READ DMA" ),
   ACI_OBSOLETE( 0xC9 ),
   ACI_DMA28OUT( 0xCA, evMandatory, evProhibited, "WRITE DMA" ),
   ACI_OBSOLETE( 0xCB ),
   ACI_DMQ28OUT( 0xCC, evOptional, evProhibited, "WRITE DMA QUEUED" ),
   ACI_PIO28OUT( 0xCD, evOptional, evProhibited, "CFA WRITE MULTIPLE WITHOUT ERASE" ),
   ACI_PIO48OUT( 0xCE, evOptional, evProhibited, "WRITE MULTIPLE FUA EXT" ),
   ACI_RESERVED( 0xCF ),
   //
   // Command codes 0xD0 to 0xDF
   //
   ACI_RESERVED( 0xD0 ),
   ACI_NONDATA ( 0xD1, evOptional, evProhibited, "CHECK MEDIA CARD TYPE" ),
   ACI_RESERVED( 0xD2 ), ACI_RESERVED( 0xD3 ), ACI_RESERVED( 0xD4 ),
   ACI_RESERVED( 0xD5 ), ACI_RESERVED( 0xD6 ), ACI_RESERVED( 0xD7 ),
   ACI_RESERVED( 0xD8 ), ACI_RESERVED( 0xD9 ), ACI_OBSOLETE( 0xDA ),
   ACI_RETIRED ( 0xDB ), ACI_RETIRED ( 0xDC ), ACI_RETIRED ( 0xDD ),
   ACI_OBSOLETE( 0xDE ), ACI_OBSOLETE( 0xDF ),
   //
   // Command codes 0xE0 to 0xEF
   //
   ACI_NONDATA ( 0xE0, evMandatory, evMandatory, "STANDBY IMMEDIATE" ),
   ACI_NONDATA ( 0xE1, evMandatory, evMandatory, "IDLE IMMEDIATE" ),
   ACI_NONDATA ( 0xE2, evMandatory, evOptional,  "STANDBY" ),
   ACI_NONDATA ( 0xE3, evMandatory, evOptional,  "IDLE" ),
   ACI_PIO28IN ( 0xE4, evOptional, evProhibited, "READ BUFFER" ),
   ACI_NONDATA ( 0xE5, evMandatory, evMandatory, "CHECK POWER MODE" ),
   ACI_NONDATA ( 0xE6, evMandatory, evMandatory, "SLEEP" ),
   ACI_NONDATA ( 0xE7, evMandatory, evOptional,  "FLUSH CACHE" ),
   ACI_PIO28OUT( 0xE8, evOptional, evProhibited, "WRITE BUFFER" ),
   ACI_RETIRED ( 0xE9 ),
   ACI_NONDATA48(0xEA, evOptional, evProhibited,  "FLUSH CACHE EXT" ),
   ACI_RESERVED( 0xEB ),
   ACI_PIO28IN ( 0xEC, evMandatory, evMandatory, "IDENTIFY DEVICE" ),
   ACI_OBSOLETE( 0xED ), ACI_OBSOLETE( 0xEE ),
   ACI_NONDATA ( 0xEF, evMandatory, evMandatory, "SET FEATURES" ),
   //
   // Command codes 0xF0 to 0xFF
   //
   ACI_VENDOR  ( 0xF0 ),
   ACI_PIO28OUT( 0xF1, evOptional, evOptional, "SECURITY SET PASSWORD" ),
   ACI_PIO28OUT( 0xF2, evOptional, evOptional, "SECURITY UNLOCK" ),
   ACI_NONDATA ( 0xF3, evOptional, evOptional, "SECURITY ERASE PREPARE" ),
   ACI_PIO28OUT( 0xF4, evOptional, evOptional, "SECURITY ERASE UNIT" ),
   ACI_NONDATA ( 0xF5, evOptional, evOptional, "SECURITY FREEZE LOCK" ),
   ACI_PIO28OUT( 0xF6, evOptional, evOptional, "SECURITY DISABLE PASSWORD" ),
   ACI_VENDOR  ( 0xF7 ),
   ACI_NONDATA ( 0xF8, evOptional, evOptional, "READ NATIVE MAX ADDRESS" ),
   ACI_NONDATA ( 0xF9, evOptional, evOptional, "SET MAX ADDRESS" ),
   ACI_VENDOR  ( 0xFA ), ACI_VENDOR  ( 0xFB ), ACI_VENDOR  ( 0xFC ),
   ACI_VENDOR  ( 0xFD ), ACI_VENDOR  ( 0xFE ), ACI_VENDOR  ( 0xFF )
};

/// A table of known ATA SMART command information, indexed by 
/// feature - 0xD0.  This table was generated from ATA-8.
static const ATA_COMMAND_INFO aci8Smart[] = {
   ACI_PIO28IN ( SMART, evOptional, evProhibited, "SMART READ DATA" ),
   ACI_OBSOLETE( SMART ),   //  B0/D1
   ACI_NONDATA( SMART, evOptional, evProhibited, 
      "SMART ENABLE/DISABLE ATTRIBUTE AUTOSAVE" ),
   ACI_OBSOLETE( SMART ),   //  B0/D3
   ACI_NONDATA ( SMART, evOptional, evProhibited, 
      "SMART EXECUTE OFF-LINE IMMEDIATE" ),
   ACI_PIO28IN ( SMART, evOptional, evProhibited, "SMART READ LOG" ),
   ACI_PIO28OUT( SMART, evOptional, evProhibited, "SMART WRITE LOG" ),
   ACI_OBSOLETE( SMART ),   //  B0/D7
   ACI_NONDATA ( SMART, evOptional, evProhibited, "SMART ENABLE OPERATIONS" ),
   ACI_NONDATA ( SMART, evOptional, evProhibited, "SMART DISABLE OPERATIONS" ),
   ACI_NONDATA ( SMART, evOptional, evProhibited, "SMART RETURN STATUS" ),
   ACI_OBSOLETE( SMART ),   //  B0/DB
   // Vendor specific B0/E0 to B0/EF
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   // Vendor specific B0/F0 to B0/FF
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
   ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),ACI_VENDOR(SMART),
};

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================
//================================================================
CTfr::CTfr( etAddressMode addressMode )
{
   Initialize( addressMode );
}

//================================================================
void CTfr::Initialize( etAddressMode addressMode )
{
   m_addressingMode = addressMode;
}

//================================================================
etAddressMode CTfr::GetAddressMode() const
{
   return m_addressingMode;
}

//================================================================
tUINT64 CTfr::GetLBA() const
{
   tUINT64 result = 0;

   // LBA mode only works if the device/head register has the
   // LBA bit set.  Make sure that it's set properly.
   tUINT8 devHead = GetDeviceHead();
   if (!( devHead & 0x40 ))
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   tUINT8 bits40to47(0), bits32to39(0), bits24to31(0),
          bits16to23(0), bits8to15(0),  bits0to7(0);

   switch ( GetAddressMode() )
   {
   case ev28Bit:
      bits24to31 = (devHead & 0x0F);
      bits16to23 = static_cast<tUINT8>(GetLBAHigh());
      bits8to15  = static_cast<tUINT8>(GetLBAMid());
      bits0to7   = static_cast<tUINT8>(GetLBALow());
      break;
   case ev48Bit:
      Split( bits40to47, bits16to23, GetLBAHigh());
      Split( bits32to39, bits8to15,  GetLBAMid() );
      Split( bits24to31, bits0to7,   GetLBALow() );
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }

   const tUINT8 unused( 0 );
   result = Join(
      Join( unused, unused, bits40to47, bits32to39 ),
      Join( bits24to31, bits16to23, bits8to15, bits0to7 )
      );
   return result;
}

//================================================================
void CTfr::SetLBA( tUINT64 lba )
{
   // LBA mode only works if the device/head register has the
   // LBA bit set.  Make sure that it's set properly.
   tUINT8 devHead = GetDeviceHead();
   if (!( devHead & 0x40 ))
   {
      devHead |= 0x40;
      SetDeviceHead( devHead );
   }

   tUINT8 bits40to47, bits32to39, bits24to31,
          bits16to23, bits8to15,  bits0to7;

   // These braces just provide scope for high32, low32, unused.
   {
      tUINT8 unused;
      tUINT32 high32, low32;
      Split( high32, low32, lba );
      Split( unused,     unused,     bits40to47, bits32to39, high32 );
      Split( bits24to31, bits16to23, bits8to15,  bits0to7,   low32 );
   }

   switch ( GetAddressMode() )
   {
   case ev28Bit:
      if ( 0x0FFFFFFF < lba )
      {
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      else
      {
         SetLBALow( bits0to7 );
         SetLBAMid( bits8to15 );
         SetLBAHigh( bits16to23 );
         // Mask in the high-order bits of dev/head.  We
         // know the high-order bits of bits24to31 are already
         // zero because of the 'if' check above.
         bits24to31 |= ( 0xF0 & devHead );
         SetDeviceHead( bits24to31 );
      }
      break;
   case ev48Bit:
      if ( 0x0FFFFFFFFFFFF < lba )
      {
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      else
      {
         SetLBALow(  Join(bits24to31, bits0to7   ) );
         SetLBAMid(  Join(bits32to39, bits8to15  ) );
         SetLBAHigh( Join(bits40to47, bits16to23 ) );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfr::InitCommand( tUINT8 command )
{
   // Default to 28-bit, unless found otherwise.
   ata::etAddressMode mode = ev28Bit;

   if ( aci8[command].valid & evValidAddressMode &&
        aci8[command].addressMode  == ev48Bit )
   {
      mode = ev48Bit;
   }
   Initialize( mode );
   SetCommandStatus( command );
}

//================================================================
void* CTfr::Prepare( 
   dta::tBytes& buffer,
   size_t &timeout,
   etProtocol &protocol,
   etDataDirection &direction
   )
{
   const ATA_COMMAND_INFO *aci;
   tUINT8 cmd = GetCommandStatus();
   aci = &aci8[ cmd ];

   // Special case : SMART (uses FEATURE register )
   if ( SMART == cmd )
   {
      tUINT16 feat = GetErrorFeature();
      if ( feat >= 0xD0 && feat <= 0xFF )
      {
         aci = &aci8Smart[ feat - 0xD0 ];
      }
   }

   // If a protocol was not specified, look up a default value.
   if ((evNoProtocol == protocol)      &&
       (evValidProtocol & aci->valid)  &&
       (aci->protocol != evNoProtocol) )
   {
      protocol = aci->protocol;
   }

   // If a data direction was not specified, look up a default value.
   if ((evNoDirection == direction)        &&
       (evValidDataDirection & aci->valid) &&
       (aci->direction != evNoDirection)   )
   {
      direction = aci->direction;
   }

   //
   // Assigning defaults is complete.  Now validate that
   // what parameters we know are valid.
   //

   if ( evNoAddressMode == GetAddressMode() )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   switch( protocol )
   {
   case evNoProtocol:
      throw dta::Error( dta::eGenericInvalidParameter );
      break;
   case evNonData:
      if ( evNoDirection != direction )
      {
         // A non-data command has a data direction.
         // Something is wrong.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   case evPIO:
      if ( evNoDirection == direction )
      {
         // A PIO command has no direction.  Something is wrong.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   case evDMA:
   case evDMAQ:
      if ( evNoDirection == direction )
      {
         // A DMA command has no direction.  Something is wrong.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   case evReset:
   case evDiagnostic:
   case evPacket:
   case evVendor:
      if ( evNoDirection != direction )
      {
         // A data-less command has a data direction.
         // Something is wrong.  I'm not even sure these
         // commands will go through ATA pass-through.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   }

   if ( evNoDirection != direction && 0 == buffer.size() )
   {
      // We need a data buffer, but don't have one.
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   return CompletePrepare( buffer, timeout, protocol, direction );
}

