/*! \file TfrSAT.hpp
    \brief  Implementation of CDriveTrustSession via the ATA 
            pass-through transport.

    TODO : Detailed description
    
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

#ifndef TFR_SAT12_HPP
#define TFR_SAT12_HPP

//=================================
// Include files
//=================================
#include <dta/Ata.hpp>

namespace sat {
//=================================
// macro definitions
//=================================

//=================================
// constants and enumerations
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief helper class used to get/set TFRs embedded in
///      a 12 or 16 byte CDB as defined in SAT.
///
/// This class provides accessor methods to more easily set
/// values in an ATA PASS-THROUGH() command as specified
/// in the SAT-2 specification (Revision 01a).
///
class CTfr : public ata::CTfr
{
public:
   //================================================================
   //
   /// Constructor.  This constructor automatically calls Initialize
   ///      to set up the tfr for a new command.
   ///
   /// \param addressMode  Should be set to the addressing mode
   ///      for this command.
   //
   //================================================================
   CTfr( ata::etAddressMode addressMode );

   /// Virtual destructor.
   virtual ~CTfr();

   //================================================================
   // Implementations of methods defined in ata::CTfr
   //================================================================
   virtual void* CompletePrepare( 
      dta::tBytes& buffer,
      size_t &timeout,
      ata::etProtocol &protocol,
      ata::etDataDirection &direction
      );

   virtual void Initialize( ata::etAddressMode );

   virtual tUINT8 GetCommandStatus() const ;
   virtual tUINT16 GetErrorFeature() const ;
   virtual tUINT16 GetLBALow() const ;
   virtual tUINT16 GetLBAMid() const ;
   virtual tUINT16 GetLBAHigh() const ;
   virtual tUINT16 GetSectorCount() const ;
   virtual tUINT8 GetDeviceHead() const ;

   virtual void SetCommandStatus( tUINT8 value ) ;
   virtual void SetErrorFeature( tUINT16 value ) ;
   virtual void SetLBALow( tUINT16 value ) ;
   virtual void SetLBAMid( tUINT16 value ) ;
   virtual void SetLBAHigh( tUINT16 value ) ;
   virtual void SetSectorCount( tUINT16 value ) ;
   virtual void SetDeviceHead( tUINT8 value ) ;

protected:  // Helper methods
   //================================================================
   //
   /// Set the CDB byte for an 8-bit TFR.
   ///
   /// \param value  The value of the TFR to be placed.
   ///
   /// \param index48  The index to the byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param index28  The index to the byte in the
   ///      TFR for 28-bit commands.
   ///
   /// \return None.
   //
   //================================================================
   void SetTFRValue( tUINT8 value, tUINT8 index48, tUINT8 index28 );

   //================================================================
   //
   /// Get the CDB byte for an 8-bit TFR.
   ///
   /// \param index48  The index to the byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param index28  The index to the byte in the
   ///      TFR for 28-bit commands.
   ///
   /// \return The value of the appropriate TFR byte.
   //
   //================================================================
   tUINT8 GetTFRValue( tUINT8 index48, tUINT8 index28 ) const;

   //================================================================
   //
   /// Set one or two CDB bytes for a 16-bit TFR.
   ///
   /// \param value  The value of the TFR to be split as appropriate.
   ///
   /// \param highIndex  The index to the high-order byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param lowIndex  The index to the low-order byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param index  The index to the byte in the
   ///      TFR for 28-bit commands.
   ///
   /// \return None.
   //
   //================================================================
   void SetTFRValue( tUINT16 value, tUINT8 highIndex, 
      tUINT8 lowIndex, tUINT8 index );

   //================================================================
   //
   /// Get the CDB byte(s) for a 16-bit TFR as a 16-bit value.
   ///
   /// \param highIndex  The index to the high-order byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param lowIndex  The index to the low-order byte in the
   ///      TFR for 48-bit commands.
   ///
   /// \param index  The index to the byte in the
   ///      TFR for 28-bit commands.
   ///
   /// \return The value of the appropriate TFR byte(s).
   //
   //================================================================
   tUINT16 GetTFRValue( tUINT8 highIndex, tUINT8 lowIndex, tUINT8 index ) const;

protected:
   tUINT8 m_cdb[16];
};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // TFR_SAT12_HPP
