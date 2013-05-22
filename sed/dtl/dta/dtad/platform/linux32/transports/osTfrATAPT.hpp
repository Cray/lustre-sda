/*! \file osTfrATAPT.hpp
    \brief  Implementation of CDriveTrustSession via the ATA 
            pass-through transport.

    TODO : Detailed description
    
    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.� No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee.�

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright � 2008.� Seagate Technology LLC �All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.

*/

#ifndef XPORT_TFR_ATA_PASS_THROUGH_HPP
#define XPORT_TFR_ATA_PASS_THROUGH_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include <dta/Ata.hpp>
//#include <dta/platform/win32/OSIncludes.h> // nvn20110622
#include "LinuxIncludes.h" // nvn20110629

namespace dtad {
//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief Class representing a set of task file registers
///      for Windows pass-through.
//
class CTfrATAPT : public ata::CTfr
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
   CTfrATAPT( ata::etAddressMode addressMode );

   /// Virtual destructor.
   virtual ~CTfrATAPT();

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

   //================================================================
protected:
   ATA_PASS_THROUGH_DIRECT m_aptd;  //!< Windows structure for pass-through //TODO: // nvn20110623 - win ddk specific
   //PIDEREGS m_curRegs;              //!< Pointer in m_aptd to current task files
   //PIDEREGS m_prevRegs;             //!< Pointer in m_aptd to previous task files
};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // XPORT_TFR_ATA_PASS_THROUGH_HPP
