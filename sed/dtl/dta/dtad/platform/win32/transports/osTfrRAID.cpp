/*! \file osTfrRAID.cpp
    \brief Windows-specific implementation of COSLocalSystemObject.

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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
#include "osTfrRAID.hpp"
#include <dta/splitjoin.hpp>

using namespace dtad;
using namespace ata;

//=================================
// macro/constant definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

//================================================================
CTfrRAID::CTfrRAID( etAddressMode addressMode )
: CTfr( addressMode )
{
   CTfr::Initialize( addressMode );
}

//================================================================
CTfrRAID::~CTfrRAID()
{
}

//================================================================
void CTfrRAID::Initialize( ata::etAddressMode addressMode )
{
   CTfr::Initialize( addressMode );

   // Now, initialize the ATA_PASS_THROUGH_DIRECT structure.
   ZeroMemory( &m_aptd, sizeof(m_aptd) );
   m_aptd.Length = sizeof(m_aptd);

   m_curRegs  = PIDEREGS( m_aptd.CurrentTaskFile );
   m_prevRegs = PIDEREGS( m_aptd.PreviousTaskFile );

}

//================================================================
tUINT8 CTfrRAID::GetCommandStatus() const
{
   return m_curRegs->bCommandReg;
}

//================================================================
tUINT16 CTfrRAID::GetErrorFeature() const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ev48Bit:
      result = dta::Join( m_prevRegs->bFeaturesReg,
                           m_curRegs->bFeaturesReg );
      break;
   case ev28Bit:
      result = m_curRegs->bFeaturesReg;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 CTfrRAID::GetLBALow() const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ev48Bit:
      result = dta::Join( m_prevRegs->bSectorNumberReg,
                           m_curRegs->bSectorNumberReg );
      break;
   case ev28Bit:
      result = m_curRegs->bSectorNumberReg;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 CTfrRAID::GetLBAMid() const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ev48Bit:
      result = dta::Join( m_prevRegs->bCylLowReg,
                           m_curRegs->bCylLowReg );
      break;
   case ev28Bit:
      result = m_curRegs->bCylLowReg;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 CTfrRAID::GetLBAHigh() const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ev48Bit:
      result = dta::Join( m_prevRegs->bCylHighReg,
                           m_curRegs->bCylHighReg );
      break;
   case ev28Bit:
      result = m_curRegs->bCylHighReg;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 CTfrRAID::GetSectorCount() const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ev48Bit:
      result = dta::Join( m_prevRegs->bSectorCountReg,
                           m_curRegs->bSectorCountReg );
      break;
   case ev28Bit:
      result = m_curRegs->bSectorCountReg;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT8 CTfrRAID::GetDeviceHead() const
{
   return m_curRegs->bDriveHeadReg;
}

//================================================================
void CTfrRAID::SetCommandStatus( tUINT8 value )
{
   m_curRegs->bCommandReg = value;
}

//================================================================
void CTfrRAID::SetErrorFeature( tUINT16 value )
{
   dta::Split( m_prevRegs->bFeaturesReg, 
                m_curRegs->bFeaturesReg, value );

   switch ( GetAddressMode() )
   {
   case ev48Bit:
      break;
   case ev28Bit:
      if ( 0 != m_prevRegs->bFeaturesReg )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfrRAID::SetLBALow( tUINT16 value )
{
   dta::Split( m_prevRegs->bSectorNumberReg, 
                m_curRegs->bSectorNumberReg, value );

   switch ( GetAddressMode() )
   {
   case ev48Bit:
      break;
   case ev28Bit:
      if ( 0 != m_prevRegs->bSectorNumberReg )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfrRAID::SetLBAMid( tUINT16 value )
{
   dta::Split( m_prevRegs->bCylLowReg, 
                m_curRegs->bCylLowReg, value );

   switch ( GetAddressMode() )
   {
   case ev48Bit:
      break;
   case ev28Bit:
      if ( 0 != m_prevRegs->bCylLowReg )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfrRAID::SetLBAHigh( tUINT16 value )
{
   dta::Split( m_prevRegs->bCylHighReg, 
                m_curRegs->bCylHighReg, value );

   switch ( GetAddressMode() )
   {
   case ev48Bit:
      break;
   case ev28Bit:
      if ( 0 != m_prevRegs->bCylHighReg )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfrRAID::SetSectorCount( tUINT16 value )
{
   dta::Split( m_prevRegs->bSectorCountReg, 
                m_curRegs->bSectorCountReg, value );

   switch ( GetAddressMode() )
   {
   case ev48Bit:
      break;
   case ev28Bit:
      if ( 0 != m_prevRegs->bSectorCountReg )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void CTfrRAID::SetDeviceHead( tUINT8 value )
{
   m_curRegs->bDriveHeadReg = value;
}

//================================================================
void* CTfrRAID::CompletePrepare( 
   dta::tBytes& buffer,
   size_t &timeout,
   etProtocol &protocol,
   etDataDirection &direction
   )
{

   bool testBufferExists = false;
   const ULONG maxULONG = -1;
   if ( static_cast<size_t>(maxULONG) < buffer.size() )
   {
      // Value too large!
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   if ( static_cast<size_t>(maxULONG) < timeout )
   {
      // Value too large!
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   m_aptd.DataBuffer         = buffer.size() ? &buffer[0] : NULL;
   m_aptd.DataTransferLength = (ULONG)buffer.size();
   m_aptd.TimeOutValue       = (ULONG)timeout;

   return &m_aptd;
}

