/*! \file byteorder.hpp
    \brief Defines the CByteOrder class.

    This file contains the class definition for ByteOrder, which will convert
    values to Big-endian format, if needed, depending on the host's orientation.
    
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

#ifndef BYTEORDER_DOT_HPP
#define BYTEORDER_DOT_HPP

//=================================
// Include files
//=================================
#include <dta/common.h>

//=================================
// class definitions
//=================================
class CByteOrder {
private:
   tBOOL m_HostOrderIsNetOrder;

   // ByteSwap a 64 bit value
   virtual tUINT64 BSwap(tUINT64 val) const
   {
      return (tUINT64)(
                       ((val & 0x00000000000000FFULL) << 56) |
                       ((val & 0x000000000000FF00ULL) << 40) |
                       ((val & 0x0000000000FF0000ULL) << 24) |
                       ((val & 0x00000000FF000000ULL) <<  8) |
                       ((val & 0x000000FF00000000ULL) >>  8) |
                       ((val & 0x0000FF0000000000ULL) >> 24) |
                       ((val & 0x00FF000000000000ULL) >> 40) |
                       ((val & 0xFF00000000000000ULL) >> 56)
                       );
   }

   // ByteSwap a 32 bit value
   virtual tUINT32 BSwap(tUINT32 val) const
   {
      return (tUINT32)(
                       ((val & 0x000000FF) << 24) |
                       ((val & 0x0000FF00) <<  8) |
                       ((val & 0x00FF0000) >>  8) |
                       ((val & 0xFF000000) >> 24)
                       );
   }

   // ByteSwap a 16 bit value
   virtual tUINT16 BSwap(tUINT16 val) const
   {
      return (tUINT16)( ((val & 0x00FF) << 8) | ((val & 0xFF00) >> 8) );
   }

public:
   CByteOrder(void)
   {
      m_HostOrderIsNetOrder = false;
      union tEndCheck
      {
         tUINT16 Word;
         tUINT8 Bytes[2];
      };

      tEndCheck ec;
      ec.Word = 0x1234;
      if( ec.Word == ( (tUINT16)((tUINT16)(ec.Bytes[0] << 8) | ec.Bytes[1]) ) )
      {
         m_HostOrderIsNetOrder = true;
      }
   };
   virtual ~CByteOrder(void) {}

   // Correct byte order of 64 bit value for transmission
   virtual tUINT64 HostToNet(tUINT64 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }

   // Correct byte order of 64 bit value after reception
   virtual tUINT64 NetToHost(tUINT64 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }

   // Correct byte order of 32 bit value for transmission
   virtual tUINT32 HostToNet(tUINT32 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }

   // Correct byte order of 32 bit value after reception
   virtual tUINT32 NetToHost(tUINT32 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }

   // Correct byte order of 32 bit value for transmission
   virtual tUINT16 HostToNet(tUINT16 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }

   // Correct byte order of 32 bit value after reception
   virtual tUINT16 NetToHost(tUINT16 val) const
   { return (m_HostOrderIsNetOrder ? val : BSwap(val)) ; }
};


#endif // BYTEORDER_DOT_HPP