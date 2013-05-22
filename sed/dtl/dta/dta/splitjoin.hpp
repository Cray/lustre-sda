/*! \file splitjoin.hpp
    \brief Definition of helpful functions to split and join integral
      numeric types.

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

#ifndef DTA_SPLIT_JOIN_HPP
#define DTA_SPLIT_JOIN_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dta.hpp"
#include <assert.h>

//=================================
// macro definitions
//=================================
namespace dta {

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

//=================================
// function definitions
//=================================
/// Split one variable in half, placing data into two variables.
template < class DEST, class SRC > void Split ( DEST &high, DEST &low, SRC src )
{
   const size_t shiftSize = sizeof(DEST) * 8;
   assert ( sizeof(SRC) == (2 * sizeof(DEST)) );
   low = static_cast<DEST>(src);
   src >>= shiftSize;
   high = static_cast<DEST>(src);
}

/// Split one variable in quarters, placing data into four variables.
template < class DEST, class SRC > void Split ( 
   DEST &highest,
   DEST &high, 
   DEST &low, 
   DEST &lowest,
   SRC src 
   )
{
   const size_t shiftSize = sizeof(DEST) * 8;
   assert ( sizeof(SRC) == (4 * sizeof(DEST)) );
   lowest = static_cast<DEST>(src);
   src >>= shiftSize;
   low = static_cast<DEST>(src);
   src >>= shiftSize;
   high = static_cast<DEST>(src);
   src >>= shiftSize;
   highest = static_cast<DEST>(src);
}

/// Join two variables, placing the result into one variable.
template < class DEST, class SRC > DEST Join( SRC high, SRC low )
{
   const size_t shiftSize = sizeof(SRC) * 8;
   assert ( sizeof(DEST) == (2 * sizeof(SRC)) );
   DEST result = high;
   result <<= shiftSize;
   result |= low;
   return result;
}

/// Join four variables, placing the result into one variable.
template < class DEST, class SRC > DEST Join( 
   SRC highest, 
   SRC high,
   SRC low,
   SRC lowest
   )
{
   const size_t shiftSize = sizeof(SRC) * 8;
   assert ( sizeof(DEST) == (4 * sizeof(SRC)) );
   DEST result = highest;
   result <<= shiftSize;
   result |= high;
   result <<= shiftSize;
   result |= low;
   result <<= shiftSize;
   result |= lowest;
   return result;
}

/// Macro to establish Join() prototypes for known compatible type sizes.
#define DEFINE_JOIN_4( dType, sType )                                   \
inline dType Join( sType highest, sType high, sType low, sType lowest ) \
{                                                                       \
   return Join<dType>(highest, high, low, lowest);                      \
}

/// Macro to establish Join() prototypes for known compatible type sizes.
#define DEFINE_JOIN_2( dType, sType )                                   \
inline dType Join( sType high, sType low )                              \
{                                                                       \
   return Join<dType>(high, low );                                      \
}

/// Macro to create inline function for known valid Join() types.
DEFINE_JOIN_4( tUINT32, tUINT8 )
/// Macro to create inline function for known valid Join() types.
DEFINE_JOIN_4( tUINT64, tUINT16 )

/// Macro to create inline function for known valid Join() types.
DEFINE_JOIN_2( tUINT16, tUINT8  )
/// Macro to create inline function for known valid Join() types.
DEFINE_JOIN_2( tUINT32, tUINT16 )
/// Macro to create inline function for known valid Join() types.
DEFINE_JOIN_2( tUINT64, tUINT32 )

}  // end namespace dta
#endif // DTA_SPLIT_JOIN_HPP
