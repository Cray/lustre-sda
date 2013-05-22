/*! \file tptr.hpp
    \brief Header file for common automatic pointer classes.
    
    This file provides a basic include point for DTA macros,
    typedefs, and classes.

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

#ifndef DTA_TPTR_DOT_H
#define DTA_TPTR_DOT_H
//=================================
// Include files
//=================================
#include "common.h"

#ifndef __cplusplus
#error "C++ support required for tptr.h"
#endif // ifndef __cplusplus

//=================================
// Macro definitions
//=================================

//=================================
// typedefs and structures
//=================================

//
/// \brief Template class for auto Pointer
/// 
/// TODO: Document tPtr
//
template < class T >
class tPtr
{
public:
   T    *p;       //< raw data pointer
   size_t alloc;  //< allocation size
   size_t len;    //< size of valid data in bytes

   /*
   \brief Template class for auto Pointer
   */ 
   tPtr() : p(0), alloc(0), len(0) {}
   tPtr( T* ptr, size_t ptrAlloc, size_t ptrLen=0 )
      : p(ptr), alloc(ptrAlloc), len(ptrLen) {}
   tPtr( const tPtr& two )
      : p(two.p), alloc(two.alloc), len(two.len) {}
   operator T*() const { return p; }
};

// nvn20110629 - for GCC, to access template base class members, use:
// this-> (recommended - why: implicitly dependent) is needed, or
// tPtr<T> (not recommended - why: virtual dispatch, if member virtual)

/* 
 \brief Template class auto-allocating (and freeing)
 * of memory arrays.
 *
 * tAllocPtr uses malloc, realloc, and free to manage
 * memory.  As a result, it is not suitable for complex
 * types ( e.g. classes ).
 */
template < class T >
class tAllocPtr : public tPtr<T>
{
public:
   /* 
   \brief Template class auto-allocating (and freeing)
   * of memory arrays.
   *
   * tAllocPtr uses malloc, realloc, and free to manage
   * memory.  As a result, it is not suitable for complex
   * types ( e.g. classes ).
   */
   tAllocPtr( size_t entries ) : tPtr<T>()
   {
      if ( entries )
      {
    	 this->p = (T*)::malloc( entries * sizeof(T) );
         this->alloc = entries;
      }
   }
   bool realloc( size_t entries )
   {
      this->p = (T*)::realloc( this->p, entries * sizeof(T) );
      this->alloc = entries;
      return NULL != this->p;
   }
   ~tAllocPtr()
   {
      if (this->p) ::free(this->p);
   }
};

/* 
 \brief Template class tVarlenStruct auto-allocating (and freeing) variable-length 
 *  structures, where a structure is followed by zero or more bytes of data.
 *
 *  tVarLenStruct
 */
template < class T >
class tVarLenStruct : public tPtr<T>
{
public:
   /* 
   \brief Template class auto-allocating (and freeing) variable-length 
      structures, where a structure is followed by zero or more bytes of data.

      tVarLenStruct uses malloc, realloc, and free to manage
      memory.  As a result, it is not suitable for complex types ( e.g. classes ).
   */
   tVarLenStruct( size_t bytes=0 ) : tPtr<T>()
   {
      bytes += sizeof(T);
      tUINT8* temp = (tUINT8*)::malloc(bytes);
      this->p = (T*)temp;
      p2 = temp + sizeof(T);
      this->alloc = bytes;
   }
   bool realloc( size_t bytes )
   {
      bytes += sizeof(T);
      tUINT8* temp = (tUINT8*)::realloc(this->p, bytes);
      this->p = (T*)temp;
      p2 = temp + sizeof(T);
      this->alloc = bytes;
      return NULL != this->p;
   }
   ~tVarLenStruct()
   {
      if (this->p) ::free(this->p);
   }
   tUINT8* p2;
};

#endif // DTA_TPTR_DOT_H