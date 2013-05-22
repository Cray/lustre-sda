/*! \file rcarray.h
    \brief Template class that safely deals with reference counted arrays
           of data types.
           
    This class is safe and relatively inexpensive to copy, and 
    has the ability to be sub-divided as necessary for "sub-arrays"
    within the array.

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

#ifndef __RCARRAY_DOT_H__
#define __RCARRAY_DOT_H__
//=================================
// Include files
//=================================

//=================================
// Constant definitions
//=================================
#define NULL   0
//=================================
// Static and external variables
//=================================

//=================================
// Structures and type definitions
//=================================

//=================================
// Class definitions
//=================================
/// A simple inline class to hold array information for 
/// owned data pointers.  It does contain the reference 
/// count information but does no allocation or freeing
/// on its own.
class CRefCountPtr 
{
public:
   /// Increment the reference count.
   /// Returns the new reference count.
   size_t IncRef() { return ++m_refCount; }
   /// Decrement the reference count.
   /// Returns the new reference count.
   size_t DecRef();
   /// Returns the number of elements in the array.
   /// This can be zero if not allocated.
   size_t Size() const { return m_bytes; }
   // Constructor.  
   CRefCountPtr( void* ptr, size_t bytes )
      : m_ptr( (char*)ptr )
      , m_bytes( bytes )
      , m_refCount(1) {}
   // Template function to make casting easy.
   template < class T >
      T* Begin() const { return (T*)m_ptr; }
   // Template function to make casting easy.
   template < class T >
      T* End() const { return (T*)(m_ptr + m_bytes); }
protected:
   // Member var storage below!
   char  *m_ptr;
   size_t m_bytes;
   size_t m_refCount;
};

/// Template class that safely deals with reference counted arrays
/// of data types.  This class is safe and relatively inexpensive
/// to copy, and has the ability to be sub-divided as necessary
/// for "sub-arrays" within the array.
template < class T, class tSize=size_t >
class rcarray
{
public:
   //------------------------------------------------------
   // rcarray Methods in alphabetical order.
   //------------------------------------------------------

   /// Allocate an array.  Release any previous array the
   /// object may contain, allocate memory, and attach the
   /// object to the newly created array.
   void Allocate( tSize count );

   /// Assign the object to point at a pre-existing array.
   /// Release any previous array the object may contain,
   /// and point the current object at the already-allocated
   /// memory and count.
   void Assign( T *ptr, tSize count, CRefCountPtr* rcp=NULL );

   /// Assign the object to point the same array as another
   /// rcarray object.
   void Assign( const rcarray& two );

   /// Copies data from another rcarray into our own array.
   /// Returns the index of the next available slot.
   tSize CopyData( const rcarray&two );

   /// Returns the number of elements in the array.
   /// This can be zero if not allocated.
   tSize Count() const { return m_count; }

   /// Create another rcarray that points to a subset
   /// of the current array.  This is a 'shallow' copy : 
   /// the buffer contents are not copied, and both point
   /// to the same memory areas.
   rcarray Mid( tSize index=0, tSize count=-1 ) const;

   /// Access the data pointer explicitly.  This is used primarily
   /// as a convenience function when you don't want to explicitly
   /// (or implicitly) cast.
   T* Ptr() const { return m_ptr; }

   /// Recast method.  Basically, it will create a new object
   /// pointing to the same type, but using a different data
   /// type.  Use with care!
   template < class U, class uSize >
   rcarray< U, uSize > Recast() const
   {
      rcarray< U, uSize > out( m_ptr, 
         (uSize)(Count() * sizeof(T) / sizeof(U)),
         m_info );
      return out;
   }

   /// Release the array.
   void Release();

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------
public:
   /// Default constructor.  Create an rcarray object that
   /// does not contain an array ( effectively NULL ).
   rcarray()
      : m_info( NULL ), m_ptr( 0 ), m_count( 0 )
   {}

   /// Sized constructor.  Create an rcarray object that
   /// owns an array with the specified count of entries.
   /// Note that the array will be allocated to fit.
   rcarray( tSize count )
      : m_info( NULL ), m_ptr( 0 ), m_count( 0 )
   {
      Allocate( count );
   }

   /// Constructor.  Create an rcarray object that does NOT
   /// own its array entries, using the provided pointer
   /// and count.  The rcarray will NOT delete the memory
   /// under any circumstances.
   rcarray( T* ptr, tSize count, CRefCountPtr* rcp=NULL )
      : m_info( NULL ), m_ptr( 0 ), m_count( 0 )
   {
      Assign( ptr, count, rcp );
   }

   /// Copy constructor.
   rcarray( const rcarray& two )
      : m_info( NULL ), m_ptr( 0 ), m_count( 0 )
   {
      Assign( two );
   }

   /// Destructor.
   ~rcarray()
   {
      Release();
   }

   /// Returns the beginning of the array.  This can
   /// be NULL if not allocated.
   operator T*() const { return m_ptr; }

   /// Addition operator.  Take two rcarray objects and
   /// create a combined array of their data items.  This
   /// invokes an extra allocation for the result and a
   /// member-by-member copy of the elements.
   rcarray operator+( const rcarray& two ) const;

   /// Equality operator.  Returns true if the size of the
   /// array and the element comparisons all return true.
   bool operator==( const rcarray& two ) const;

   /// Inequality operator.  Uses operator== to determine
   /// equality ( or lack thereof ).
   bool operator!=( const rcarray& two ) const
   { return !(*this == two ); }

   /// Assignment operator.  Not surprisingly, it just uses
   /// the Assign() method to do the work.
   rcarray& operator= (const rcarray& two)
   { Assign( two ); return *this; }

   //------------------------------------------------------
   // Contained helper classes
   //------------------------------------------------------
protected:
   /***
   /// A simple class to hold array information for owned
   /// data pointers.  This mostly means that the class will
   /// delete[] the pointer it was handed once the reference
   /// count reaches zero.
   class rcaInfo : public CRefCountPtr
   {
   public:
      /// Returns the beginning of the array.  This can
      /// be NULL if not allocated.
      operator T*() const { return m_ptr; }
      /// Returns the number of elements in the array.
      /// This can be zero if not allocated.
      tSize Count() const { return m_count; }
      // Constructor.  
      rcaInfo( tSize count )
         : CRefCountPtr( new T[count], count*sizeof(T) )
         , m_count( count )
      {}
   protected:
      // Member var storage below!
      tSize m_count;
   };
   ***/
private:
   //------------------------------------------------------
   // Member variables.
   //------------------------------------------------------
   CRefCountPtr *m_info;
   T*            m_ptr;
   tSize         m_count;
};

//=================================
// Template Class implementations
//=================================

/// Decrement the reference count.  If the reference count
/// hits zero, then for rcaInfoOwned objects we need to
/// delete and zero the array it points to.
inline size_t CRefCountPtr::DecRef()
{
   if ( 0 == --m_refCount )
   {
      delete [] m_ptr;
      m_ptr   = NULL;
      m_bytes = 0;
   }
   return m_refCount;
}

//------------------------------------------------------
// rcarray Methods in alphabetical order.
//------------------------------------------------------

/// Allocate an array.  Release any previous array the
/// object may contain, allocate memory, and attach the
/// object to the newly created array.
template < class T, class tSize >
void rcarray<T,tSize>::Allocate( tSize count )
{
   Release();
   m_info  = new CRefCountPtr( new T[count], count*sizeof(T) );
   m_ptr   = m_info->Begin<T>();
   m_count = count;
}

/// Assign the object to point at a pre-existing array.
/// Release any previous array the object may contain,
/// and point the current object at the already-allocated
/// memory and count.
template < class T, class tSize >
void rcarray<T,tSize>::Assign( T *ptr, tSize count, CRefCountPtr *rcp )
{
   if ( rcp )
   {
      rcp->IncRef();
   }
   Release();
   m_info  = rcp;
   m_ptr   = ptr;
   m_count = count;
}

/// Assign the object to point the same array as another
/// rcarray object.
template < class T, class tSize >
void rcarray<T,tSize>::Assign( const rcarray& two )
{
   // Be sure to increment two *BEFORE* decrementing
   // our own reference count, just in case this item
   // is self-assignment.
   if ( two.m_info ) 
   {
      two.m_info->IncRef();
   }
   if ( m_info ) 
   {
      m_info->DecRef();
   }
   m_info  = two.m_info;
   m_ptr   = two.m_ptr;
   m_count = two.m_count;
}

/// Copies data from another rcarray into our own array.
/// Returns the index of the next available slot.
template < class T, class tSize >
tSize rcarray<T,tSize>::CopyData( const rcarray& two )
{
}

/// Create another rcarray that points to a subset
/// of the current array.  This is a 'shallow' copy : 
/// the buffer contents are not copied, and both point
/// to the same memory areas.
template < class T, class tSize >
rcarray<T,tSize> rcarray<T,tSize>::Mid( tSize index, tSize count ) const
{
   if ( count < 0 )
   {
      count = m_count;
   }

   // Before we start splitting the array, grab
   // the true remaining size of the array.
   T* outOfBounds = m_info
      ? m_info->End<T>()
      : m_ptr + m_count;
   
   T* start = m_ptr + index;
   if ( outOfBounds < start )
   {
      // Starting point is out of bounds.
      start = outOfBounds;
   }

   T* end = start + count;
   if ( outOfBounds < end )
   {
      // Ending address is out of bounds.
      end = outOfBounds;
   }

   rcarray<T,tSize> result( *this );
   result.m_ptr   = start;
   result.m_count = static_cast<tSize>(end - start);
   return result;
}

/// Release the array.
template < class T, class tSize >
void rcarray<T,tSize>::Release()
{
   if ( m_info && 0 == m_info->DecRef() )
   {
      delete m_info;
   }
   m_info  = NULL;
   m_ptr   = NULL;
   m_count = 0;
}

//------------------------------------------------------
// rcarray Operators.
//------------------------------------------------------

/// Addition operator.  Take two rcarray objects and
/// create a combined array of their data items.  This
/// invokes an extra allocation for the result and a
/// member-by-member copy of the elements.
template < class T, class tSize >
rcarray<T,tSize> rcarray<T,tSize>::operator+( const rcarray& two ) const
{
   const rcarray& one( *this );

   rcarray<T,tSize> result( Count() + two.Count() );
   T *src, *srcEnd, *dest;
   dest = result;
   for( src=one, srcEnd= (T*)one + one.Count();
        src < srcEnd; src++, dest++ )
   {
      *dest = *src;
   }
   for( src=two, srcEnd= (T*)two + two.Count();
        src < srcEnd; src++, dest++ )
   {
      *dest = *src;
   }
   return result;
}

/// Comparison operator.  Returns true if the size of the
/// array and the element comparisons all return true.
template < class T, class tSize >
bool rcarray<T,tSize>::operator==( const rcarray<T,tSize>& two ) const
{
   if ( m_count != two.m_count )
   {
      return false;
   }
   // Shortcut : if the pointers and lengths are the same,
   // there's no reason to do the comparisons.  They *ARE*
   // the same, so they will be equal.
   if ( m_ptr == two.m_ptr )
   {
      return true;
   }
   for ( tSize i = 0; i < m_count; i++ )
   {
      if ( m_ptr[i] != two.m_ptr[i] )
      {
         return false;
      }
   }
   return true;
}

#endif // __RCARRAY_DOT_H__