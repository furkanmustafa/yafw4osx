#ifndef WATCH_SIMPLE_BASE_H
#define WATCH_SIMPLE_BASE_H

#include <IOKit/IOLib.h>

class __attribute__((visibility("hidden"))) SimpleBase
{
public:
	SInt32 references  __attribute__ ((aligned (4)));
	
public:
	
	int Retain() { return OSIncrementAtomic(&references); }
	int Release() 
	{
		SInt32 val = OSDecrementAtomic(&references) - 1;
		
		if(val == 0)
			Free();
		
		return val;
	}
	
	virtual void Free();	
};


#endif WATCH_SIMPLE_BASE_H

