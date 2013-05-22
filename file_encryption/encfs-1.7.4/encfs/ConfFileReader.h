#ifndef CONFILEREADER_H
#define CONFILEREADER_H


#include <iostream>
#include <libconfig.h++>

class ConfFileReader 
{

public:
	static ConfFileReader * getInstance();
	libconfig::Setting& GetAttrValue(const char* attr) const;
	bool IsAttr(const char* attr) const;
	int ReadConfigFile();
	~ConfFileReader ()
    	{
             instanceFlag = false;
    	}	
private:
	libconfig::Config cfg;
	static bool instanceFlag;
    	static ConfFileReader  *single;
    	ConfFileReader ();
	ConfFileReader(const ConfFileReader&);
  	ConfFileReader& operator=(const ConfFileReader&);

};

libconfig::Setting& get_attr_value(const char* attr);
#endif /* CONFILEREADER_H */
