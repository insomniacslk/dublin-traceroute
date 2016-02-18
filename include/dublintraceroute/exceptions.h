/**
 * \file   exceptions.h
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   October 2015
 * \brief  Common exceptions
 *
 * This module contains the common exceptions definitions
 */
 
 #ifndef _EXCEPTIONS_H
#define _EXCEPTIONS_H

#include <stdexcept>

class DublinTracerouteException: public std::runtime_error {
public:
	DublinTracerouteException(const char *msg): std::runtime_error(msg) {};
	DublinTracerouteException(std::string msg): std::runtime_error(msg.c_str()) {};
};


class DublinTracerouteInProgressException: public DublinTracerouteException {
public:
	DublinTracerouteInProgressException(const char *msg): DublinTracerouteException(msg) {};
	DublinTracerouteInProgressException(std::string msg): DublinTracerouteException(msg.c_str()) {};
};

class DublinTracerouteFailedException: public DublinTracerouteException {
public:
	DublinTracerouteFailedException(const char *msg): DublinTracerouteException(msg) {};
	DublinTracerouteFailedException(std::string msg): DublinTracerouteException(msg.c_str()) {};
};

#endif /* _EXCEPTIONS_H */

