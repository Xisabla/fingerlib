#ifndef INCLUDE_HFINGER_EXCEPTIONS_HPP
#define INCLUDE_HFINGER_EXCEPTIONS_HPP

#include <exception>
#include <string>

class BadReportmodeVariable : public std::exception
{
private:
    std::string message;

public:
    BadReportmodeVariable(const std::string& message = "Problem with 'reportmode' variable value.") : message(message) {}

    virtual ~BadReportmodeVariable() throw () {}

    virtual const char* what() const throw()
    {
        return message.c_str();
    }
};


class NotAPcap : public std::exception
{
private:
    std::string message;

public:
    NotAPcap(const std::string& message = "The provided file is not a valid pcap file.") : message(message) {}

    virtual ~NotAPcap() throw () {}

    virtual const char* what() const throw()
    {
        return message.c_str();
    }
};

#endif // INCLUDE_HFINGER_EXCEPTIONS_HPP