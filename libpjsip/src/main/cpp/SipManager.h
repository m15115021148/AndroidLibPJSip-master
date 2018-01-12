//
// Created by weiminji on 11/5/17.
//

#ifndef PJSIPAPP_SIPMANAGER_H
#define PJSIPAPP_SIPMANAGER_H

#include <pjsua2.hpp>
#include <iostream>

using namespace pj;

class SipManager {
private:
    Endpoint mSipEndpoint;
    int mPort;
public:
    SipManager();
    ~SipManager();

    bool init(unsigned port);

};


#endif //PJSIPAPP_SIPMANAGER_H
