//
// Created by weiminji on 11/5/17.
//

#include <pjsua2/include/pjsip/sip_types.h>
#include "SipManager.h"

SipManager::SipManager()
{

}

SipManager::~SipManager()
{

}

bool SipManager::init(unsigned port)
{
    mSipEndpoint.libCreate();

    // Initialize endpoint
    EpConfig ep_cfg;
    mSipEndpoint.libInit( ep_cfg );

    // Create SIP transport. Error handling sample is shown
    TransportConfig tcfg;
    tcfg.port = port;
    try {
        mSipEndpoint.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
    } catch (Error &err) {
        std::cout << err.info() << std::endl;
        return false;
    }

    // Start the library (worker threads etc)
    mSipEndpoint.libStart();

    return true;
}