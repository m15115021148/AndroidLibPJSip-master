//
// Created by weiminji on 11/5/17.
//

#ifndef PJSIPAPP_SIPACCOUNT_H
#define PJSIPAPP_SIPACCOUNT_H

#include <pjsua2.hpp>
#include <string>

using namespace pj;

class SipAccount : public Account {
private:

public:
    SipAccount(std::string account, std::string password, std::string sipServer, std::string scheme);

    virtual void onRegState(OnRegStateParam &prm) {
        AccountInfo ai = getInfo();
        std::cout << (ai.regIsActive? "*** Register:" : "*** Unregister:")
                  << " code=" << prm.code << std::endl;
    }

    virtual void onIncomingCall(OnIncomingCallParam &prm);
};


#endif //PJSIPAPP_SIPACCOUNT_H
