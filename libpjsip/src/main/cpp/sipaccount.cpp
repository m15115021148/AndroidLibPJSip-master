//
// Created by weiminji on 11/5/17.
//

#include "sipaccount.h"
#include <iostream>

SipAccount::SipAccount(std::string account, std::string password, std::string sipServer, std::string scheme)
{
    // Configure an AccountConfig
    AccountConfig acfg;
    acfg.idUri = "sip:" + account + "@" + sipServer;
    acfg.regConfig.registrarUri = "sip:" + sipServer;
    AuthCredInfo cred(scheme, "*", account, 0, password);
    acfg.sipConfig.authCreds.push_back( cred );

    create(acfg);
}



virtual void SipAccount::onIncomingCall(OnIncomingCallParam &prm)
{
    Account::onIncomingCall(prm);

    Call *call = new MyCall(*this, iprm.callId);

    // Just hangup for now
    CallOpParam op;
    op.statusCode = PJSIP_SC_DECLINE;
    call->hangup(op);

    // And delete the call
    delete call;

}

void SipAccount::onRegState(OnRegStateParam &prm) {
    AccountInfo ai = getInfo();
    std::cout << (ai.regIsActive? "*** Register:" : "*** Unregister:")
              << " code=" << prm.code << std::endl;
}