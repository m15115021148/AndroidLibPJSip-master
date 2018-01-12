package com.honeywell.libpjsip;

import android.util.Log;

import org.pjsip.pjsua2.Account;
import org.pjsip.pjsua2.AccountConfig;
import org.pjsip.pjsua2.AuthCredInfo;
import org.pjsip.pjsua2.CallOpParam;
import org.pjsip.pjsua2.OnIncomingCallParam;
import org.pjsip.pjsua2.OnRegStateParam;

import static org.pjsip.pjsua2.pjsip_status_code.PJSIP_SC_OK;

/**
 * Created by weiminji on 10/31/17.
 */

public class SipAccount extends Account {
    private String TAG = SipAccount.class.getName();

    @Override
    public void onRegState(OnRegStateParam prm) {
        System.out.println("*** On registration state: " + prm.getCode() + prm.getReason());
    }

    private SipAccount() {
        super();
    }

    @Override
    public void onIncomingCall(OnIncomingCallParam prm) {
        super.onIncomingCall(prm);

        Log.d(TAG, "onIncomingCall");

        try {
            SipCall call = new SipCall(this, prm.getCallId());
            CallOpParam rprm = new CallOpParam();
            rprm.setStatusCode(PJSIP_SC_OK);
            call.answer(rprm);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SipAccount createNewAccount(String account, String password, String sipServer, String scheme) {
        SipAccount acc = new SipAccount();

        try {
            AccountConfig acfg = new AccountConfig();
            acfg.setIdUri("sip:" + account + "@" + sipServer);
            acfg.getRegConfig().setRegistrarUri("sip:" + sipServer);
            AuthCredInfo cred = new AuthCredInfo(scheme, "*", account, 0, password);
            acfg.getSipConfig().getAuthCreds().add( cred );
            // Create the account
            acc.create(acfg);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return acc;
    }


    @Override
    public void finalize() {
        // Explicitly destroy and delete endpoint
        delete();
    }
}
