package com.honeywell.libpjsip;

import org.pjsip.pjsua2.Account;
import org.pjsip.pjsua2.Call;
import org.pjsip.pjsua2.CallInfo;
import org.pjsip.pjsua2.OnCallMediaStateParam;
import org.pjsip.pjsua2.OnCallStateParam;
import org.pjsip.pjsua2.pjsip_inv_state;

/**
 * Created by weiminji on 11/4/17.
 */

public class SipCall extends Call {
    public SipCall(Account acc, int call_id) {
        super(acc, call_id);
    }

    public SipCall(Account acc) {
        super(acc);
    }

    // Notification when call's state has changed.
    @Override
    public void onCallState(OnCallStateParam prm) {
        try {
            CallInfo callInfo = getInfo();
            if (callInfo.getState() == pjsip_inv_state.PJSIP_INV_STATE_DISCONNECTED) {
                delete();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Notification when call's media state has changed.
    @Override
    public void onCallMediaState(OnCallMediaStateParam prm) {

    }
}
