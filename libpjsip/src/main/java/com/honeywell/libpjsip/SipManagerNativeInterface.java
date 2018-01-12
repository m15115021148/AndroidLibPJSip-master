package com.honeywell.libpjsip;


/**
 * Created by weiminji on 10/29/17.
 */

public class SipManagerNativeInterface {
    private String TAG = SipManagerNativeInterface.class.getName();
    static {
        System.loadLibrary("pjsua2");
        System.loadLibrary("pjsip-lib");
        System.out.println("Library loaded");
    }


    public SipManagerNativeInterface(int port) {
        initFromJNI(port);
    }

    @Override
    public void finalize() {

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    private native boolean initFromJNI(int port);

    private long mNativeObject;
}
