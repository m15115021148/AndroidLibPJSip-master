package com.example.weiminji.pjsipapp;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import com.honeywell.libpjsip.SipAccount;
import com.honeywell.libpjsip.SipManagerNativeInterface;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private SipManagerNativeInterface mSipManagerNativeInterface;
    private SipAccount mSipAccount;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());

        //mSipManagerNativeInterface = new SipManagerNativeInterface(5060);
        //mSipAccount = SipAccount.createNewAccount("abc", "12345","192.168.9.127", "android");
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
