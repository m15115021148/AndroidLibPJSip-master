//
// Created by weiminji on 11/5/17.
//

#include <jni.h>

#include "SipManager.h

//声明属性域ID,方便访问
struct fieldIds {
    jclass javaClass;
    jfieldID mNativeObject;
} jSipManagerFieldIds;


#define SIP_MANAGER_CLASS "com/honeywell/SipManagerNativeInterface" //JAVAC对象

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_honeywell_libpjsip_SipManagerNativeInterface_initFromJNI(JNIEnv *env, jobject instance, jint port)
{
    jSipManagerFieldIds.javaClass = env->FindClass(SIP_MANAGER_CLASS);
    jSipManagerFieldIds.mNativeObject = env->GetFieldID(jSipManagerFieldIds.javaClass, "mNativeObject", "J");


    SipManager *sipManager = new SipManager();
    return sipManager->init(port);
}