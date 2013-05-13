package com.anonpass.anondroid;

public class PBCNative {
	public native byte[] encrypt();

    static {
        //System.loadLibrary("gmp");
        System.loadLibrary("pbc_interface");
    }
}
