package com.thtf.aios.tools.signgateway.service;

import com.thtf.aios.tools.signgateway.model.PublicKeyInfo;

public interface SignService
{
	public PublicKeyInfo[] getPublicKeys();

	public byte[] sign(byte[] data, String keyname);
}
