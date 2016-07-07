package com.thtf.aios.tools.signgateway.model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyContext
{
	public static class KeyPair
	{
		public String keyname;

		public X509Certificate publicKey;
		public PrivateKey privateKey;
	}

	public PublicKeyInfo[] publicKeyInfos;

	public KeyPair[] keyPairs;

	public KeyPair findKeyPair(String keyname)
	{
		if (keyPairs == null)
			return null;
		
		for(KeyPair keypair: keyPairs)
		{
			if (keypair.keyname.equals(keyname))
				return keypair;
		}

		return null;
	}
}
