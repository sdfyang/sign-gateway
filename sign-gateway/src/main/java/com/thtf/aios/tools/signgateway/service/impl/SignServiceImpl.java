package com.thtf.aios.tools.signgateway.service.impl;

import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.ServletContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.stereotype.Service;
import org.springframework.web.context.ServletContextAware;

import com.thtf.aios.tools.signgateway.model.KeyContext;
import com.thtf.aios.tools.signgateway.model.PublicKeyInfo;
import com.thtf.aios.tools.signgateway.service.SignService;

@Service("signService")
public class SignServiceImpl
	implements
		SignService,
		ServletContextAware,
		InitializingBean,
		ApplicationListener<ContextClosedEvent>
{
	protected KeyContext keyContext = new KeyContext();
	protected ServletContext servletContext;
	protected String keydir;

	protected Boolean watched = true;
	protected Thread watchThread = null;

	protected static BouncyCastleProvider sBouncyCastleProvider =
		new BouncyCastleProvider();

	static {
        Security.addProvider(sBouncyCastleProvider);
	}

	public void afterPropertiesSet()
		throws Exception
	{
		keydir = servletContext.getRealPath("/keys");

		Path path = Paths.get(keydir);
		
		WatchService watcherService = path.getFileSystem().newWatchService();

		path.register(watcherService,
			StandardWatchEventKinds.ENTRY_CREATE,
			StandardWatchEventKinds.ENTRY_MODIFY,
			StandardWatchEventKinds.ENTRY_DELETE);

		startWatch(watcherService);

		loadKeys(keydir);
	}

	protected void startWatch(final WatchService watcherService)
	{
		watchThread = new Thread() {
			public void run()
			{
				try
				{
					WatchKey key = watcherService.take();

					while(true)
					{
						List<WatchEvent<?>> events = key.pollEvents();
	
						if (events.size() != 0)
							loadKeys(keydir);
					}
				} catch(Exception e)
				{ }
			}
		};
		
		watchThread.start();
	}

	public void onApplicationEvent(ContextClosedEvent event)
	{
		watchThread.interrupt();
	}
	
	protected void loadKeys(String keydir)
	{
		File dir = new File(keydir);

		File[] pems = dir.listFiles(new FilenameFilter() {
			public boolean accept(File file, String filename)
			{
				File child = new File(file, filename);
				if (!child.isFile())
					return false;

				return filename.endsWith(".pem");
			}
		});

		ArrayList<PublicKeyInfo> publicKeyInfos =
			new ArrayList<PublicKeyInfo>(pems.length);
		ArrayList<KeyContext.KeyPair> keyPairs =
			new ArrayList<KeyContext.KeyPair>(pems.length);

		for(File pem: pems)
		{
			try
			{	
				PublicKeyInfo keyInfo = new PublicKeyInfo();
	
				keyInfo.keyname = pem.getName();
				keyInfo.content = FileSystem.readBytes(pem);
	
				KeyContext.KeyPair keyPair = new KeyContext.KeyPair();
	
				keyPair.keyname = pem.getName();

				keyPair.publicKey = readPublicKey(pem);
				keyPair.privateKey =
					readPrivateKey(new File(
						getFileNameNoEx(pem.getAbsolutePath()) + ".pk8"));

				publicKeyInfos.add(keyInfo);
				keyPairs.add(keyPair);
			} catch(Exception e)
			{
				e.printStackTrace();
			}
		}
		
		keyContext.publicKeyInfos =
			publicKeyInfos.toArray(new PublicKeyInfo[publicKeyInfos.size()]);
		keyContext.keyPairs =
			keyPairs.toArray(new KeyContext.KeyPair[keyPairs.size()]);
	}

	public PublicKeyInfo[] getPublicKeys()
	{
		return keyContext.publicKeyInfos;
	}

	public byte[] sign(byte[] data, String keyname)
	{
		KeyContext.KeyPair keyPair = keyContext.findKeyPair(keyname);

		if (keyPair == null)
			return null;

		ByteArrayOutputStream output = new ByteArrayOutputStream();

		try
		{
			writeSignatureBlock(
				new CMSProcessableByteArray(data),
				keyPair.publicKey, keyPair.privateKey, output);
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return output.toByteArray();
	}

	public void setServletContext(ServletContext servletContext)
	{
		this.servletContext = servletContext;
	}

	private static String getFileNameNoEx(String filename)
	{   
        if ((filename != null) && (filename.length() > 0))
        {
            int dot = filename.lastIndexOf('.');   

            if ((dot >-1) && (dot < (filename.length())))
            { 
                return filename.substring(0, dot);   
            }   
        }

        return filename;   
    }
	
	private static X509Certificate readPublicKey(File file)
        throws IOException, GeneralSecurityException
	{
        FileInputStream input = new FileInputStream(file);

        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(input);
        } finally
        {
            input.close();
        }
    }

	private static PrivateKey readPrivateKey(File file)
        throws IOException, GeneralSecurityException
	{
        DataInputStream input = new DataInputStream(new FileInputStream(file));
        try
        {
            byte[] bytes = new byte[(int) file.length()];
            input.read(bytes);

            /* Check to see if this is in an EncryptedPrivateKeyInfo structure. */
            PKCS8EncodedKeySpec spec = decryptPrivateKey(bytes, file);
            if (spec == null) {
                spec = new PKCS8EncodedKeySpec(bytes);
            }

            /*
             * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm
             * OID and use that to construct a KeyFactory.
             */
            ASN1InputStream bIn =
            	new ASN1InputStream(new ByteArrayInputStream(spec.getEncoded()));
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(bIn.readObject());
            String algOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();

            return KeyFactory.getInstance(algOid).generatePrivate(spec);
        } finally
        {
            input.close();
        }
    }

	private static PKCS8EncodedKeySpec decryptPrivateKey(
		byte[] encryptedPrivateKey, File keyFile)
        throws GeneralSecurityException
	{
        EncryptedPrivateKeyInfo epkInfo;
        try {
            epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
        } catch (IOException ex) {
            // Probably not an encrypted key.
            return null;
        }

        char[] password = readPassword(keyFile).toCharArray();

        SecretKeyFactory skFactory =
        	SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());

        try
        {
            return epkInfo.getKeySpec(cipher);
        } catch (InvalidKeySpecException ex)
        {
            System.err.println(
            	"signapk: Password for " + keyFile + " may be bad.");

            throw ex;
        }
    }
	
	private static String readPassword(File keyFile)
	{
		File passwordFile =
			new File(getFileNameNoEx(keyFile.getAbsolutePath()) + ".pw");
		if (!passwordFile.exists())
			return "";

		String password = FileSystem.readString(passwordFile, "utf-8");
		
		return password;
    }

	private static void writeSignatureBlock(
        CMSTypedData data, X509Certificate publicKey, PrivateKey privateKey,
        OutputStream out)
        throws IOException,
               CertificateEncodingException,
               OperatorCreationException,
               CMSException {
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>(1);
        certList.add(publicKey);
        JcaCertStore certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer =
        	new JcaContentSignerBuilder(getSignatureAlgorithm(publicKey))
            .setProvider(sBouncyCastleProvider)
            .build(privateKey);
        gen.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder()
                .setProvider(sBouncyCastleProvider)
                .build())
            .setDirectSignature(true)
            .build(signer, publicKey));
        gen.addCertificates(certs);
        CMSSignedData sigData = gen.generate(data, false);

        ASN1InputStream asn1 = new ASN1InputStream(sigData.getEncoded());
        DEROutputStream dos = new DEROutputStream(out);
        dos.writeObject(asn1.readObject());
    }

	private static final int USE_SHA1 = 1;
    private static final int USE_SHA256 = 2;

	/** Returns the expected signature algorithm for this key type. */
    private static String getSignatureAlgorithm(X509Certificate cert) {
        String sigAlg = cert.getSigAlgName().toUpperCase(Locale.US);
        String keyType = cert.getPublicKey().getAlgorithm().toUpperCase(Locale.US);
        if ("RSA".equalsIgnoreCase(keyType)) {
            if (getDigestAlgorithm(cert) == USE_SHA256) {
                return "SHA256withRSA";
            } else {
                return "SHA1withRSA";
            }
        } else if ("EC".equalsIgnoreCase(keyType)) {
            return "SHA256withECDSA";
        } else {
            throw new IllegalArgumentException("unsupported key type: " + keyType);
        }
    }
    
    private static int getDigestAlgorithm(X509Certificate cert) {
        String sigAlg = cert.getSigAlgName().toUpperCase(Locale.US);
        if ("SHA1WITHRSA".equals(sigAlg) ||
            "MD5WITHRSA".equals(sigAlg)) {     // see "HISTORICAL NOTE" above.
            return USE_SHA1;
        } else if (sigAlg.startsWith("SHA256WITH")) {
            return USE_SHA256;
        } else {
            throw new IllegalArgumentException("unsupported signature algorithm \"" + sigAlg +
                                               "\" in cert [" + cert.getSubjectDN());
        }
    }
}
