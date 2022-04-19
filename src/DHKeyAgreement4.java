import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

/*
 * This program executes the Diffie-Hellman key agreement protocol between
 * 4 parties: A, B, C, and D using a shared 2048-bit DH parameter.
 */
public class DHKeyAgreement4 {

    public static void main(String argv[]) throws Exception {

        // A creates her own DH key pair with 2048-bit key size
        System.out.println("A: Generate DH keypair ...");
        KeyPairGenerator AKpairGen = KeyPairGenerator.getInstance("DH");
        AKpairGen.initialize(2048);
        KeyPair AKpair = AKpairGen.generateKeyPair();

        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey) AKpair.getPublic()).getParams();

        // B creates his own DH key pair using the same params
        System.out.println("B: Generate DH keypair ...");
        KeyPairGenerator BKpairGen = KeyPairGenerator.getInstance("DH");
        BKpairGen.initialize(dhParamShared);
        KeyPair BKpair = BKpairGen.generateKeyPair();

        // C creates her own DH key pair using the same params
        System.out.println("C: Generate DH keypair ...");
        KeyPairGenerator CKpairGen = KeyPairGenerator.getInstance("DH");
        CKpairGen.initialize(dhParamShared);
        KeyPair CKpair = CKpairGen.generateKeyPair();

        //Create key pair for D using same params
        System.out.println("D: Generate DH keypair ...");
        KeyPairGenerator DKpairGen = KeyPairGenerator.getInstance("DH");
        DKpairGen.initialize(dhParamShared);
        KeyPair DKpair = CKpairGen.generateKeyPair();

        // A initialize
        System.out.println("A: Initialize ...");
        KeyAgreement AKeyAgree = KeyAgreement.getInstance("DH");
        AKeyAgree.init(AKpair.getPrivate());
        // B initialize
        System.out.println("B: Initialize ...");
        KeyAgreement BKeyAgree = KeyAgreement.getInstance("DH");
        BKeyAgree.init(BKpair.getPrivate());
        // C initialize
        System.out.println("C: Initialize ...");
        KeyAgreement CKeyAgree = KeyAgreement.getInstance("DH");
        CKeyAgree.init(CKpair.getPrivate());
        //Initialise D
        System.out.println("C: Initialize ...");
        KeyAgreement DKeyAgree = KeyAgreement.getInstance("DH");
        DKeyAgree.init(DKpair.getPrivate());

        // A uses D's public key
        Key ad = AKeyAgree.doPhase(DKpair.getPublic(), false);
        // B uses A's public key
        Key ba = BKeyAgree.doPhase(AKpair.getPublic(), false);
        // C uses B's public key
        Key cb = CKeyAgree.doPhase(BKpair.getPublic(), false);
        //D uses C's public key
        Key dc = DKeyAgree.doPhase(CKpair.getPublic(), false);

        //A (AD) uses result from DC
        Key adc = AKeyAgree.doPhase(dc, false);
        //B (BA) uses result from AD
        Key bad = BKeyAgree.doPhase(ad, false);
        //C (CB) uses result from BA
        Key cba = CKeyAgree.doPhase(ba, false);
        //D (DC) uses result from CB
        Key dbc = DKeyAgree.doPhase(cb, false);

        //A (ADC) uses result from DCB
        AKeyAgree.doPhase(dbc, true);
        //B(BAD) uses result from ADC
        BKeyAgree.doPhase(adc, true);
        //C(CBA) uses result from BAD
        CKeyAgree.doPhase(bad, true);
        //D(DBC) uses result from CBA
        DKeyAgree.doPhase(cba, true);

        byte[] ASharedSecret = AKeyAgree.generateSecret();
        System.out.println("A secret: " + toHexString(ASharedSecret));
        byte[] BSharedSecret = BKeyAgree.generateSecret();
        System.out.println("B secret: " + toHexString(BSharedSecret));
        byte[] CSharedSecret = CKeyAgree.generateSecret();
        System.out.println("C secret: " + toHexString(CSharedSecret));
        byte[] DSharedSecret = DKeyAgree.generateSecret();
        System.out.println("D Secret: " + toHexString(DSharedSecret));
        // Compare A and B
        if (!java.util.Arrays.equals(ASharedSecret, BSharedSecret)) throw new Exception("A and B differ");
        System.out.println("A and B are the same");
        // Compare B and C
        if (!java.util.Arrays.equals(BSharedSecret, CSharedSecret)) throw new Exception("B and C differ");
        System.out.println("B and C are the same");
        //Compare C and D
        if(!java.util.Arrays.equals(CSharedSecret, DSharedSecret)) throw new Exception ("C and D differ");
        System.out.println("C and D are the same");
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}