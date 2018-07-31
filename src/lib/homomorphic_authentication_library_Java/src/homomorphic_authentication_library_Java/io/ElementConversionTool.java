package homomorphic_authentication_library_Java.io;

import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

public class ElementConversionTool {

    public static String convertElementToString(Element e) {
        return convertBytesToString(e.toBytes());
    }

    public static String convertBytesToString(byte[] e) {
        return Arrays.toString(e);
    }

    public static byte[] convertStringToBytes(String s) {
        String[] byteValues = s.substring(1, s.length() - 1).split(",");
        byte[] bytes = new byte[byteValues.length];

        for (int i = 0, len = bytes.length; i < len; i++) {
            bytes[i] = Byte.parseByte(byteValues[i].trim());
        }

        return bytes;
    }

    public static Element convertStringToElement(String s, Field<Element> f) {
        return convertBytesToElement(s.getBytes(), f);
    }

    public static Element convertBytesToElement(byte[] b, Field<Element> f) {
        return f.newElementFromBytes(b);
    }
}
