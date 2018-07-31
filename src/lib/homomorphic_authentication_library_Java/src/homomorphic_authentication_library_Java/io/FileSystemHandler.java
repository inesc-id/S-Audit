package homomorphic_authentication_library_Java.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;

public class FileSystemHandler {

    public static void writeFile(final String file_path, String data) {
        PrintWriter writer;
        try {
            writer = new PrintWriter(file_path, "UTF-8");
            writer.print(data);
            writer.close();
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static String readFile(final String file_path) {
        String s = "";
        try {
            Object[] lines = (Object[]) Files.readAllLines(Paths.get(file_path),
                    StandardCharsets.UTF_8).toArray();
            for (int i = 0; i < lines.length; i++) {
                if (i > 0) {
                    s += '\n';
                }
                s += (String) lines[i];
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return s;
    }

    public static void writeFile(final String file_path, final byte[] data) throws IOException {
        InputStream in = new ByteArrayInputStream(data);
        OutputStream out;
        out = new FileOutputStream(file_path);
        out.write(data);
        out.close();
    }

    public static byte[] readFileBytes(final String file_path) throws IOException {
        return FileUtils.readFileToByteArray(new File(file_path));
    }
}
