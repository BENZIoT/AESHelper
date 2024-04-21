  import javax.crypto.Cipher;
  import javax.crypto.spec.IvParameterSpec;
  import javax.crypto.spec.SecretKeySpec;
  import java.util.Base64;

  public class Main {

      public static void main(String[] args) throws Exception {
          String key = "afa25480e73346fab5e8e1552be4de93";
          String ivS = "426e26e82c704e59";
          String content = "{\"starttime\": 1706720400, \"endtime\": 1711904400}";
          String enString = Encrypt(content, key.getBytes("utf8"), ivS.getBytes("utf8"));
          System.out.println("Encrypted string: " + enString);
      }

      static final char[] legalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

      static String encode(byte[] data) {
          int start = 0;
          int len = data.length;
          StringBuilder buf = new StringBuilder(data.length * 3 / 2);

          int end = len - 3;
          int i = start;
          int n = 0;

          while (i <= end) {
              int d = ((((int) data[i]) & 0xff) << 16)
                      | ((((int) data[i + 1]) & 0xff) << 8)
                      | (((int) data[i + 2]) & 0xff);
              buf.append(legalChars[(d >> 18) & 63]);
              buf.append(legalChars[(d >> 12) & 63]);
              buf.append(legalChars[(d >> 6) & 63]);
              buf.append(legalChars[d & 63]);
              i += 3;
              if (n++ >= 14) {
                  n = 0;
                  buf.append("");
              }
          }

          if (i == start + len - 2) {
              int d = ((((int) data[i]) & 0xff) << 16)
                      | ((((int) data[i + 1]) & 255) << 8);
              buf.append(legalChars[(d >> 18) & 63]);
              buf.append(legalChars[(d >> 12) & 63]);
              buf.append(legalChars[(d >> 6) & 63]);
              buf.append("=");
          } else if (i == start + len - 1) {
              int d = (((int) data[i]) & 0xff) << 16;
              buf.append(legalChars[(d >> 18) & 63]);
              buf.append(legalChars[(d >> 12) & 63]);
              buf.append("==");
          }

          return buf.toString();
      }

      static String Encrypt(String content, byte[] key, byte[] ivS) throws Exception {
          byte[] raw = key;
          SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
          Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
          IvParameterSpec iv = new IvParameterSpec(ivS);
          cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
          byte[] encrypted = cipher.doFinal(content.getBytes("utf8"));
          byte[] newB = new byte[ivS.length + encrypted.length];
          System.arraycopy(ivS, 0, newB, 0, ivS.length);
          System.arraycopy(encrypted, 0, newB, ivS.length, encrypted.length);
          return encode(newB);
      }
  }
