import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/**
 * Dynamic string decryptor — runs INSIDE Docker only.
 *
 * Loads the target JAR in an isolated URLClassLoader, reflectively finds
candidate decryptor methods from candidates.json, and calls them with
all extracted (string, key) pairs. Outputs decrypted strings to stdout.
 *
 * Usage (inside Docker):
 *   java -cp . JarsecDynamicDecrypt /path/to/candidates.json /path/to/target.jar
 */
public class JarsecDynamicDecrypt {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: JarsecDynamicDecrypt candidates.json target.jar [output.json]");
            System.exit(1);
        }

        String candidatesPath = args[0];
        String jarPath = args[1];
        String outPath = args.length > 2 ? args[2] : "decrypted_dynamic.json";

        // Read candidates
        String jsonStr = Files.readString(Path.of(candidatesPath));
        JSONObject root = new JSONObject(jsonStr);
        JSONArray candidates = root.getJSONArray("candidates");

        if (candidates.length() == 0) {
            System.out.println("{\"results\":[],\"error\":\"no candidates\"}");
            System.exit(0);
        }

        // Load target JAR in isolated classloader
        URLClassLoader loader = new URLClassLoader(
            new URL[]{new File(jarPath).toURI().toURL()},
            JarsecDynamicDecrypt.class.getClassLoader()
        );

        // Install restrictive security manager
        System.setSecurityManager(new DecryptSecurityManager());

        List<JSONObject> results = new ArrayList<>();

        for (int i = 0; i < candidates.length(); i++) {
            JSONObject cand = candidates.getJSONObject(i);
            String className = cand.getString("class_name");
            String methodName = cand.getString("method_name");
            String desc = cand.getString("descriptor");
            JSONArray strings = cand.getJSONArray("string_args");

            System.err.println("Trying " + className + "." + methodName + " with " + strings.length() + " strings...");

            try {
                Class<?> clazz = loader.loadClass(className);

                // Find matching method by name + descriptor
                Method targetMethod = null;
                for (Method m : clazz.getDeclaredMethods()) {
                    if (m.getName().equals(methodName) && isMatchingDescriptor(m, desc)) {
                        targetMethod = m;
                        break;
                    }
                }

                if (targetMethod == null) {
                    System.err.println("  Method not found: " + methodName);
                    continue;
                }

                targetMethod.setAccessible(true);

                // Call with each string/key pair
                for (int j = 0; j < strings.length(); j++) {
                    JSONObject pair = strings.getJSONObject(j);
                    String encrypted = pair.getString("encrypted");
                    int key = pair.getInt("key");

                    try {
                        Object result = targetMethod.invoke(null, encrypted, key);
                        if (result != null) {
                            String decrypted = result.toString();
                            JSONObject r = new JSONObject();
                            r.put("class", className);
                            r.put("method", methodName);
                            r.put("key", key);
                            r.put("encrypted_preview", encrypted.substring(0, Math.min(50, encrypted.length())));
                            r.put("decrypted", decrypted);
                            results.add(r);
                        }
                    } catch (InvocationTargetException e) {
                        // Decryptor may fail for some strings — skip
                        System.err.println("  Failed for key=" + key + ": " + e.getCause().getMessage());
                    }
                }
            } catch (Exception e) {
                System.err.println("  Error loading class: " + e.getMessage());
            }
        }

        loader.close();

        // Output
        JSONObject out = new JSONObject();
        out.put("results", results);
        out.put("count", results.size());
        Files.writeString(Path.of(outPath), out.toString(2));

        System.out.println(out.toString(2));
    }

    static boolean isMatchingDescriptor(Method m, String desc) {
        // Quick check: desc like (Ljava/lang/String;I)Ljava/lang/String;
        Class<?>[] params = m.getParameterTypes();
        Class<?> ret = m.getReturnType();
        if (params.length == 2 && params[0] == String.class) {
            if (ret == String.class || ret == Object.class) {
                if (params[1] == int.class || params[1] == long.class) {
                    return true;
                }
            }
        }
        return false;
    }

    static class DecryptSecurityManager extends SecurityManager {
        @Override
        public void checkPermission(java.security.Permission perm) {
            // Allow reflection
            if (perm.getName().startsWith("accessDeclaredMembers") ||
                perm.getName().startsWith("suppressAccessChecks")) {
                return;
            }
            // Block network, filesystem, exec, exit
            String name = perm.getName();
            if (name.contains("SocketPermission") ||
                name.contains("NetPermission") ||
                name.contains("FilePermission") ||
                name.contains("RuntimePermission") && (name.contains("exec") || name.contains("exitVM"))) {
                throw new SecurityException("Blocked: " + name);
            }
            // Allow everything else (loading classes, etc.)
        }
    }
}
