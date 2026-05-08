import java.io.FileWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;

public class portscanner {

    // Metadata for the portfolio
    private static final String APP_NAME = "Sentinel-Scanner-Core";
    private static final String VERSION = "1.2.0-Stable";

    private static final Map<Integer, String> VULN_DB = new HashMap<>();
    static {
        VULN_DB.put(21, "FTP: Insecure Authentication (CVE-1999-0081)");
        VULN_DB.put(22, "SSH: Check for weak SSH keys");
        VULN_DB.put(23, "Telnet: High Risk - Unencrypted traffic");
        VULN_DB.put(80, "HTTP: Missing TLS/SSL encryption");
        VULN_DB.put(135, "RPC: Potential for Remote Code Execution");
        VULN_DB.put(445, "SMB: Vulnerable to EternalBlue/WannaCry");
        VULN_DB.put(3389, "RDP: Check for BlueKeep (CVE-2019-0708)");
    }

    public static void main(String[] args) {
        String target = "127.0.0.1";
        int startPort = 1;
        int endPort = 1000;
        
        System.out.println("Initializing " + APP_NAME + " [v" + VERSION + "]");
        
        ExecutorService executor = Executors.newFixedThreadPool(50);
        List<Future<String>> scanTasks = new ArrayList<>();

        for (int port = startPort; port <= endPort; port++) {
            scanTasks.add(performScan(executor, target, port));
        }

        executor.shutdown();

        // 3. Reporting Logic (Portfolio Requirement)
        generateReports(scanTasks, target);
    }

    private static Future<String> performScan(ExecutorService executor, String ip, int port) {
        return executor.submit(() -> {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), 150);
                String risk = VULN_DB.getOrDefault(port, "General Service - Check version");
                // Returning as a CSV-style string for easy parsing
                return port + "," + risk;
            } catch (Exception e) {
                return null;
            }
        });
    }

    private static void generateReports(List<Future<String>> tasks, String target) {
        StringBuilder jsonReport = new StringBuilder("[\n");
        
        try (FileWriter txtWriter = new FileWriter("ScanReport.txt")) {
            txtWriter.write("=== " + APP_NAME + " SECURITY REPORT ===\nTarget: " + target + "\n\n");

            for (Future<String> task : tasks) {
                String result = task.get();
                if (result != null) {
                    String[] parts = result.split(",");
                    String port = parts[0];
                    String risk = parts[1];

                    // Add to Text Report
                    txtWriter.write("[!] ALERT: Port " + port + " is OPEN. Risk: " + risk + "\n");
                    
                    // Add to JSON Report
                    jsonReport.append(String.format("  {\"port\": %s, \"risk\": \"%s\"},\n", port, risk));
                    
                    // Live Feedback
                    System.out.println("\u001B[31m[FOUND]\u001B[0m Port " + port + " -> " + risk);
                }
            }
            
            // Clean up JSON trailing comma and close
            if (jsonReport.length() > 2) jsonReport.setLength(jsonReport.length() - 2);
            jsonReport.append("\n]");

            try (FileWriter jsonWriter = new FileWriter("results.json")) {
                jsonWriter.write(jsonReport.toString());
            }

            System.out.println("\n[+] Report generated: ScanReport.txt");
            System.out.println("[+] Machine-readable data: results.json");

        } catch (Exception e) {
            System.err.println("Error generating reports: " + e.getMessage());
        }
    }
}