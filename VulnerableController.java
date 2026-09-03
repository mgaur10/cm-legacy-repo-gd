package com.example.vulnerableserver.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.util.HtmlUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class VulnerableController {

    // 1. Hardcoded Secrets Remediation: Retrieve secrets from environment variables or a secure configuration manager
    private static final String AWS_SECRET_KEY = System.getenv("AWS_SECRET_KEY");
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    // Mock catalog for secure price lookup
    private static final Map<String, Double> ITEM_CATALOG = Map.of(
        "item_1", 19.99,
        "item_2", 49.99,
        "item_3", 5.00
    );

    // 2. SQL Injection Remediation: Use PreparedStatement with parameterized queries
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        
        String query = "SELECT username FROM users WHERE username = ? AND password = ?";
        
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
             PreparedStatement stmt = conn.prepareStatement(query)) {
            
            stmt.setString(1, username);
            stmt.setString(2, password);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return ResponseEntity.ok("Welcome back " + rs.getString("username"));
                } else {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
                }
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Database error occurred.");
        }
    }

    // 3. Reflected Cross-Site Scripting (XSS) Remediation: HTML-escape user input before rendering
    @GetMapping(value = "/receipt", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String receipt(@RequestParam(value = "customer_name", defaultValue = "Valued Customer") String customerName) {
        String safeCustomerName = HtmlUtils.htmlEscape(customerName);
        return "<html><body><h1>Thank you for your order, " + safeCustomerName + "!</h1></body></html>";
    }

    // 4. Business Logic Flaw Remediation: Fetch product price from server-side catalog instead of trusting client payload
    @PostMapping("/checkout")
    public ResponseEntity<String> checkout(@RequestBody Map<String, Object> payload) {
        String itemId = (String) payload.get("item_id");
        int quantity = (Integer) payload.get("quantity");
        
        Double price = ITEM_CATALOG.get(itemId);
        if (price == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid item ID");
        }
        
        double totalBilled = price * quantity;
        
        String responseMessage = String.format("Successfully checked out item: %s, quantity: %d. Total charged: $%.2f", 
            itemId, quantity, totalBilled);
            
        return ResponseEntity.ok(responseMessage);
    }

    // 5. Path Traversal Remediation: Validate and normalize the file path to ensure it remains within the target directory
    @GetMapping("/download")
    public ResponseEntity<byte[]> download(@RequestParam("file") String filename) {
        try {
            if (filename == null || filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
            }
            
            Path baseDir = Paths.get("/var/reports").toAbsolutePath().normalize();
            Path filePath = baseDir.resolve(filename).toAbsolutePath().normalize();
            
            if (!filePath.startsWith(baseDir)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
            }
            
            File file = filePath.toFile();
            if (!file.exists() || !file.isFile()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }
            
            byte[] fileBytes = Files.readAllBytes(filePath);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(fileBytes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}