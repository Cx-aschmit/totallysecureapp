package org.t246osslab.easybuggy4sb.controller;

import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class CxController {

    // Allowlist of safe commands that can be executed
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
        "whoami", "date", "pwd", "hostname"
    ));

    @GetMapping("v2/authed/getTime") // require auth
    public String getTime() {
        return new Date().toString();
    }

    @GetMapping("v2/authed/getUser") // require auth
    public String getUser() {
        return "user is: " + System.getProperty("user.name");
    }

    @GetMapping("v2/authed/getIP") // require auth
    public String getIP() throws UnknownHostException {
        return Inet4Address.getLocalHost().getHostAddress();
    }

    @ApiIgnore // don't want this in openapi file
    @GetMapping("v2/authed/multiply") // require auth
    public int multiply(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a * b;
    }

    // curl localhost:8080/legacy/runCommand/whoami
    @PostMapping("legacy/runCommand/{cmd}")
    public String runCommand(@PathVariable String cmd) throws IOException {
        // Security fix: Validate command against allowlist to prevent command injection
        if (cmd == null || cmd.trim().isEmpty()) {
            throw new IllegalArgumentException("Command cannot be empty");
        }

        // Extract base command (before any spaces or special characters)
        String baseCommand = cmd.trim().split("\\s+")[0];

        // Check if command is in allowlist
        if (!ALLOWED_COMMANDS.contains(baseCommand)) {
            throw new SecurityException("Command not allowed: " + baseCommand);
        }

        // Reject commands with dangerous characters that could enable command injection
        if (cmd.matches(".*[;&|`$<>\\\\'\"].*")) {
            throw new SecurityException("Command contains forbidden characters");
        }

        // Use ProcessBuilder for safer command execution with proper argument separation
        ProcessBuilder processBuilder = new ProcessBuilder(baseCommand);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();

        // Read output safely with proper resource management
        try (InputStream inputStream = process.getInputStream();
             InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
             BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {

            String result = bufferedReader.lines().collect(Collectors.joining("\n"));

            // Wait for process to complete
            try {
                process.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Command execution interrupted", e);
            }

            return result;
        }
    }

    @GetMapping("legacy/add")
    public int add(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a + b;
    }

    @GetMapping("internal")
    public String internal() {
        return "this is an internal api";
    }

    @GetMapping("internal/op1")
    public String op1() {
        return "op1 api";
    }

    @PostMapping("internal/op2")
    public String op2() {
        return "op2 api";
    }
}
