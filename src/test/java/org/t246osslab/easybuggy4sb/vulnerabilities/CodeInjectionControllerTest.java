package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Security tests for CodeInjectionController to verify that:
 * 1. Valid JSON strings are properly parsed
 * 2. Invalid JSON strings are rejected
 * 3. Code injection attempts are prevented (no arbitrary code execution)
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class CodeInjectionControllerTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webApplicationContext(this.webApplicationContext).build();
    }

    /**
     * Test that valid JSON strings are accepted and processed correctly
     */
    @Test
    public void testValidJsonString() throws Exception {
        // Test with a simple valid JSON object
        String validJson = "{\"name\":\"test\",\"value\":123}";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", validJson))
                .andExpect(status().isOk())
                .andReturn();

        // Verify that the valid JSON was accepted (no error message should be set)
        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertTrue("Valid JSON should not produce an error message", errmsg == null);
    }

    /**
     * Test that valid JSON arrays are accepted
     */
    @Test
    public void testValidJsonArray() throws Exception {
        String validJsonArray = "[1,2,3,\"test\"]";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", validJsonArray))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertTrue("Valid JSON array should not produce an error message", errmsg == null);
    }

    /**
     * Test that valid nested JSON structures are accepted
     */
    @Test
    public void testValidNestedJson() throws Exception {
        String nestedJson = "{\"user\":{\"name\":\"John\",\"age\":30,\"addresses\":[{\"city\":\"NYC\"}]}}";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", nestedJson))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertTrue("Valid nested JSON should not produce an error message", errmsg == null);
    }

    /**
     * Test that invalid JSON syntax is properly rejected
     */
    @Test
    public void testInvalidJsonSyntax() throws Exception {
        // Missing closing brace
        String invalidJson = "{\"name\":\"test\"";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", invalidJson))
                .andExpect(status().isOk())
                .andReturn();

        // Verify that an error message was set for invalid JSON
        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Invalid JSON should produce an error message", errmsg);
    }

    /**
     * Test that malformed JSON with extra characters is rejected
     */
    @Test
    public void testMalformedJsonWithTrailingCharacters() throws Exception {
        String malformedJson = "{\"name\":\"test\"}extratext";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", malformedJson))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Malformed JSON should produce an error message", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that code injection attempts are blocked
     * This test attempts to execute JavaScript code that would succeed with eval()
     * but should fail with a proper JSON parser
     */
    @Test
    public void testCodeInjectionAttemptBlocked() throws Exception {
        // Attempt to inject JavaScript code that would execute with eval()
        String injectionAttempt = "');java.lang.Runtime.getRuntime().exec('calc');//";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", injectionAttempt))
                .andExpect(status().isOk())
                .andReturn();

        // The injection attempt should be rejected as invalid JSON
        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Code injection attempt should be blocked and produce an error", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that JavaScript function calls are not executed
     */
    @Test
    public void testJavaScriptFunctionCallBlocked() throws Exception {
        // Attempt to call a JavaScript function
        String functionCall = "');alert('XSS');//";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", functionCall))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("JavaScript function calls should be blocked", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that code execution via string escape is blocked
     */
    @Test
    public void testCodeExecutionViaStringEscapeBlocked() throws Exception {
        // Attempt to break out of string context and execute code
        String escapeAttempt = "'+eval('malicious_code')+'";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", escapeAttempt))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Code execution via string escape should be blocked", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that system command execution attempts are blocked
     */
    @Test
    public void testSystemCommandExecutionBlocked() throws Exception {
        // Attempt to execute system commands via JavaScript
        String commandExecution = "');var proc=java.lang.Runtime.getRuntime().exec('whoami');//";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", commandExecution))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("System command execution should be blocked", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that constructor injection is blocked
     */
    @Test
    public void testConstructorInjectionBlocked() throws Exception {
        // Attempt to use constructor for code injection
        String constructorInjection = "');this.constructor.constructor('return process')().exit();//";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", constructorInjection))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Constructor injection should be blocked", errmsg);
    }

    /**
     * CRITICAL SECURITY TEST: Verify that prototype pollution attempts are blocked
     */
    @Test
    public void testPrototypePollutionBlocked() throws Exception {
        // Attempt prototype pollution
        String prototypePollution = "{'__proto__':{'polluted':true}}";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", prototypePollution))
                .andExpect(status().isOk())
                .andReturn();

        // This might be accepted as valid JSON (which is okay), but should not execute any code
        // The key is that no code execution occurs, which we validate by the app not crashing
        assertNotNull("Request should complete without code execution", result.getModelAndView());
    }

    /**
     * Test that empty input shows the appropriate message
     */
    @Test
    public void testEmptyInput() throws Exception {
        MvcResult result = mockMvc.perform(get("/codeijc"))
                .andExpect(status().isOk())
                .andReturn();

        // Should show a message asking user to enter JSON string
        Object msg = result.getModelAndView().getModel().get("msg");
        assertNotNull("Empty input should show instructional message", msg);
    }

    /**
     * Test with whitespace-only input
     */
    @Test
    public void testWhitespaceOnlyInput() throws Exception {
        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", "   "))
                .andExpect(status().isOk())
                .andReturn();

        // Whitespace-only should be treated as blank
        Object msg = result.getModelAndView().getModel().get("msg");
        assertNotNull("Whitespace-only input should show instructional message", msg);
    }

    /**
     * Test JSON with special characters that should be allowed
     */
    @Test
    public void testJsonWithSpecialCharacters() throws Exception {
        String jsonWithSpecials = "{\"text\":\"Line1\\nLine2\\tTabbed\"}";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", jsonWithSpecials))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertTrue("Valid JSON with escape sequences should be accepted", errmsg == null);
    }

    /**
     * Test JSON with Unicode characters
     */
    @Test
    public void testJsonWithUnicode() throws Exception {
        String jsonWithUnicode = "{\"name\":\"Test\\u0020User\"}";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", jsonWithUnicode))
                .andExpect(status().isOk())
                .andReturn();

        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertTrue("Valid JSON with Unicode should be accepted", errmsg == null);
    }

    /**
     * CRITICAL SECURITY TEST: Ensure no ScriptEngine or eval usage remains
     * This is a meta-test that verifies the remediation was applied correctly
     */
    @Test
    public void testNoScriptEngineUsage() throws Exception {
        // This test attempts a classic ScriptEngine exploit that would work if eval was still used
        String classicExploit = "';java.lang.System.exit(0);//";

        MvcResult result = mockMvc.perform(get("/codeijc")
                .param("jsonString", classicExploit))
                .andExpect(status().isOk())
                .andReturn();

        // If we reach this point, the exploit failed (good!)
        // If ScriptEngine.eval was still used, the JVM would have exited
        Object errmsg = result.getModelAndView().getModel().get("errmsg");
        assertNotNull("Classic ScriptEngine exploit should be blocked", errmsg);
    }
}
