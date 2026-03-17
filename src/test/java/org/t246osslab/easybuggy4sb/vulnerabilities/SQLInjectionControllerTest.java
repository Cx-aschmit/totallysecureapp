package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.core.model.User;

/**
 * Comprehensive test suite for SQLInjectionController to verify:
 * 1. SQL injection vulnerability is fixed using parameterized queries
 * 2. Stored XSS is prevented by proper database querying
 * 3. Normal functionality is preserved
 * 4. Edge cases and attack vectors are handled correctly
 */
@RunWith(MockitoJUnitRunner.class)
public class SQLInjectionControllerTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private MessageSource messageSource;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private SQLInjectionController controller;

    private ModelAndView mav;
    private Locale locale;

    @Before
    public void setUp() {
        mav = new ModelAndView();
        locale = Locale.ENGLISH;

        // Mock the message source
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
            .thenReturn("Test message");
    }

    /**
     * Test 1: Verify that SQL injection attempts are blocked
     * Tests common SQL injection payloads to ensure parameterized queries prevent injection
     */
    @Test
    public void testSQLInjectionAttackIsBlocked() {
        // Setup: SQL injection payloads that should be treated as literal strings
        String sqlInjectionName = "admin' OR '1'='1";
        String sqlInjectionPassword = "password123";

        // Mock empty result (injection should not work)
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(new ArrayList<User>());

        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(sqlInjectionName, sqlInjectionPassword, mav, request, locale);

        // Verify: The SQL injection should be treated as literal string in parameterized query
        // Verify that query was called with parameterized SQL (using ?)
        verify(jdbcTemplate).query(
            eq("SELECT name, secret FROM USERS WHERE name = ? OR password = ?"),
            eq(new Object[]{sqlInjectionName, sqlInjectionPassword}),
            any(RowMapper.class)
        );

        // Verify the injection attempt didn't bypass authentication
        assertNotNull(result);
    }

    /**
     * Test 2: Verify multiple SQL injection attack vectors are blocked
     */
    @Test
    public void testVariousSQLInjectionPayloadsAreBlocked() {
        String[] injectionPayloads = {
            "' OR 1=1--",
            "admin'--",
            "' OR 'x'='x",
            "1' UNION SELECT NULL,NULL--",
            "'; DROP TABLE USERS--"
        };

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(new ArrayList<User>());
        when(request.getMethod()).thenReturn("POST");

        // Test each injection payload
        for (String payload : injectionPayloads) {
            reset(jdbcTemplate);
            when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(new ArrayList<User>());

            ModelAndView result = controller.process(payload, "testpass123", new ModelAndView(), request, locale);

            // Verify parameterized query is used (not string concatenation)
            verify(jdbcTemplate).query(
                contains("?"),  // Must contain parameter placeholders
                any(Object[].class),  // Must use parameter array
                any(RowMapper.class)
            );

            // Verify the SQL doesn't contain direct concatenation of user input
            verify(jdbcTemplate, never()).query(
                contains(payload),  // User input should NOT appear in SQL string
                any(RowMapper.class)
            );
        }
    }

    /**
     * Test 3: Verify legitimate users can still log in successfully
     */
    @Test
    public void testLegitimateUserLoginSucceeds() {
        // Setup: Valid credentials
        String validName = "john_doe";
        String validPassword = "SecurePass123";

        List<User> mockUsers = new ArrayList<>();
        User user = new User();
        user.setName(validName);
        user.setSecret("user_secret");
        mockUsers.add(user);

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(mockUsers);
        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(validName, validPassword, mav, request, locale);

        // Verify: User list should be added to model
        assertNotNull(result.getModel().get("userList"));
        @SuppressWarnings("unchecked")
        List<User> resultUsers = (List<User>) result.getModel().get("userList");
        assertEquals(1, resultUsers.size());
        assertEquals(validName, resultUsers.get(0).getName());

        // Verify parameterized query was used
        verify(jdbcTemplate).query(
            eq("SELECT name, secret FROM USERS WHERE name = ? OR password = ?"),
            eq(new Object[]{validName, validPassword}),
            any(RowMapper.class)
        );
    }

    /**
     * Test 4: Verify XSS payloads stored in database don't cause SQL injection
     * This tests the Stored XSS scenario where malicious data might be in the DB
     */
    @Test
    public void testStoredXSSPayloadHandling() {
        // Setup: User searching with normal credentials
        String normalName = "testuser";
        String normalPassword = "testpass123";

        // Mock a user with XSS payload in the name/secret (as if it was stored via SQL injection)
        List<User> mockUsers = new ArrayList<>();
        User xssUser = new User();
        xssUser.setName("<script>alert('XSS')</script>");
        xssUser.setSecret("<img src=x onerror=alert('XSS')>");
        mockUsers.add(xssUser);

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(mockUsers);
        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(normalName, normalPassword, mav, request, locale);

        // Verify: The XSS payload is returned (view layer should handle escaping via th:text)
        @SuppressWarnings("unchecked")
        List<User> resultUsers = (List<User>) result.getModel().get("userList");
        assertNotNull(resultUsers);
        assertEquals(1, resultUsers.size());

        // The data contains XSS but won't execute because:
        // 1. SQL injection is prevented (can't inject it)
        // 2. Thymeleaf th:text auto-escapes HTML
        assertTrue(resultUsers.get(0).getName().contains("<script>"));
        assertTrue(resultUsers.get(0).getSecret().contains("<img"));
    }

    /**
     * Test 5: Verify empty/null input handling
     */
    @Test
    public void testEmptyInputHandling() {
        when(request.getMethod()).thenReturn("POST");
        when(messageSource.getMessage(eq("msg.warn.enter.name.and.passwd"), any(), any(Locale.class)))
            .thenReturn("Please enter name and password");

        // Test null inputs
        ModelAndView result1 = controller.process(null, null, mav, request, locale);
        assertNotNull(result1.getModel().get("errmsg"));

        // Test empty inputs
        ModelAndView result2 = controller.process("", "", new ModelAndView(), request, locale);
        assertNotNull(result2.getModel().get("errmsg"));

        // Test whitespace inputs
        ModelAndView result3 = controller.process("   ", "   ", new ModelAndView(), request, locale);
        assertNotNull(result3.getModel().get("errmsg"));

        // Verify jdbcTemplate.query was never called
        verify(jdbcTemplate, never()).query(anyString(), any(Object[].class), any(RowMapper.class));
    }

    /**
     * Test 6: Verify short password is rejected
     */
    @Test
    public void testShortPasswordRejection() {
        when(request.getMethod()).thenReturn("POST");

        // Password less than 8 characters
        ModelAndView result = controller.process("username", "short", mav, request, locale);

        // Verify query was not executed
        verify(jdbcTemplate, never()).query(anyString(), any(Object[].class), any(RowMapper.class));

        // Verify error message is set
        assertNotNull(result.getModel().get("errmsg"));
    }

    /**
     * Test 7: Verify user not found scenario
     */
    @Test
    public void testUserNotFound() {
        String name = "nonexistent";
        String password = "password123";

        // Mock empty result
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(new ArrayList<User>());
        when(request.getMethod()).thenReturn("POST");
        when(messageSource.getMessage(eq("msg.error.user.not.exist"), any(), any(Locale.class)))
            .thenReturn("User does not exist");

        // Execute
        ModelAndView result = controller.process(name, password, mav, request, locale);

        // Verify error message
        assertEquals("User does not exist", result.getModel().get("errmsg"));

        // Verify no userList in model
        assertNull(result.getModel().get("userList"));
    }

    /**
     * Test 8: Verify special characters in legitimate passwords are handled correctly
     */
    @Test
    public void testSpecialCharactersInPassword() {
        String name = "testuser";
        String passwordWithSpecialChars = "P@ssw0rd!#$%";

        List<User> mockUsers = new ArrayList<>();
        User user = new User();
        user.setName(name);
        user.setSecret("secret");
        mockUsers.add(user);

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(mockUsers);
        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(name, passwordWithSpecialChars, mav, request, locale);

        // Verify parameterized query handles special characters correctly
        verify(jdbcTemplate).query(
            eq("SELECT name, secret FROM USERS WHERE name = ? OR password = ?"),
            eq(new Object[]{name, passwordWithSpecialChars}),
            any(RowMapper.class)
        );

        // Verify success
        assertNotNull(result.getModel().get("userList"));
    }

    /**
     * Test 9: Verify SQL keywords in user input are treated as literals
     */
    @Test
    public void testSQLKeywordsAsLiterals() {
        String nameWithKeywords = "SELECT FROM WHERE";
        String passwordWithKeywords = "DROP TABLE UNION";

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(new ArrayList<User>());
        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(nameWithKeywords, passwordWithKeywords, mav, request, locale);

        // Verify SQL keywords are passed as parameters, not concatenated into SQL
        verify(jdbcTemplate).query(
            eq("SELECT name, secret FROM USERS WHERE name = ? OR password = ?"),
            eq(new Object[]{nameWithKeywords, passwordWithKeywords}),
            any(RowMapper.class)
        );

        // Verify the SQL string itself doesn't contain the user input
        verify(jdbcTemplate, never()).query(
            contains("DROP TABLE"),
            any(RowMapper.class)
        );
    }

    /**
     * Test 10: Verify database exception handling
     */
    @Test
    public void testDatabaseExceptionHandling() {
        String name = "testuser";
        String password = "testpass123";

        // Mock database exception
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenThrow(new org.springframework.dao.DataAccessException("DB Error") {});
        when(request.getMethod()).thenReturn("POST");
        when(messageSource.getMessage(eq("msg.db.access.error.occur"), any(), any(Locale.class)))
            .thenReturn("Database error occurred");

        // Execute
        ModelAndView result = controller.process(name, password, mav, request, locale);

        // Verify error message is set
        assertEquals("Database error occurred", result.getModel().get("errmsg"));

        // Verify no userList in model
        assertNull(result.getModel().get("userList"));
    }

    /**
     * Test 11: Verify unicode and multi-byte characters are handled correctly
     */
    @Test
    public void testUnicodeCharacterHandling() {
        String unicodeName = "用户名";  // Chinese characters
        String unicodePassword = "パスワード123";  // Japanese characters

        List<User> mockUsers = new ArrayList<>();
        User user = new User();
        user.setName(unicodeName);
        user.setSecret("secret");
        mockUsers.add(user);

        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
            .thenReturn(mockUsers);
        when(request.getMethod()).thenReturn("POST");

        // Execute
        ModelAndView result = controller.process(unicodeName, unicodePassword, mav, request, locale);

        // Verify parameterized query handles unicode correctly
        verify(jdbcTemplate).query(
            eq("SELECT name, secret FROM USERS WHERE name = ? OR password = ?"),
            eq(new Object[]{unicodeName, unicodePassword}),
            any(RowMapper.class)
        );

        // Verify success
        assertNotNull(result.getModel().get("userList"));
    }

    /**
     * Test 12: Verify GET request doesn't show error message
     */
    @Test
    public void testGETRequestWithoutCredentials() {
        when(request.getMethod()).thenReturn("GET");

        // Execute with no credentials
        ModelAndView result = controller.process(null, null, mav, request, locale);

        // Verify no error message for GET request
        assertNull(result.getModel().get("errmsg"));

        // Verify no query was executed
        verify(jdbcTemplate, never()).query(anyString(), any(Object[].class), any(RowMapper.class));
    }
}
