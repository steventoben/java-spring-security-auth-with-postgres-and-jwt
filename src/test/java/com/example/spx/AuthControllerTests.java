package com.example.spx;

import com.example.spx.config.WebSecurityConfig;
import com.example.spx.controller.AuthController;
import com.example.spx.dto.AuthenticationResponseBody;
import com.example.spx.dto.UserCredentialsDTO;
import com.example.spx.exception.AuthException;
import com.example.spx.exception.UserDoesNotExistException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockBodyContent;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTests {

    @Autowired
    private MockMvc mvc;

    Map<String, UserCredentialsDTO> credentials = new HashMap<>();

    @BeforeEach
    void insertTestCredentials() {
        UserCredentialsDTO goodCredentials = new UserCredentialsDTO();
        goodCredentials.setUsername("user");
        goodCredentials.setPassword("password");

        UserCredentialsDTO badPasswordCredentials = new UserCredentialsDTO();
        badPasswordCredentials.setUsername("user");
        badPasswordCredentials.setPassword("passwordd");

        UserCredentialsDTO badUsernameCredentials = new UserCredentialsDTO();
        badUsernameCredentials.setUsername("dneuser");
        badUsernameCredentials.setPassword("password");

        credentials.put("good", goodCredentials);
        credentials.put("badPassword", badPasswordCredentials);
        credentials.put("badUsername", badUsernameCredentials);
    }

    @Test
    void rootWhenAuthenticatedThenSaysName() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        UserCredentialsDTO userCredentialsDTO = new UserCredentialsDTO();
        userCredentialsDTO.setUsername("user");
        userCredentialsDTO.setPassword("password");

        MvcResult mvcResult = this.mvc.perform(
                post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userCredentialsDTO))
                        .accept(MediaType.APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn();

        String responseString = mvcResult.getResponse().getContentAsString();
        JSONObject jsonResponse = new JSONObject(responseString);

        this.mvc.perform(get("/test")
                .header("Authorization", "Bearer " + jsonResponse.get("token")))
                .andExpect(content().string("user"));
    }
    //Test whenAuthTokenStaleCheckLoginCredentials or ignore Bearer on Login page
    //if trying to /login and have stale bearer jwt you'll be 401d, instead the stale token should be removed and grant user anonymous 200 access to /login

    /*
     *
     * Testing REST API Login (/login) supplied body of invalid credentials
     * 1.   Username is correct (User exists), Password is incorrect for the User
     * 2.   Username is incorrect (User with supplied username does not exist), Password doesn't matter because no User
     *
     *
     */


    /**
     *
     * @throws Exception
     */
    @Test
    void whenBadPasswordSuppliedToLoginThenReturnUnauthorized() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        UserCredentialsDTO userCredentialsDTO = new UserCredentialsDTO();
        userCredentialsDTO.setUsername("user");
        userCredentialsDTO.setPassword("passwordd");

        MvcResult mvcResult = this.mvc.perform(
                post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userCredentialsDTO))
                        .accept(MediaType.APPLICATION_JSON)
        ).andExpect(status().isUnauthorized())
                .andExpect(result -> Assert.isTrue(result.getResolvedException() instanceof AuthException))
                .andExpect(result -> Assert.hasText("Password incorrect", result.getResolvedException().getMessage()))
                .andReturn();
    }

    @Test
    void whenLoginWithUsernameThatDNE_thenReturnUnauthorized() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        UserCredentialsDTO userCredentialsDTO = new UserCredentialsDTO();
        userCredentialsDTO.setUsername("use");
        userCredentialsDTO.setPassword("password");

        MvcResult mvcResult = this.mvc.perform(
                        post("/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userCredentialsDTO))
                                .accept(MediaType.APPLICATION_JSON)
                ).andExpect(status().isBadRequest())
                .andExpect(result -> Assert.isTrue(result.getResolvedException() instanceof UserDoesNotExistException))
                .andExpect(result -> Assert.hasText("User could not be found", result.getResolvedException().getMessage()))
                .andReturn();
    }
}
