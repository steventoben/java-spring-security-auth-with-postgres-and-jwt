package com.example.spx;

import com.example.spx.dto.CreateUserDTO;
import com.example.spx.dto.UserCredentialsDTO;
import com.example.spx.exception.AuthException;
import com.example.spx.exception.UserDoesNotExistException;
import com.example.spx.exception.UsernameNotAvailableException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.Assert;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTests {

    //IntelliJ shows an error because it can't Autowire the Bean
    //I haven't defined a Bean for it but used the autoconfig, so it works regardless
    @Autowired
    private MockMvc mvc;

    @Test
    void whenAuthenticatedThenSaysName() throws Exception {

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
    @Test
    void whenLoginWithValidCredentials_thenRespondOK() throws Exception {

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

    }

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

    //Run this method with fresh username then run second with same username for integration test
    @Test
    void whenRegisterWithValidCredentials_thenReturnCreated() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        CreateUserDTO createUserDTO = new CreateUserDTO();
        createUserDTO.setUsername("p");
        createUserDTO.setPassword("password");

        MvcResult mvcResult = this.mvc.perform(
                        post("/create")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(createUserDTO))
                                .accept(MediaType.APPLICATION_JSON)
                ).andExpect(status().isCreated())
                .andReturn();
    }

    @Test
    void whenRegisterWithTakenCredentials_thenReturnBadRequest() throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        CreateUserDTO createUserDTO = new CreateUserDTO();
        createUserDTO.setUsername("user");
        createUserDTO.setPassword("password");

        MvcResult mvcResult = this.mvc.perform(
                        post("/create")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(createUserDTO))
                                .accept(MediaType.APPLICATION_JSON)
                ).andExpect(status().isBadRequest())
                .andExpect(result -> Assert.isTrue(result.getResolvedException() instanceof UsernameNotAvailableException))
                .andExpect(result -> Assert.hasText("Username taken", result.getResolvedException().getMessage()))
                .andReturn();
    }
}
