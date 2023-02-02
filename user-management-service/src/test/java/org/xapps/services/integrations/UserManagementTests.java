package org.xapps.services.integrations;

import akka.actor.typed.ActorSystem;
import akka.http.javadsl.marshallers.jackson.Jackson;
import akka.http.javadsl.model.ContentTypes;
import akka.http.javadsl.model.HttpHeader;
import akka.http.javadsl.model.HttpRequest;
import akka.http.javadsl.model.StatusCodes;
import akka.http.javadsl.testkit.JUnitRouteTest;
import akka.http.javadsl.testkit.TestRoute;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.xapps.services.entities.Role;
import org.xapps.services.entities.User;
import org.xapps.services.servers.UserRoutes;
import org.xapps.services.services.UserService;
import org.xapps.services.services.requests.Login;
import org.xapps.services.services.responses.Authentication;

import java.net.http.HttpHeaders;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class UserManagementTests  extends JUnitRouteTest {

    private ObjectMapper objectMapper = new ObjectMapper();
    private ActorSystem system = ActorSystem.create(UserService.create(), "gfg");
    private UserRoutes userRoutes = new UserRoutes(system, system);
    private TestRoute appRoute = testRoute(userRoutes.routes());

    @Before
    public void seedDatabase() {
        system.tell(new UserService.SeedCommand());
        Assertions.assertTrue(true);
    }

    @Test
    public void testCalculatorAdd() throws JsonProcessingException, InterruptedException {
        Login login = new Login("root@gmail.com", "123456");
        appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK);
    }




    @Test
    public void loginRoot_success() throws JsonProcessingException {
        Login login = new Login("root@gmail.com", "123456");
        Authentication authentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(authentication.token());
        assertNotNull(authentication.validity());
    }

    @Test
    public void loginRoot_failByInvalidPassword() throws JsonProcessingException {
        Login login = new Login("root@gmail.com", "invalid");
        appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.UNAUTHORIZED);
    }

    @Test
    public void login_failByInvalidCredentials() throws JsonProcessingException {
        Login login = new Login("invalid@gmail.com", "123456");
        appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.UNAUTHORIZED);
    }

    @Test
    public void createAndEditUserWithDefaultRole_success() throws JsonProcessingException {
        User user = new User("vladdoe@gmail.com", "qwerty", "Vlad", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
                .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("vladdoe@gmail.com", createdUser.getEmail());
        assertEquals("Vlad", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        Login login = new Login(user.getEmail(), user.getPassword());
        Authentication authentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        User userModified = new User("annadoe@gmail.com", "qwerty", "Anna", "Doe", null);

        User updatedUser = appRoute.run(
            HttpRequest.PUT(String.format("/users/%d", createdUser.getId()))
                .withHeaders(
                    Collections.singleton(
                        HttpHeader.parse("Authorization", String.format("Bearer %s", authentication.token()))
                    )
                )
                .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(userModified))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(updatedUser.getId());
        assertEquals(createdUser.getId(), updatedUser.getId());
        assertEquals("annadoe@gmail.com", updatedUser.getEmail());
        assertEquals("Anna", updatedUser.getFirstName());
        assertEquals("Doe", updatedUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());
    }

    @Test
    public void createUserWithAdminRole_failByNoAdminCredentials() throws JsonProcessingException {
        Role[] roles = appRoute.run(
                HttpRequest.GET("/users/roles")
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Role[].class));

        Role adminRole = Arrays.stream(roles).filter((it) -> it.getName().equals(Role.ADMINISTRATOR)).findFirst().orElse(null);
        assertNotNull(adminRole);

        User user = new User("vladdoe@gmail.com", "qwerty", "Vlad", "Doe", Collections.singletonList(adminRole));

        appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.FORBIDDEN);
    }

    @Test
    public void createUserWithAdminRole_success() throws JsonProcessingException {
        Login login = new Login("root@gmail.com", "123456");
        Authentication rootAuthentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(rootAuthentication.token());
        assertNotNull(rootAuthentication.validity());

        Role[] roles = appRoute.run(
                HttpRequest.GET("/users/roles")
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Role[].class));

        Role adminRole = Arrays.stream(roles).filter((it) -> it.getName().equals(Role.ADMINISTRATOR)).findFirst().orElse(null);
        assertNotNull(adminRole);

        User anotherAdminUser = new User("kathdoe@gmail.com", "qwerty", "Kath", "Doe", Collections.singletonList(adminRole));

        User createdAdmin = appRoute.run(
                HttpRequest.POST("/users")
                    .withHeaders(
                        Collections.singleton(
                            HttpHeader.parse("Authorization", String.format("Bearer %s", rootAuthentication.token()))
                        )
                    )
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(anotherAdminUser))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdAdmin.getId());
        assertNotEquals(0, createdAdmin.getId());
        assertEquals("kathdoe@gmail.com", createdAdmin.getEmail());
        assertNotNull(createdAdmin.getRoles());
        assertEquals(1, createdAdmin.getRoles().size());
        assertEquals(Role.ADMINISTRATOR, createdAdmin.getRoles().get(0).getName());
    }

    @Test
    public void createUser_failByUsernameDuplicity() throws JsonProcessingException {
        User user = new User("root@gmail.com", "qwerty", "Root", "Second", null);
        appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.BAD_REQUEST);
    }

    @Test
    public void createAndEditUserWithUserCredentials_failByWrongId() throws JsonProcessingException {
        User user = new User("robdoe@gmail.com", "qwerty", "Rob", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("robdoe@gmail.com", createdUser.getEmail());
        assertEquals("Rob", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        Login login = new Login(user.getEmail(), user.getPassword());
        Authentication authentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(authentication.token());
        assertNotNull(authentication.validity());

        User userModified = new User("robdoe@gmail.com", "qwerty", "Robert", "Doe", null);

        appRoute.run(
                HttpRequest.PUT(String.format("/users/%dwrong", createdUser.getId()))
                    .withHeaders(
                        Collections.singleton(
                            HttpHeader.parse("Authorization", String.format("Bearer %s", authentication.token()))
                        )
                    )
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(userModified))
            )
            .assertStatusCode(StatusCodes.NOT_FOUND);
    }

    @Test
    public void editUserToAdminWithUserCredentials_failByNoAdminCredentials() throws JsonProcessingException {
        User user = new User("donalddoe@gmail.com", "qwerty", "Donald", "Doe", null);
        User createdUser = appRoute.run(
                        HttpRequest.POST("/users")
                                .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
                )
                .assertStatusCode(StatusCodes.CREATED)
                .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("donalddoe@gmail.com", createdUser.getEmail());
        assertEquals("Donald", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        Login login = new Login(user.getEmail(), user.getPassword());
        Authentication authentication = appRoute.run(
                        HttpRequest.POST("/users/login")
                                .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
                )
                .assertStatusCode(StatusCodes.OK)
                .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(authentication.token());
        assertNotNull(authentication.validity());

        Role[] roles = appRoute.run(
                        HttpRequest.GET("/users/roles")
                )
                .assertStatusCode(StatusCodes.OK)
                .entity(Jackson.unmarshaller(Role[].class));

        Role adminRole = Arrays.stream(roles).filter((it) -> it.getName().equals(Role.ADMINISTRATOR)).findFirst().orElse(null);
        assertNotNull(adminRole);

        User userModified = new User("donalddoe@gmail.com", "qwerty", "Donald", "Doe", Collections.singletonList(adminRole));

        appRoute.run(
                HttpRequest.PUT(String.format("/users/%d", createdUser.getId()))
                    .withHeaders(
                        Collections.singleton(
                            HttpHeader.parse("Authorization", String.format("Bearer %s", authentication.token()))
                        )
                    )
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(userModified))
            )
            .assertStatusCode(StatusCodes.FORBIDDEN);
    }

    @Test
    public void editUser_failByNoUserCredentials() throws JsonProcessingException {
        User user = new User("lindadoe@gmail.com", "qwerty", "Linda", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("lindadoe@gmail.com", createdUser.getEmail());
        assertEquals("Linda", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        User modifiedUser = new User("robdoe@gmail.com", "qwerty", "Linda", "McDoe", null);

        appRoute.run(
                HttpRequest.PUT(String.format("/users/%d", createdUser.getId()))
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(modifiedUser))
            )
            .assertStatusCode(StatusCodes.FORBIDDEN);
    }

    @Test
    public void editUserWithAdminCredentials_success() throws JsonProcessingException {
        User user = new User("joanadoe@gmail.com", "qwerty", "Joana", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("joanadoe@gmail.com", createdUser.getEmail());
        assertEquals("Joana", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        Login login = new Login("root@gmail.com", "123456");
        Authentication authentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(authentication.token());
        assertNotNull(authentication.validity());

        User userModified = new User("joanadoe@gmail.com", "qwerty", "Joana", "McDoe", null);

        User updatedUser = appRoute.run(
                HttpRequest.PUT(String.format("/users/%d", createdUser.getId()))
                    .withHeaders(
                        Collections.singleton(
                            HttpHeader.parse("Authorization", String.format("Bearer %s", authentication.token()))
                        )
                    )
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(userModified))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(updatedUser.getId());
        assertEquals(createdUser.getId(), updatedUser.getId());
        assertEquals(userModified.getEmail(), updatedUser.getEmail());
        assertEquals(userModified.getFirstName(), updatedUser.getFirstName());
        assertEquals(userModified.getLastName(), updatedUser.getLastName());
        assertNotNull(updatedUser.getRoles());
        assertEquals(1, updatedUser.getRoles().size());
        assertEquals(Role.GUEST, updatedUser.getRoles().get(0).getName());
    }

    @Test
    public void deleteUserWithUserCredentials_success() throws JsonProcessingException {
        User user = new User("ninadoe@gmail.com", "qwerty", "Nina", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("ninadoe@gmail.com", createdUser.getEmail());
        assertEquals("Nina", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        Login login = new Login("ninadoe@gmail.com", "qwerty");
        Authentication authentication = appRoute.run(
                HttpRequest.POST("/users/login")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(login))
            )
            .assertStatusCode(StatusCodes.OK)
            .entity(Jackson.unmarshaller(Authentication.class));

        assertNotNull(authentication.token());
        assertNotNull(authentication.validity());

        appRoute.run(
                HttpRequest.DELETE(String.format("/users/%d", createdUser.getId()))
                    .withHeaders(
                        Collections.singleton(
                            HttpHeader.parse("Authorization", String.format("Bearer %s", authentication.token()))
                        )
                    )
            )
                .assertStatusCode(StatusCodes.OK);
    }

    @Test
    public void deleteUser_failByNoCredentials() throws JsonProcessingException {
        User user = new User("luciadoe@gmail.com", "qwerty", "Lucia", "Doe", null);
        User createdUser = appRoute.run(
                HttpRequest.POST("/users")
                    .withEntity(ContentTypes.APPLICATION_JSON, objectMapper.writeValueAsString(user))
            )
            .assertStatusCode(StatusCodes.CREATED)
            .entity(Jackson.unmarshaller(User.class));

        assertNotNull(createdUser.getId());
        assertNotEquals(0, createdUser.getId());
        assertEquals("luciadoe@gmail.com", createdUser.getEmail());
        assertEquals("Lucia", createdUser.getFirstName());
        assertEquals("Doe", createdUser.getLastName());
        assertNotNull(createdUser.getRoles());
        assertEquals(1, createdUser.getRoles().size());
        assertEquals(Role.GUEST, createdUser.getRoles().get(0).getName());

        appRoute.run(
                HttpRequest.DELETE(String.format("/users/%d", createdUser.getId()))
            )
            .assertStatusCode(StatusCodes.FORBIDDEN);
    }
}
