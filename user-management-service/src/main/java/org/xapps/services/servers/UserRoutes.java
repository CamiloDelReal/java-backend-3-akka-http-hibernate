package org.xapps.services.servers;

import akka.actor.typed.ActorRef;
import akka.actor.typed.ActorSystem;
import akka.actor.typed.Scheduler;
import akka.actor.typed.javadsl.AskPattern;
import akka.http.javadsl.marshallers.jackson.Jackson;
import akka.http.javadsl.model.ContentTypes;
import akka.http.javadsl.model.HttpResponse;
import akka.http.javadsl.model.StatusCodes;
import akka.http.javadsl.server.PathMatchers;
import akka.http.javadsl.server.Route;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.xapps.services.entities.User;
import org.xapps.services.services.UserService;
import org.xapps.services.services.requests.Login;
import org.xapps.services.services.responses.*;
import org.xapps.services.services.utils.PropertiesProvider;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static akka.http.javadsl.server.Directives.*;

@Slf4j
public class UserRoutes {
    private final ActorRef<UserService.Command> userServiceActor;
    private final Scheduler scheduler;
    private final ObjectMapper objectMapper;
    private final PropertiesProvider propertiesProvider;

    public UserRoutes(ActorSystem<?> actorSystem, ActorRef<UserService.Command> userServiceActor) {
        this.userServiceActor = userServiceActor;
        this.scheduler = actorSystem.scheduler();
        this.objectMapper = new ObjectMapper();
        this.propertiesProvider = PropertiesProvider.getInstance();
    }

    private CompletableFuture<HttpResponse> roles() {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<RolesResponse> rolesResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.RolesCommand(me), Duration.ofSeconds(5), scheduler);
        rolesResponseFuture.whenComplete((rolesResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (rolesResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(rolesResponse.roles());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    case UNAUTHORIZED -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.UNAUTHORIZED));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private CompletableFuture<HttpResponse> loginUser(Login loginRequest) {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<LoginResponse> loginResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.LoginCommand(loginRequest, me), Duration.ofSeconds(5), scheduler);
        loginResponseFuture.whenComplete((loginResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (loginResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(loginResponse.authentication());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    case UNAUTHORIZED -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.UNAUTHORIZED));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private Route authenticateWithJwt(java.util.function.Function<Optional<User>, Route> inner) {
        return optionalHeaderValueByName("Authorization", bearerAuthentication -> {
            if (bearerAuthentication.isPresent() && bearerAuthentication.get().startsWith("Bearer")) {
                String token = bearerAuthentication.get().substring(7);
                try {
                    Algorithm algorithm = Algorithm.HMAC256(propertiesProvider.securityTokenKey());
                    JWTVerifier verifier = JWT.require(algorithm)
                            .withIssuer("XApps")
                            .build();
                    DecodedJWT jwt = verifier.verify(token);
                    User principal = objectMapper.readValue(jwt.getSubject(), User.class);
                    System.out.println("AppLogger - JWT Logged In  " + principal);
                    return inner.apply(Optional.of(principal));
                } catch (JWTVerificationException | JsonProcessingException ex) {
                    log.error("Exception captured", ex);
                    return complete(StatusCodes.UNAUTHORIZED);
                }
            } else {
                return inner.apply(Optional.empty());
            }
        });
    }

    private CompletableFuture<HttpResponse> createUser(User user) {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<UserResponse> userResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.CreateCommand(user, me), Duration.ofSeconds(5), scheduler);
        userResponseFuture.whenComplete((userResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (userResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(userResponse.user());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.CREATED).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    case EMAIL_NO_AVAILABLE -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.BAD_REQUEST));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private CompletableFuture<HttpResponse> readAllUsers() {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<UsersResponse> usersResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.ReadAllCommand(me), Duration.ofSeconds(5), scheduler);
        usersResponseFuture.whenComplete((usersResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (usersResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(usersResponse.users());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private CompletableFuture<HttpResponse> readUser(Long id) {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<UserResponse> userResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.ReadCommand(id, me), Duration.ofSeconds(5), scheduler);
        userResponseFuture.whenComplete((userResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (userResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(userResponse.user());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    case NOT_FOUND -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.NOT_FOUND));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private CompletableFuture<HttpResponse> updateUser(Long id, User user) {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<UserResponse> userResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.UpdateCommand(id, user, me), Duration.ofSeconds(5), scheduler);
        userResponseFuture.whenComplete((userResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (userResponse.type()) {
                    case OK -> {
                        try {
                            String data = objectMapper.writeValueAsString(userResponse.user());
                            response.complete(HttpResponse.create().withStatus(StatusCodes.OK).withEntity(ContentTypes.APPLICATION_JSON, data));
                        } catch (JsonProcessingException ex) {
                            log.error("Exception captured", ex);
                            response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                        }
                    }
                    case NOT_FOUND -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.NOT_FOUND));
                    }
                    case EMAIL_NO_AVAILABLE -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.BAD_REQUEST));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    private CompletableFuture<HttpResponse> deleteUser(Long id) {
        CompletableFuture<HttpResponse> response = new CompletableFuture<>();
        CompletionStage<Response> deleteResponseFuture = AskPattern.ask(userServiceActor, me -> new UserService.DeleteCommand(id, me), Duration.ofSeconds(5), scheduler);
        deleteResponseFuture.whenComplete((deleteResponse, throwable) -> {
            if (throwable != null) {
                log.error("Exception received", throwable);
                response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
            } else {
                switch (deleteResponse.type()) {
                    case OK -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.OK));
                    }
                    case NOT_FOUND -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.NOT_FOUND));
                    }
                    default -> {
                        response.complete(HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR));
                    }
                }
            }
        });
        return response;
    }

    public Route routes() {
        return pathPrefix("users", () ->
                concat(
                        path("roles", () -> get(() -> completeWithFuture(roles()))),
                        path("login", () -> post(() -> entity(Jackson.unmarshaller(Login.class), login -> completeWithFuture(loginUser(login))))),
                        pathEnd(() -> concat(
                                get(() -> authenticateWithJwt(principal -> {
                                    return authorize(() -> principal.isPresent() && principal.get().isAdministrator(), () -> {
                                        return completeWithFuture(readAllUsers());
                                    });
                                })),
                                post(() -> authenticateWithJwt(principal -> {
                                    return entity(Jackson.unmarshaller(User.class), user -> {
                                        return authorize(() -> !user.isAdministrator() || (principal.isPresent() && principal.get().isAdministrator()), () -> {
                                            return completeWithFuture(createUser(user));
                                        });
                                    });
                                }))
                        )),
                        path(PathMatchers.longSegment(), (Long userId) -> concat(
                                get(() -> authenticateWithJwt(principal -> {
                                    return authorize(() -> principal.isPresent() && (principal.get().isAdministrator() || Objects.equals(principal.get().getId(), userId)), () -> {
                                        return completeWithFuture(readUser(userId));
                                    });
                                })),
                                put(() -> authenticateWithJwt(principal -> {
                                    return entity(Jackson.unmarshaller(User.class), user -> {
                                        return authorize(() -> principal.isPresent() && (principal.get().isAdministrator() || (Objects.equals(principal.get().getId(), userId) && !user.isAdministrator())), () -> {
                                            return completeWithFuture(updateUser(userId, user));
                                        });
                                    });
                                })),
                                delete(() -> authenticateWithJwt(principal -> {
                                    return authorize(() -> principal.isPresent() && (principal.get().isAdministrator() || Objects.equals(principal.get().getId(), userId)), () -> {
                                        return completeWithFuture(deleteUser(userId));
                                    });
                                }))
                        ))
                )
        );
    }

}
