package org.xapps.services.services;

import akka.actor.typed.ActorRef;
import akka.actor.typed.Behavior;
import akka.actor.typed.javadsl.AbstractBehavior;
import akka.actor.typed.javadsl.ActorContext;
import akka.actor.typed.javadsl.Behaviors;
import akka.actor.typed.javadsl.Receive;
import at.favre.lib.crypto.bcrypt.BCrypt;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.xapps.services.entities.Role;
import org.xapps.services.entities.User;
import org.xapps.services.repositories.RoleRepository;
import org.xapps.services.repositories.UserRepository;
import org.xapps.services.services.requests.Login;
import org.xapps.services.services.responses.*;
import org.xapps.services.services.utils.PropertiesProvider;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class UserService extends AbstractBehavior<UserService.Command> {

    public interface Command extends Serializable {
    }

    public record SeedCommand() implements Command {
        @Serial
        private static final long serialVersionUID = 32432483742934L;
    }

    public record LoginCommand(
            Login login,
            ActorRef<LoginResponse> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 786873498237498L;
    }

    public record CreateCommand(
            User user,
            ActorRef<UserResponse> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 95889437584375894L;
    }

    public record ReadAllCommand(
            ActorRef<UsersResponse> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 4573298477743192384L;
    }

    public record ReadCommand(
            Long id,
            ActorRef<UserResponse> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 5864587832984943897L;
    }

    public record UpdateCommand(
            Long id,
            User user,
            ActorRef<UserResponse> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 1293483957984357876L;
    }

    public record DeleteCommand(
            Long id,
            ActorRef<Response> replyTo
    ) implements Command {
        @Serial
        private static final long serialVersionUID = 12845894359348758L;
    }

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ObjectMapper objectMapper;
    private final PropertiesProvider propertiesProvider;

    public UserService(ActorContext<Command> context) {
        super(context);
        this.userRepository = new UserRepository();
        this.roleRepository = new RoleRepository();
        this.objectMapper = new ObjectMapper();
        this.propertiesProvider = PropertiesProvider.getInstance();
    }

    public static Behavior<Command> create() {
        return Behaviors.setup(UserService::new);
    }

    @Override
    public Receive<Command> createReceive() {
        return newReceiveBuilder()
                .onMessage(SeedCommand.class, this::seedDatabase)
                .onMessage(LoginCommand.class, this::login)
                .onMessage(CreateCommand.class, this::create)
                .onMessage(ReadAllCommand.class, this::readAll)
                .onMessage(ReadCommand.class, this::read)
                .onMessage(UpdateCommand.class, this::update)
                .onMessage(DeleteCommand.class, this::delete)
                .build();
    }

    private Behavior<Command> seedDatabase(SeedCommand command) {
        Role administratorRole = null;
        if(roleRepository.count() == 0L) {
            Role guestRole = new Role(Role.GUEST);
            guestRole = roleRepository.create(guestRole);
            administratorRole = new Role(Role.ADMINISTRATOR);
            administratorRole = roleRepository.create(administratorRole);
        }

        if(userRepository.count() == 0L) {
            if (administratorRole == null) {
                administratorRole = roleRepository.getByName(Role.ADMINISTRATOR);
            }
            User administrator = new User(
                    "root@gmail.com",
                    BCrypt.withDefaults().hashToString(12, "123456".toCharArray()),
                    "Root", "Administrator",
                    List.of(administratorRole)
            );
            userRepository.create(administrator);
        }

        return Behaviors.same();
    }

    private Behavior<Command> login(LoginCommand command) {
        User user = userRepository.getByEmail(command.login.username());
        if (user != null) {
            BCrypt.Result result = BCrypt.verifyer().verify(command.login.password().toCharArray(), user.getPassword());
            if (result.verified) {
                try {
                    Algorithm algorithm = Algorithm.HMAC256((String) propertiesProvider.securityTokenKey());
                    long currentTimestamp = Instant.now().toEpochMilli();
                    long expirationTimestamp = currentTimestamp + propertiesProvider.securityValidity();
                    Date currentDate = new Date(currentTimestamp);
                    Date expirationDate = new Date(expirationTimestamp);
                    String subject = objectMapper.writeValueAsString(user);
                    String token = JWT.create()
                            .withIssuer("XApps")
                            .withIssuedAt(currentDate)
                            .withExpiresAt(expirationDate)
                            .withSubject(subject)
                            .sign(algorithm);
                    command.replyTo.tell(new LoginResponse(ResponseType.OK, new Authentication(token, expirationTimestamp)));
                } catch (JWTCreationException | JsonProcessingException ex) {
                    log.error("Exception captured", ex);
                    command.replyTo.tell(new LoginResponse(ResponseType.UNKNWON));
                }
            } else {
                command.replyTo.tell(new LoginResponse(ResponseType.UNAUTHORIZED));
            }
        } else {
            command.replyTo.tell(new LoginResponse(ResponseType.UNAUTHORIZED));
        }
        return Behaviors.same();
    }

    private Behavior<Command> create(CreateCommand command) {
        User user = userRepository.getByEmail(command.user.getEmail());
        if (user == null) {
            user = command.user;
            user.setPassword(BCrypt.withDefaults().hashToString(12, user.getPassword().toCharArray()));
            List<Role> roles = null;
            if (user.getRoles() != null && !user.getRoles().isEmpty()) {
                roles = roleRepository.getByNames(user.getRoles().stream().map(Role::getName).collect(Collectors.toList()));
            }
            if (roles == null || roles.isEmpty()) {
                Role guestRole = roleRepository.getByName(Role.GUEST);
                roles = List.of(guestRole);
            }
            user.setRoles(roles);
            user = userRepository.create(user);
            command.replyTo.tell(new UserResponse(ResponseType.OK, user));
        } else {
            command.replyTo.tell(new UserResponse(ResponseType.EMAIL_NO_AVAILABLE));
        }
        return Behaviors.same();
    }

    private Behavior<Command> readAll(ReadAllCommand command) {
        List<User> users = userRepository.readAll();
        command.replyTo.tell(new UsersResponse(ResponseType.OK, users));
        return Behaviors.same();
    }

    private Behavior<Command> read(ReadCommand command) {
        User user = userRepository.read(command.id);
        if (user != null) {
            command.replyTo.tell(new UserResponse(ResponseType.OK, user));
        } else {
            command.replyTo.tell(new UserResponse(ResponseType.NOT_FOUND));
        }
        return Behaviors.same();
    }

    private Behavior<Command> update(UpdateCommand command) {
        User user = userRepository.read(command.id);
        if (user != null) {
            User duplicity = userRepository.getByIdAndEmail(command.id, command.user.getEmail());
            if (duplicity == null) {
                user.setEmail(command.user.getEmail());
                if (command.user.getPassword() != null) {
                    user.setPassword(BCrypt.withDefaults().hashToString(12, command.user.getPassword().toCharArray()));
                }
                user.setFirstName(command.user.getFirstName());
                user.setLastName(command.user.getLastName());
                List<Role> roles = null;
                if (command.user.getRoles() != null && !command.user.getRoles().isEmpty()) {
                    roles = roleRepository.getByNames(command.user.getRoles().stream().map(Role::getName).collect(Collectors.toList()));
                }
                if (roles != null && !roles.isEmpty()) {
                    user.setRoles(roles);
                }
                user = userRepository.update(user);
                command.replyTo.tell(new UserResponse(ResponseType.OK, user));
            } else {
                command.replyTo.tell(new UserResponse(ResponseType.EMAIL_NO_AVAILABLE));
            }
        } else {
            command.replyTo.tell(new UserResponse(ResponseType.NOT_FOUND));
        }
        return Behaviors.same();
    }

    private Behavior<Command> delete(DeleteCommand command) {
        User user = userRepository.read(command.id);
        if (user != null) {
            userRepository.delete(user);
            command.replyTo.tell(new Response(ResponseType.OK));
        } else {
            command.replyTo.tell(new Response(ResponseType.NOT_FOUND));
        }
        return Behaviors.same();
    }
}
