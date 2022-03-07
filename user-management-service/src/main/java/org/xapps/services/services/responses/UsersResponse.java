package org.xapps.services.services.responses;

import com.sun.istack.Nullable;
import org.xapps.services.entities.User;

import java.util.List;

public record UsersResponse(
        ResponseType type,
        @Nullable List<User> users
) {
    public UsersResponse(ResponseType type) {
        this(type, null);
    }
}