package org.xapps.services.services.responses;

import com.sun.istack.Nullable;
import org.xapps.services.entities.User;

public record UserResponse(
        ResponseType type,
        @Nullable User user
) {
    public UserResponse(ResponseType type) {
        this(type, null);
    }
}
