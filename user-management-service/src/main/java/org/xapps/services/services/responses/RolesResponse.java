package org.xapps.services.services.responses;

import com.sun.istack.Nullable;
import org.xapps.services.entities.Role;

import java.util.List;

public record RolesResponse(
        ResponseType type,
        @Nullable List<Role> roles
) {
    public RolesResponse(ResponseType type) {
        this(type, null);
    }
}
