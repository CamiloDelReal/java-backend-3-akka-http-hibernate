package org.xapps.services.services.responses;

import com.sun.istack.Nullable;

public record LoginResponse(
        ResponseType type,
        @Nullable Authentication authentication) {
    public LoginResponse(ResponseType type) {
        this(type, null);
    }
}
