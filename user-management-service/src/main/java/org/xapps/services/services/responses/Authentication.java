package org.xapps.services.services.responses;

public record Authentication(
        String token,
        Long validity
) {
}
