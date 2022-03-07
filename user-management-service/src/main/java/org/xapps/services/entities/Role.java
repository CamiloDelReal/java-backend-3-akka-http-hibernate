package org.xapps.services.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
@EqualsAndHashCode
@Entity(name = "roles")
@Table(name = "roles")
public class Role {
    public static final String ADMINISTRATOR = "Administrator";
    public static final String GUEST = "Guest";

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    @JsonProperty("id")
    private Long id;

    @Column(name = "name")
    @JsonProperty("name")
    private String name;

    public Role(String name) {
        this.name = name;
    }
}
