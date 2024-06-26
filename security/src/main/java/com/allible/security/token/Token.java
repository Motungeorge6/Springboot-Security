package com.allible.security.token;

import com.allible.security.user.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.stereotype.Indexed;
 @Document(collection = "Token")
 @Builder
 @NoArgsConstructor
 @AllArgsConstructor
 @Data
public class Token {
    @Id

    public String id;

    public String token;

    @Field
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @DBRef
    public User user;

}
