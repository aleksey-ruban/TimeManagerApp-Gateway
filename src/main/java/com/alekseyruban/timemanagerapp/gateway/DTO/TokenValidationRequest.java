package com.alekseyruban.timemanagerapp.gateway.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenValidationRequest {
    @NotNull
    private Long sessionId;

    @NotBlank
    private String token;
}
