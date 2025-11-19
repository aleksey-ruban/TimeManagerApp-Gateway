package com.alekseyruban.timemanagerapp.gateway.DTO;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenValidationResponse {
    @NotNull
    private Boolean valid;
}
