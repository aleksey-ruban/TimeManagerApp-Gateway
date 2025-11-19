package com.alekseyruban.timemanagerapp.gateway.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "gateway")
@Getter
@Setter
public class CustomGatewayProperties {
    private List<String> whitelist;
}