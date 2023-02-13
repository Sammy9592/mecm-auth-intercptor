package com.sl.mecm.auth.intercptor.config;


import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

//@Configuration("authHttpClientConfigs")
public class AuthHttpClientConfigs {


//    @Bean("tokenServiceRestTemplate")
//    public RestTemplate createTokenServiceRestTemplate(){
//        RequestConfig config = RequestConfig.custom()
//                .setConnectTimeout(Timeout.ofSeconds(tokenServiceConfig.getTimeout()))
//                .setConnectionRequestTimeout(Timeout.ofSeconds(tokenServiceConfig.getTimeout()))
//                .build();
//        CloseableHttpClient client = HttpClientBuilder
//                .create()
//                .setDefaultRequestConfig(config)
//                .build();
//        ClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(client);
//        return new RestTemplate(factory);
//    }
}
