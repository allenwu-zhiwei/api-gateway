package com.nusiss.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//@EnableEurekaClient
//As of Spring Cloud 2020.0.x and later (including Spring Cloud 2021.x and Spring Cloud 2022.x), @EnableEurekaClient has been removed, and it's no longer required. Spring Boot applications that include the necessary Eureka dependencies will automatically register themselves as Eureka clients without the need for @EnableEurekaClient.
public class ApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGatewayApplication.class, args);
	}

}
