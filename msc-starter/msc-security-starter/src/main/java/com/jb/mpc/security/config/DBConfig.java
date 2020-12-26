package com.jb.mpc.security.config;

import com.jb.mpc.security.util.DecryptionFilter;
import com.jb.mpc.security.util.XssFilter;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Data
@Component
@RefreshScope
public class DBConfig {

    //是否对明文数据库用户名密码进行加密
    @Value("${encryptionDatasource:T}")
    private String encryptionDatasource;

    //是否通信数据传输安全模式
    @Value("${isTransSafe:F}")
    private String isTransSafe;

    //是否xss安全模式
    @Value("${isXssSafe:F}")
    private String isXssSafe;

    //是否model和token安全模式
    @Value("${isModelSafe:T}")
    private String isModelSafe;

    //解密密钥
    @Value("${decKey:useProInfo}")
    private String decKey;

    //加密类型
    @Value("${cryptType:1}")
    private String cryptType;

    //sm2加密模式
    @Value("${cipherMode:C1C3C2}")
    private String cipherMode;
    //待加密请求
    @Value("${encryptionRequest:}")
    private String encryptionRequest;

    //加密字段
    @Value("${base64Encryption:}")
    private String base64Encryption;

    //文件分布式存储方式  目前有三个模式  local、fastDFS、oss
    @Value("${fileSaveType:local}")
    private String fileSaveType;

    //是否是使用的达梦数据库
    @Value("${dataSourceModel:F}")
    private String dataSourceModel;

    @Bean
    public FilterRegistrationBean registerFilter() {

        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new DecryptionFilter());
        registration.addUrlPatterns("/*");
        registration.setName("DecryptionFilter");
        registration.setOrder(1);
        return registration;
    }

    /**
     * 配置xss防范过滤器
     * @return
     */
    @Bean
    public FilterRegistrationBean xssFilterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new XssFilter());
        registration.addUrlPatterns("/*");
        registration.setName("xssFilter");
        return registration;
    }

}
