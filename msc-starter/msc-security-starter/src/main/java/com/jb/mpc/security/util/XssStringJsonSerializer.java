package com.jb.mpc.security.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.jb.mpc.security.config.DBConfig;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.context.ApplicationContext;

import java.io.IOException;

public class XssStringJsonSerializer extends JsonSerializer<String> {

   @Override
   public Class<String> handledType() {
        return String.class;
   }

   @Override
   public void serialize(String value, JsonGenerator jsonGenerator,SerializerProvider serializerProvider) throws IOException {
        if (value != null) {
            //调用Sercice层
            ApplicationContext context = SpringUtil.getApplicationContext();
            DBConfig dBConfig = context.getBean(DBConfig.class);// 注意是Service，不是ServiceImpl
            String isSafe = dBConfig.getIsXssSafe();// 是否xss安全模式
            if ("T".equals(isSafe)) {
                value = StringEscapeUtils.escapeHtml3(value);
            }
            jsonGenerator.writeString(value);
        }
   }
}